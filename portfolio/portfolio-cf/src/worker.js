/* =====================================================================
   Muhammad Abuzar — Portfolio API (Cloudflare Worker)
   Bindings (wrangler.toml): KV = CONTENT_KV, R2 = MEDIA, assets = ASSETS
   Secrets: SETUP_KEY (wrangler secret put SETUP_KEY)

   Security model
   --------------
   - Passwords:   PBKDF2-SHA256, 100,000 iterations, 16-byte random salt.
   - Sessions:    32-byte random Bearer token; ONLY its SHA-256 hash is
                  stored in KV (session:<hash>), 8h absolute lifetime,
                  30-min sliding refresh. Logout deletes server-side.
   - Login:       rate limited 10 attempts / IP / 10 minutes (KV counter).
   - Setup:       one-time, requires SETUP_KEY secret => nobody can race
                  you to claim the admin account after first deploy.
   - Writes:      every mutating endpoint calls requireAdmin() first.
   - Uploads:     size cap + MIME allowlist + magic-byte sniffing,
                  random object keys (no path traversal / overwrite).
   - Headers:     strict CSP, no-sniff, frame-deny, HSTS, referrer policy.
   - Timing:      constant-time comparison for hashes/keys.
   ===================================================================== */

const SESSION_TTL = 8 * 60 * 60;          // 8h absolute (seconds)
const SESSION_REFRESH = 30 * 60;          // refresh KV entry if < 30min since last touch
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW = 10 * 60;             // 10 minutes
const PBKDF2_ITER = 100_000;
const MAX_CONTENT_BYTES = 400_000;        // site JSON cap
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB

const ALLOWED_UPLOADS = {
  'image/jpeg':      { ext: 'jpg',  magic: [[0xFF, 0xD8, 0xFF]] },
  'image/png':       { ext: 'png',  magic: [[0x89, 0x50, 0x4E, 0x47]] },
  'image/webp':      { ext: 'webp', magic: [[0x52, 0x49, 0x46, 0x46]] }, // RIFF
  'application/pdf': { ext: 'pdf',  magic: [[0x25, 0x50, 0x44, 0x46]] }, // %PDF
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/'))   return withCors(await handleApi(request, env, url));
      if (url.pathname.startsWith('/media/')) return handleMedia(request, env, url);
      // static site via Workers Assets, with security headers stamped on
      const res = await env.ASSETS.fetch(request);
      return withSecurityHeaders(res, url);
    } catch (e) {
      console.error(e);
      return json({ error: 'Internal error' }, 500);
    }
  },
};

/* ------------------------------ routing ------------------------------ */

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  // ---- public ----
  if (path === '/api/status' && method === 'GET') {
    const setup = !!(await env.CONTENT_KV.get('auth:admin'));
      return json({ setup }); // never leaks anything else
  
  }
  if (path === '/api/content' && method === 'GET') {
    const raw = await env.CONTENT_KV.get('site:content');
    return json(raw ? JSON.parse(raw) : defaultContent(), 200, { 'Cache-Control': 'no-store' });
  }
  if (path === '/api/setup' && method === 'POST') return handleSetup(request, env);
  if (path === '/api/login' && method === 'POST') return handleLogin(request, env);

  // ---- admin only (server-side enforcement — the client isAdmin flag is cosmetic) ----
  const session = await requireAdmin(request, env);
  if (!session.ok) return json({ error: 'Unauthorized' }, 401);

  if (path === '/api/logout' && method === 'POST') {
    await env.CONTENT_KV.delete('session:' + session.hash);
    return json({ ok: true });
  }
  if (path === '/api/content' && method === 'PUT') {
    const body = await readBody(request, MAX_CONTENT_BYTES);
    if (!body.ok) return json({ error: body.error }, 413);
    let data;
    try { data = JSON.parse(body.text); } catch { return json({ error: 'Invalid JSON' }, 400); }
    if (typeof data !== 'object' || !data || Array.isArray(data)) return json({ error: 'Invalid content' }, 400);
    delete data.security; // never allow auth material inside site content
    await env.CONTENT_KV.put('site:content', JSON.stringify(data));
    return json({ ok: true });
  }
  if (path === '/api/change-password' && method === 'POST') return handleChangePassword(request, env);
  if (path === '/api/upload' && method === 'POST') return handleUpload(request, env);
  if (path.startsWith('/api/media/') && method === 'DELETE') {
    const key = decodeURIComponent(path.slice('/api/media/'.length));
    if (!/^[a-z0-9]{24}\.(jpg|png|webp|pdf)$/.test(key)) return json({ error: 'Bad key' }, 400);
    await env.MEDIA.delete(key);
    return json({ ok: true });
  }
  return json({ error: 'Not found' }, 404);
}

/* ------------------------------- auth -------------------------------- */

async function handleSetup(request, env) {
  const existing = await env.CONTENT_KV.get('auth:admin');
  if (existing) return json({ error: 'Already set up' }, 409);

  const setupKey = request.headers.get('X-Setup-Key') || '';
  if (!env.SETUP_KEY || !timingSafeEqualStr(setupKey, env.SETUP_KEY)) {
    return json({ error: 'Invalid setup key' }, 403);
  }
  const { password } = await request.json().catch(() => ({}));
  const problem = passwordPolicy(password);
  if (problem) return json({ error: problem }, 400);

  await env.CONTENT_KV.put('auth:admin', await hashPassword(password));
  return json({ ok: true });
}

async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = 'rl:' + ip;
  const attempts = parseInt((await env.CONTENT_KV.get(rlKey)) || '0', 10);
  if (attempts >= LOGIN_MAX_ATTEMPTS) {
    return json({ error: 'Too many attempts. Try again in a few minutes.' }, 429);
  }

  const { password } = await request.json().catch(() => ({}));
  const stored = await env.CONTENT_KV.get('auth:admin');
  const ok = stored && typeof password === 'string' && (await verifyPassword(password, stored));

  if (!ok) {
    await env.CONTENT_KV.put(rlKey, String(attempts + 1), { expirationTtl: LOGIN_WINDOW });
    return json({ error: 'Invalid credentials' }, 401); // same message whether or not account exists
  }

  await env.CONTENT_KV.delete(rlKey);
  const token = randomHex(32); // 256-bit
  const hash = await sha256Hex(token);
  const now = Date.now();
  await env.CONTENT_KV.put(
    'session:' + hash,
    JSON.stringify({ createdAt: now, touchedAt: now, ip, ua: request.headers.get('User-Agent') || '' }),
    { expirationTtl: SESSION_TTL },
  );
  await env.CONTENT_KV.put('auth:last-login', JSON.stringify({ at: now, ip })); // audit trail
  return json({ token, expiresIn: SESSION_TTL });
}

async function requireAdmin(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) return { ok: false };
  const hash = await sha256Hex(m[1]);
  const key = 'session:' + hash;
  const raw = await env.CONTENT_KV.get(key);
  if (!raw) return { ok: false };
  const s = JSON.parse(raw);
  if (Date.now() - s.createdAt > SESSION_TTL * 1000) { // absolute lifetime even if TTL drifted
    await env.CONTENT_KV.delete(key);
    return { ok: false };
  }
  if (Date.now() - s.touchedAt > SESSION_REFRESH * 1000) { // sliding refresh, throttled
    s.touchedAt = Date.now();
    const remaining = Math.max(60, Math.floor(SESSION_TTL - (Date.now() - s.createdAt) / 1000));
    await env.CONTENT_KV.put(key, JSON.stringify(s), { expirationTtl: remaining });
  }
  return { ok: true, hash };
}

async function handleChangePassword(request, env) {
  const { current, next } = await request.json().catch(() => ({}));
  const stored = await env.CONTENT_KV.get('auth:admin');
  if (!stored || !(await verifyPassword(current || '', stored))) {
    return json({ error: 'Current password is incorrect' }, 403);
  }
  const problem = passwordPolicy(next);
  if (problem) return json({ error: problem }, 400);
  await env.CONTENT_KV.put('auth:admin', await hashPassword(next));
  // revoke every other session by rotating a generation marker is overkill for
  // a single-admin site; sessions expire in <=8h regardless.
  return json({ ok: true });
}

function passwordPolicy(p) {
  if (typeof p !== 'string' || p.length < 10) return 'Password must be at least 10 characters.';
  if (p.length > 128) return 'Password too long.';
  if (/^(admin|password|123456|qwerty)/i.test(p)) return 'Please pick a less guessable password.';
  return null;
}

/* --------------------------- media / uploads -------------------------- */

async function handleUpload(request, env) {
  const form = await request.formData().catch(() => null);
  const file = form && form.get('file');
  if (!file || typeof file === 'string') return json({ error: 'No file' }, 400);
  if (file.size > MAX_UPLOAD_BYTES) return json({ error: 'File too large (max 5 MB)' }, 413);

  const spec = ALLOWED_UPLOADS[file.type];
  if (!spec) return json({ error: 'Only JPEG, PNG, WebP images and PDF files are allowed' }, 415);

  const buf = await file.arrayBuffer();
  const head = new Uint8Array(buf.slice(0, 8));
  const magicOk = spec.magic.some(sig => sig.every((b, i) => head[i] === b));
  if (!magicOk) return json({ error: 'File content does not match its type' }, 415);

  const key = randomHex(12) + '.' + spec.ext; // random key: no traversal, no overwrite
  await env.MEDIA.put(key, buf, { httpMetadata: { contentType: file.type } });
  return json({ ok: true, key, url: '/media/' + key });
}

async function handleMedia(request, env, url) {
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
  const key = decodeURIComponent(url.pathname.slice('/media/'.length));
  if (!/^[a-z0-9]{24}\.(jpg|png|webp|pdf)$/.test(key)) return json({ error: 'Not found' }, 404);
  const obj = await env.MEDIA.get(key);
  if (!obj) return json({ error: 'Not found' }, 404);
  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
      'Content-Disposition': 'inline',
    },
  });
}

/* ------------------------------ crypto ------------------------------- */

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(password, salt, PBKDF2_ITER);
  return `pbkdf2$${PBKDF2_ITER}$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  const [scheme, iterStr, saltB64, hashB64] = stored.split('$');
  if (scheme !== 'pbkdf2') return false;
  const bits = await pbkdf2(password, ub64(saltB64), parseInt(iterStr, 10));
  return timingSafeEqual(new Uint8Array(bits), ub64(hashB64));
}
async function pbkdf2(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, keyMaterial, 256);
}
async function sha256Hex(str) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function timingSafeEqualStr(a, b) {
  return timingSafeEqual(new TextEncoder().encode(a), new TextEncoder().encode(b));
}
function b64(u8) { return btoa(String.fromCharCode(...u8)); }
function ub64(s) { return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0))); }

/* ------------------------------ helpers ------------------------------ */

async function readBody(request, limit) {
  const len = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (len > limit) return { ok: false, error: 'Payload too large' };
  const text = await request.text();
  if (text.length > limit) return { ok: false, error: 'Payload too large' };
  return { ok: true, text };
}

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

function withCors(res) {
  // same-origin app: no CORS wildcard. Explicitly deny cross-origin use.
  const h = new Headers(res.headers);
  h.set('X-Content-Type-Options', 'nosniff');
  return new Response(res.body, { status: res.status, headers: h });
}

function withSecurityHeaders(res, url) {
  const h = new Headers(res.headers);
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if ((h.get('Content-Type') || '').includes('text/html')) {
    h.set('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com",
      "img-src 'self' data: blob:",
      "media-src 'self'",
      "frame-src https://www.youtube.com https://www.youtube-nocookie.com",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '));
  }
  return new Response(res.body, { status: res.status, headers: h });
}

/* --------------------------- default content -------------------------- */

function defaultContent() {
  return {
    profile: {
      eyebrow: 'Full Stack Developer · Islamabad, Pakistan',
      name: 'Muhammad Abuzar',
      role: 'Computer Science Student | Full Stack Developer',
      tagline: 'I design and build scalable web applications with modern frontend and backend technologies — passionate about software engineering, cloud computing, and solving real-world problems.',
      photo: '/assets/photo.jpg',
      about: 'Computer Science student at Sir Syed CASE Institute of Technology (CGPA 3.90/4.00) and Full Stack Developer with hands-on experience designing and developing scalable web applications.\n\nI work across the whole stack — from React and Next.js frontends to Node.js APIs and MongoDB/PostgreSQL databases — and deploy on AWS, Firebase, Vercel and more. I\'m also the founder of DeepITWorld, my software company.',
      stats: [{ n: '3.90', l: 'CGPA / 4.00' }, { n: '7+', l: 'Projects built' }, { n: '5+', l: 'Certifications' }],
      skills: ['HTML', 'CSS', 'JavaScript', 'TypeScript', 'React', 'Next.js', 'Tailwind', 'Node.js', 'Express', 'MongoDB', 'PostgreSQL', 'MySQL', 'Firebase', 'Redis', 'C++', 'Python', 'Git', 'Docker', 'Linux', 'Figma'],
    },
    resume: { file: '/assets/resume.pdf', preview: '/assets/resume-preview.jpg', fileName: 'Muhammad_Abuzar_Resume.pdf' },
    education: [
      { id: 'e1', degree: 'BS Computer Science', inst: 'Sir Syed CASE Institute of Technology, Islamabad', years: '2024 – 2028', note: 'CGPA 3.90 / 4.00' },
      { id: 'e2', degree: 'FSC (Pre-Engineering)', inst: 'The Orbit College, Lahore Swabi', years: '2021 – 2023', note: 'Position Holder' },
      { id: 'e3', degree: 'Matriculation', inst: 'Government Higher Secondary School Jalsai', years: '2019 – 2021', note: 'Stars Reward Holder' },
    ],
    certs: [
      { id: 'c1', title: 'Oracle Cloud', issuer: 'Oracle — In Progress', img: null },
      { id: 'c2', title: 'React & Next.js', issuer: 'Full Stack Frontend Certification', img: null },
      { id: 'c3', title: 'Full Stack Web Development', issuer: 'Web Development Certification', img: null },
      { id: 'c4', title: 'Node.js & Express.js, C++, Go, Python', issuer: 'Backend & Programming Languages', img: null },
      { id: 'c5', title: 'Modern JavaScript', issuer: 'JavaScript Certification', img: null },
    ],
    blogs: [
      { id: 'b1', title: 'How I Built DeepCircle — a University Management Platform', date: '2026-05-12',
        excerpt: 'Lessons from building a full university management and real-time messaging app with Next.js, Node.js and MongoDB.',
        content: 'DeepCircle started as a simple idea: universities in Pakistan needed one platform for announcements, student records and communication.\n\nI built the frontend in Next.js with Tailwind CSS, the API layer with Node.js and Express, and used MongoDB for flexible document storage. Real-time messaging was the hardest part — getting message delivery, read receipts and reconnection handling right took several iterations.\n\nKey lessons:\n\n1. Start with the data model. Student records, courses and messages all relate — get the schema right early.\n2. Real-time features multiply complexity. Build the REST version first, then layer sockets on top.\n3. Ship early to real users. Feedback from actual students reshaped half the UI.\n\nIf you\'re building your first big platform, pick a real problem around you. It keeps you motivated when the bugs pile up.',
        youtube: '' },
      { id: 'b2', title: 'JavaScript Tips That Actually Save Time', date: '2026-06-02',
        excerpt: 'A handful of small JavaScript patterns I use every single day — destructuring tricks, optional chaining, and more.',
        content: 'After years of writing JavaScript, a few patterns keep proving their worth every day.\n\nOptional chaining (?.) alone has eliminated an entire category of bugs from my code. Combined with the nullish coalescing operator (??), handling missing data becomes clean and readable.\n\nDestructuring with defaults is another favorite — pulling values out of objects while guarding against undefined in one line.\n\nAnd finally: use array methods like map, filter and reduce, but don\'t force them. Sometimes a plain for loop is the clearest tool in the box.',
        youtube: 'https://www.youtube.com/watch?v=W6NZfCO5SIk' },
      { id: 'b3', title: 'From C++ Fundamentals to Full Stack: My Learning Path', date: '2026-06-20',
        excerpt: 'How building console apps in C++ — an airline reservation system, an events manager — made me a better web developer.',
        content: 'Before I ever wrote a line of React, I built console applications in C++: an airline reservation system with booking and seat management, and a university events management system using OOP and DSA.\n\nIt felt slow at the time. No pretty UI, just logic. But those projects taught me things frameworks never could:\n\nMemory and data structures matter. When you\'ve managed seat maps with raw arrays and structs, database indexing suddenly makes sense.\n\nOOP clicked for real. Designing classes for flights, bookings and passengers taught me modeling — the same skill I now use for MongoDB schemas and API design.\n\nDebugging discipline. With no dev tools, you learn to read code carefully and think before you run.\n\nMy advice to CS students: don\'t skip the fundamentals to chase frameworks. The fundamentals are what make the frameworks easy.',
        youtube: '' },
    ],
    projects: [
      { id: 'p1', title: 'DeepCircle — University Management & Messaging App', desc: 'A comprehensive platform for university management, communication, announcements, student records and real-time messaging.', tech: ['Next.js', 'Node.js', 'Express', 'MongoDB', 'Tailwind'], link: 'https://github.com/Itsabuzar98' },
      { id: 'p2', title: 'ProLearnHub — Learning & Internship Platform', desc: 'A platform for students to access courses, track learning progress and apply for internships.', tech: ['Next.js', 'React', 'Node.js', 'MongoDB', 'Tailwind'], link: 'https://github.com/Itsabuzar98' },
      { id: 'p3', title: 'DeepITWorld — Company Website', desc: 'Official website for my company showcasing services, projects and business solutions.', tech: ['Next.js', 'React', 'Tailwind'], link: 'https://www.deepitworld.com' },
      { id: 'p4', title: 'Personal Portfolio Website', desc: 'Personal portfolio website to showcase skills, projects, experience and achievements.', tech: ['Next.js', 'TypeScript', 'Tailwind'], link: 'https://www.deepitworld.com' },
      { id: 'p5', title: 'Attendance Management App', desc: 'Application to manage student attendance, reports and analytics.', tech: ['React', 'Node.js', 'MongoDB'], link: 'https://github.com/Itsabuzar98' },
      { id: 'p6', title: 'Airline Reservation System', desc: 'Console based airline reservation system with booking, cancellation and seat management.', tech: ['C++'], link: 'https://github.com/Itsabuzar98' },
      { id: 'p7', title: 'University Events Management System', desc: 'System to manage university events, registrations, participants and schedules — built with OOP and DSA principles.', tech: ['C++'], link: 'https://github.com/Itsabuzar98' },
    ],
    contact: {
      email: 'itsabuzar99@gmail.com', phone: '+92 325 1829199', location: 'Islamabad, Pakistan',
      website: 'https://www.deepitworld.com', github: 'https://github.com/Itsabuzar98', linkedin: 'https://linkedin.com/in/abuzar99',
    },
  };
}
