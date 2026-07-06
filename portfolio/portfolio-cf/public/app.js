/* Muhammad Abuzar — Portfolio frontend (talks to the Cloudflare Worker API).
   No secrets live here. The admin token is a Bearer token kept in
   sessionStorage; every write is re-verified server-side. */

'use strict';

/* ------------------------------- API ---------------------------------- */
const Api = {
  token: sessionStorage.getItem('pf_token') || null,
  setToken(t) { this.token = t; t ? sessionStorage.setItem('pf_token', t) : sessionStorage.removeItem('pf_token'); },
  async req(path, opts = {}) {
    const headers = Object.assign({}, opts.headers);
    if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.json); }
    if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
    const res = await fetch(path, Object.assign({}, opts, { headers }));
    if (res.status === 401 && this.token) { App.forceLogout(); throw new Error('Session expired'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('Request failed (' + res.status + ')'));
    return data;
  },
  getStatus() { return this.req('/api/status'); },
  getContent() { return this.req('/api/content'); },
  saveContent(data) { return this.req('/api/content', { method: 'PUT', json: data }); },
  setup(setupKey, password) { return this.req('/api/setup', { method: 'POST', json: { password }, headers: { 'X-Setup-Key': setupKey } }); },
  login(password) { return this.req('/api/login', { method: 'POST', json: { password } }); },
  logout() { return this.req('/api/logout', { method: 'POST' }); },
  changePassword(current, next) { return this.req('/api/change-password', { method: 'POST', json: { current, next } }); },
  async upload(fileOrBlob, filename) {
    const fd = new FormData();
    fd.append('file', fileOrBlob, filename || fileOrBlob.name || 'upload');
    return this.req('/api/upload', { method: 'POST', body: fd });
  },
};

/* ------------------------------ helpers -------------------------------- */
function esc(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function escAttr(s) { return esc(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function val(id) { return document.getElementById(id).value; }
function fmtDate(d) { try { return new Date(d + 'T00:00:00').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }); } catch (e) { return d; } }
function ytId(url) {
  if (!url) return null;
  const m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/|live\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/);
  return m ? m[1] : null;
}
const ICON_MAP = {
  'html': 'devicon-html5-plain colored', 'html5': 'devicon-html5-plain colored', 'css': 'devicon-css3-plain colored', 'css3': 'devicon-css3-plain colored',
  'javascript': 'devicon-javascript-plain colored', 'js': 'devicon-javascript-plain colored',
  'typescript': 'devicon-typescript-plain colored', 'python': 'devicon-python-plain colored',
  'c++': 'devicon-cplusplus-plain colored', 'cpp': 'devicon-cplusplus-plain colored', 'c': 'devicon-c-plain colored', 'c#': 'devicon-csharp-plain colored',
  'go': 'devicon-go-original-wordmark colored', 'golang': 'devicon-go-original-wordmark colored',
  'node.js': 'devicon-nodejs-plain colored', 'node': 'devicon-nodejs-plain colored', 'nodejs': 'devicon-nodejs-plain colored',
  'express': 'devicon-express-original', 'express.js': 'devicon-express-original',
  'next.js': 'devicon-nextjs-original', 'nextjs': 'devicon-nextjs-original',
  'react': 'devicon-react-original colored', 'vue': 'devicon-vuejs-plain colored', 'angular': 'devicon-angularjs-plain colored',
  'tailwind': 'devicon-tailwindcss-plain colored', 'tailwind css': 'devicon-tailwindcss-plain colored',
  'java': 'devicon-java-plain colored', 'php': 'devicon-php-plain colored', 'ruby': 'devicon-ruby-plain colored',
  'rust': 'devicon-rust-plain', 'swift': 'devicon-swift-plain colored', 'kotlin': 'devicon-kotlin-plain colored',
  'git': 'devicon-git-plain colored', 'github': 'devicon-github-original', 'docker': 'devicon-docker-plain colored',
  'mysql': 'devicon-mysql-plain colored', 'postgresql': 'devicon-postgresql-plain colored', 'mongodb': 'devicon-mongodb-plain colored',
  'redis': 'devicon-redis-plain colored', 'firebase': 'devicon-firebase-plain colored', 'flutter': 'devicon-flutter-plain colored', 'dart': 'devicon-dart-plain colored',
  'bootstrap': 'devicon-bootstrap-plain colored', 'linux': 'devicon-linux-plain', 'figma': 'devicon-figma-plain colored',
  'django': 'devicon-django-plain', 'flask': 'devicon-flask-original',
};
function iconFor(name) { return ICON_MAP[name.trim().toLowerCase()] || null; }

function compressImage(file, maxW = 1300, quality = 0.78) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => {
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, maxW / img.width);
        const cv = document.createElement('canvas');
        cv.width = Math.round(img.width * scale); cv.height = Math.round(img.height * scale);
        cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
        cv.toBlob(b => b ? res(b) : rej(new Error('compress failed')), 'image/jpeg', quality);
      };
      img.onerror = rej; img.src = r.result;
    };
    r.onerror = rej; r.readAsDataURL(file);
  });
}

/* -------------------------------- App ---------------------------------- */
const App = {
  data: null, isAdmin: false, needsSetup: false, logoClicks: 0, logoClickTimer: null,

  async init() {
    try {
      const [content, status] = await Promise.all([Api.getContent(), Api.getStatus()]);
      this.data = content;
      this.needsSetup = !status.setup;
    } catch (e) {
      document.body.innerHTML = '<p style="padding:40px;text-align:center">Could not load site content. Please refresh.</p>';
      return;
    }
    // restore admin session if a token survives in this tab
    if (Api.token) { this.isAdmin = true; document.body.classList.add('admin'); }

    this.renderAll();
    document.getElementById('f-year').textContent = new Date().getFullYear();

    // hidden login: triple-click logo or Ctrl+Shift+A, or open #/admin
    document.getElementById('logo').addEventListener('click', () => {
      this.logoClicks++;
      clearTimeout(this.logoClickTimer);
      this.logoClickTimer = setTimeout(() => this.logoClicks = 0, 900);
      if (this.logoClicks >= 3) { this.logoClicks = 0; if (!this.isAdmin) this.openLogin(); }
    });
    document.addEventListener('keydown', e => {
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'a') { e.preventDefault(); if (!this.isAdmin) this.openLogin(); }
      if (e.key === 'Escape') this.closeModals();
    });
    if (location.hash === '#/admin' && !this.isAdmin) this.openLogin();

    // CSP-safe event delegation for all [data-action] elements
    document.addEventListener('click', e => {
      const el = e.target.closest('[data-action]');
      if (el) { this.dispatch(el.dataset.action, e); return; }
      if (e.target.classList && e.target.classList.contains('overlay')) this.closeModals();
    });
  },

  dispatch(action, e) {
    if (action.indexOf('nav-links') !== -1) { document.querySelector('.nav-links').classList.toggle('open'); return; }
    const m = action.match(/^(?:event\.stopPropagation\(\);\s*)?App\.(\w+)\((?:'((?:[^'\\]|\\.)*)'|null|)\)$/);
    if (!m) return;
    if (action.startsWith('event.stopPropagation')) e.stopPropagation();
    const fn = this[m[1]];
    if (typeof fn === 'function') fn.call(this, m[2] !== undefined ? m[2] : (action.includes('null') ? null : undefined));
  },

  /* ---------- navigation ---------- */
  go(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('visible'));
    document.getElementById('page-' + page).classList.add('visible');
    document.querySelectorAll('.nav-links button').forEach(b => b.classList.toggle('active', b.dataset.page === page));
    document.querySelector('.nav-links').classList.remove('open');
    if (page === 'blogs') this.showBlogList();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  /* ---------- auth ---------- */
  openLogin() {
    document.getElementById('setupFields').style.display = this.needsSetup ? 'block' : 'none';
    document.getElementById('confirmField').style.display = this.needsSetup ? 'block' : 'none';
    document.querySelector('#loginOverlay h3').textContent = this.needsSetup ? '🛡 First-time admin setup' : '🛡 Admin login';
    document.getElementById('loginOverlay').classList.add('open');
    document.getElementById('loginPass').value = '';
    const err = document.getElementById('loginErr'); err.style.display = 'none';
    const pass = document.getElementById('loginPass');
    pass.onkeydown = ev => { if (ev.key === 'Enter') App.login(); };
    setTimeout(() => pass.focus(), 50);
  },
  async login() {
    const err = document.getElementById('loginErr');
    const show = m => { err.textContent = m; err.style.display = 'block'; };
    const password = val('loginPass');
    try {
      if (this.needsSetup) {
        if (password.length < 10) return show('Password must be at least 10 characters.');
        if (password !== val('loginPass2')) return show('Passwords do not match.');
        await Api.setup(val('setupKey'), password);
        this.needsSetup = false;
      }
      const r = await Api.login(password);
      Api.setToken(r.token);
      this.isAdmin = true;
      document.body.classList.add('admin');
      this.closeModals();
      this.renderContact();
      this.toast('✔ Welcome back, Abuzar. Session valid for 8 hours.');
    } catch (e) { show(e.message); }
  },
  async logout() {
    try { await Api.logout(); } catch (e) {}
    this.forceLogout();
    this.toast('Logged out.');
  },
  forceLogout() {
    Api.setToken(null);
    this.isAdmin = false;
    document.body.classList.remove('admin');
    this.renderContact();
  },

  /* ---------- rendering ---------- */
  renderAll() { this.renderProfile(); this.renderResume(); this.renderBlogs(); this.renderProjects(); this.renderContact(); },

  renderProfile() {
    const p = this.data.profile;
    document.getElementById('logoName').textContent = p.name.split(' ').pop() || 'Portfolio';
    document.getElementById('f-name').textContent = p.name;
    document.getElementById('h-eyebrow').textContent = p.eyebrow;
    document.getElementById('h-name').textContent = p.name;
    document.getElementById('h-role').textContent = p.role;
    document.getElementById('h-tagline').textContent = p.tagline;
    document.getElementById('h-photo').src = p.photo;
    document.getElementById('h-about').textContent = p.about;
    document.title = p.name + ' — Portfolio';

    document.getElementById('h-stats').innerHTML = p.stats.map(s => `<div class="stat"><b>${esc(s.n)}</b><small>${esc(s.l)}</small></div>`).join('');
    document.getElementById('h-skills').innerHTML = p.skills.map(s => {
      const ic = iconFor(s);
      return `<span class="chip">${ic ? `<i class="${ic}" style="font-size:.95rem;vertical-align:-2px"></i> ` : ''}${esc(s)}</span>`;
    }).join('');

    const withIcons = p.skills.filter(s => iconFor(s)).slice(0, 12);
    const r1 = withIcons.filter((_, i) => i % 2 === 0), r2 = withIcons.filter((_, i) => i % 2 === 1);
    const wrap = document.querySelector('.orbit-wrap');
    const size = wrap.offsetWidth || 420;
    const place = (el, arr, radius) => {
      el.innerHTML = '';
      arr.forEach((s, i) => {
        const ang = (360 / arr.length) * i;
        const d = document.createElement('div');
        d.className = 'orb-icon';
        d.style.transform = `rotate(${ang}deg) translate(${radius}px) rotate(${-ang}deg)`;
        d.innerHTML = `<i class="${iconFor(s)}" title="${escAttr(s)}"></i>`;
        el.appendChild(d);
      });
    };
    place(document.getElementById('ring1'), r1, size * 0.38);
    place(document.getElementById('ring2'), r2, size * 0.52);

    const items = p.skills.map(s => {
      const ic = iconFor(s);
      return `<span>${ic ? `<i class="${ic}"></i>` : ''}${esc(s)}</span>`;
    }).join('');
    document.getElementById('marquee').innerHTML = items + items;
  },

  renderResume() {
    document.getElementById('resume-img').src = this.data.resume.preview;
    document.getElementById('edu-list').innerHTML = this.data.education.map(e => `
      <div class="edu-item">
        <div class="yrs">${esc(e.years)}</div>
        <h4>${esc(e.degree)}</h4>
        <div class="inst">${esc(e.inst)}</div>
        ${e.note ? `<span class="chip" style="margin-top:8px">${esc(e.note)}</span>` : ''}
      </div>`).join('');

    document.getElementById('cert-grid').innerHTML = this.data.certs.map(c => `
      <article class="item-card cert-card" data-action="App.viewCert('${escAttr(c.id)}')">
        <button class="edit-pin" data-action="event.stopPropagation();App.editCert('${escAttr(c.id)}')" title="Edit certification">✎</button>
        <div class="badge">🎓</div>
        <h3>${esc(c.title)}</h3>
        <p>${esc(c.issuer)}</p>
        ${c.img ? `<div class="thumb"><img src="${escAttr(c.img)}" alt="${escAttr(c.title)} certificate"></div><span class="view-tag">View certificate →</span>`
                : `<span class="no-file">Certificate file coming soon</span>`}
      </article>`).join('');
  },

  viewCert(id) {
    const c = this.data.certs.find(x => x.id === id); if (!c) return;
    if (!c.img) { this.toast(this.isAdmin ? 'No file attached yet — click ✎ to upload the certificate image.' : 'Certificate file will be available soon.'); return; }
    this.lightbox(c.title, c.img, c.title.replace(/[^a-z0-9]+/gi, '_') + '_certificate.jpg');
  },
  viewResume() {
    this.lightbox('Resume — ' + this.data.profile.name, this.data.resume.preview, 'resume-preview.jpg');
  },
  lightbox(title, src, dlName) {
    document.getElementById('lb-title').textContent = title;
    document.getElementById('lb-img').src = src;
    const btn = document.getElementById('lb-download');
    btn.onclick = () => { const a = document.createElement('a'); a.href = src; a.download = dlName; a.click(); };
    document.getElementById('lightbox').classList.add('open');
  },
  downloadResume() {
    const a = document.createElement('a');
    a.href = this.data.resume.file;
    a.download = this.data.resume.fileName || 'resume.pdf';
    a.click();
  },

  renderBlogs() {
    const g = document.getElementById('blog-grid');
    const blogs = [...this.data.blogs].sort((a, b) => b.date.localeCompare(a.date));
    g.innerHTML = blogs.length ? blogs.map(b => `
      <article class="item-card">
        ${ytId(b.youtube) ? '<span class="yt-flag" title="Includes video">▶</span>' : ''}
        <button class="edit-pin" data-action="event.stopPropagation();App.editBlog('${escAttr(b.id)}')" title="Edit post">✎</button>
        <span class="date">${esc(fmtDate(b.date))}</span>
        <h3>${esc(b.title)}</h3>
        <p>${esc(b.excerpt)}</p>
        <button class="read" data-action="App.readBlog('${escAttr(b.id)}')">Read post →</button>
      </article>`).join('')
      : '<p style="color:var(--muted)">No posts yet.</p>';
  },
  showBlogList() {
    document.getElementById('blog-list-view').style.display = 'block';
    document.getElementById('blog-read-view').style.display = 'none';
  },
  readBlog(id) {
    const b = this.data.blogs.find(x => x.id === id); if (!b) return;
    const vid = ytId(b.youtube);
    const v = document.getElementById('blog-read-view');
    v.innerHTML = `
      <div class="reader">
        <button class="back" data-action="App.showBlogList()">← All posts</button>
        <div style="position:relative">
          <button class="edit-pin" style="top:0" data-action="App.editBlog('${escAttr(b.id)}')" title="Edit post">✎</button>
          <div class="eyebrow">Blog post</div>
          <h1>${esc(b.title)}</h1>
          <div class="meta">${esc(fmtDate(b.date))} · ${esc(this.data.profile.name)}</div>
        </div>
        ${vid ? `<div class="video-frame"><iframe src="https://www.youtube.com/embed/${vid}" title="YouTube video" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></div>` : ''}
        <div class="body">${esc(b.content)}</div>
      </div>`;
    document.getElementById('blog-list-view').style.display = 'none';
    v.style.display = 'block';
    window.scrollTo({ top: 0 });
  },

  renderProjects() {
    const g = document.getElementById('project-grid');
    g.innerHTML = this.data.projects.length ? this.data.projects.map(p => `
      <article class="item-card">
        <button class="edit-pin" data-action="App.editProject('${escAttr(p.id)}')" title="Edit project">✎</button>
        <h3>${esc(p.title)}</h3>
        <p>${esc(p.desc)}</p>
        <div class="tech-tags">${p.tech.map(t => {
          const ic = iconFor(t);
          return `<span class="chip">${ic ? `<i class="${ic}" style="font-size:.85rem;vertical-align:-2px"></i> ` : ''}${esc(t)}</span>`;
        }).join('')}</div>
        ${p.link ? `<a class="read" style="margin-top:16px;display:inline-block" href="${escAttr(p.link)}" target="_blank" rel="noopener">Visit project ↗</a>` : ''}
      </article>`).join('')
      : '<p style="color:var(--muted)">No projects yet.</p>';
  },

  renderContact() {
    const c = this.data.contact;
    const rows = [
      { ico: '✉', label: 'Email', val: c.email, href: 'mailto:' + c.email },
      { ico: '📱', label: 'Phone', val: c.phone, href: 'tel:' + (c.phone || '').replace(/\s/g, '') },
      { ico: '📍', label: 'Location', val: c.location },
      { ico: '🌐', label: 'Website', val: c.website, href: c.website },
      { ico: '🐙', label: 'GitHub', val: c.github, href: c.github },
      { ico: '💼', label: 'LinkedIn', val: c.linkedin, href: c.linkedin },
    ].filter(r => r.val);
    let html = rows.map(r => `
      <div class="contact-item">
        <div class="ico">${r.ico}</div>
        <div><small>${r.label}</small>${r.href ? `<a href="${escAttr(r.href)}" target="_blank" rel="noopener"><b>${esc(r.val)}</b></a>` : `<b>${esc(r.val)}</b>`}</div>
      </div>`).join('');
    if (this.isAdmin) {
      html += `
      <div class="contact-item" style="border-color:rgba(34,211,170,.4)">
        <div class="ico">⚙</div>
        <div><small>Admin security</small><b>Change admin password</b><br>
        <button class="read" style="margin-top:8px;background:none;border:none;color:var(--accent2);font-weight:600" data-action="App.changePass()">Update password →</button></div>
      </div>`;
    }
    document.getElementById('contact-grid').innerHTML = html;
  },

  /* ---------- editors ---------- */
  modal(html) { document.getElementById('editModal').innerHTML = html; document.getElementById('editOverlay').classList.add('open'); },
  closeModals() { document.querySelectorAll('.overlay').forEach(o => o.classList.remove('open')); },
  guard() { if (!this.isAdmin) { this.toast('Admin login required.'); return false; } return true; },

  editProfile() {
    if (!this.guard()) return;
    const p = this.data.profile;
    this.modal(`
      <h3>Edit profile</h3><p class="hint">This updates the hero section.</p>
      <div class="field"><label>Eyebrow text</label><input id="e-eyebrow" value="${escAttr(p.eyebrow)}"></div>
      <div class="field"><label>Name</label><input id="e-name" value="${escAttr(p.name)}"></div>
      <div class="field"><label>Role / title</label><input id="e-role" value="${escAttr(p.role)}"></div>
      <div class="field"><label>Tagline</label><textarea id="e-tagline">${esc(p.tagline)}</textarea></div>
      <div class="field"><label>Photo (optional — replaces current)</label><input type="file" id="e-photo" accept="image/jpeg,image/png,image/webp"></div>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveProfile()">Save changes</button>
      </div>`);
  },
  async saveProfile() {
    try {
      const p = this.data.profile;
      p.eyebrow = val('e-eyebrow'); p.name = val('e-name'); p.role = val('e-role'); p.tagline = val('e-tagline');
      const f = document.getElementById('e-photo').files[0];
      if (f) {
        const blob = await compressImage(f, 700, 0.82);
        const up = await Api.upload(blob, 'photo.jpg');
        p.photo = up.url;
      }
      await this.persist(); this.renderProfile(); this.closeModals(); this.toast('Profile saved.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },

  editAbout() {
    if (!this.guard()) return;
    const p = this.data.profile;
    this.modal(`
      <h3>Edit about section</h3><p class="hint">Stats format: number | label (one per line)</p>
      <div class="field"><label>About text</label><textarea id="e-about" style="min-height:180px">${esc(p.about)}</textarea></div>
      <div class="field"><label>Stats</label><textarea id="e-stats">${esc(p.stats.map(s => s.n + ' | ' + s.l).join('\n'))}</textarea></div>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveAbout()">Save changes</button>
      </div>`);
  },
  async saveAbout() {
    try {
      const p = this.data.profile;
      p.about = val('e-about');
      p.stats = val('e-stats').split('\n').map(l => l.split('|')).filter(a => a.length >= 2).map(a => ({ n: a[0].trim(), l: a.slice(1).join('|').trim() }));
      await this.persist(); this.renderProfile(); this.closeModals(); this.toast('About section saved.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },

  editSkills() {
    if (!this.guard()) return;
    this.modal(`
      <h3>Edit skills</h3><p class="hint">Comma separated. Known names (HTML, CSS, JavaScript, TypeScript, React, Next.js, Node.js, C++, Go, Python, MongoDB, Docker…) get animated icons automatically.</p>
      <div class="field"><label>Skills</label><textarea id="e-skills">${esc(this.data.profile.skills.join(', '))}</textarea></div>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveSkills()">Save changes</button>
      </div>`);
  },
  async saveSkills() {
    try {
      this.data.profile.skills = val('e-skills').split(',').map(s => s.trim()).filter(Boolean);
      await this.persist(); this.renderProfile(); this.closeModals(); this.toast('Skills saved.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },

  /* ----- resume / education / certs ----- */
  editResume() {
    if (!this.guard()) return;
    this.modal(`
      <h3>Replace resume</h3>
      <p class="hint">Upload a new PDF (max 5 MB) and, optionally, a preview image (JPG/PNG) shown on the page.</p>
      <div class="field"><label>Resume PDF</label><input type="file" id="e-resume" accept="application/pdf"></div>
      <div class="field"><label>Preview image (optional)</label><input type="file" id="e-resimg" accept="image/jpeg,image/png,image/webp"></div>
      <p class="err" id="resErr"></p>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveResume()">Save resume</button>
      </div>`);
  },
  async saveResume() {
    const err = document.getElementById('resErr');
    try {
      const pdf = document.getElementById('e-resume').files[0];
      const img = document.getElementById('e-resimg').files[0];
      if (!pdf && !img) { err.textContent = 'Choose at least one file.'; err.style.display = 'block'; return; }
      if (pdf) {
        const up = await Api.upload(pdf, pdf.name);
        this.data.resume.file = up.url;
        this.data.resume.fileName = pdf.name;
      }
      if (img) {
        const blob = await compressImage(img, 1400, 0.8);
        const up = await Api.upload(blob, 'resume-preview.jpg');
        this.data.resume.preview = up.url;
      }
      await this.persist(); this.renderResume(); this.closeModals(); this.toast('Resume updated.');
    } catch (e) { err.textContent = e.message; err.style.display = 'block'; }
  },

  editEducation() {
    if (!this.guard()) return;
    const txt = this.data.education.map(e => [e.degree, e.inst, e.years, e.note || ''].join(' | ')).join('\n');
    this.modal(`
      <h3>Edit education</h3><p class="hint">One entry per line: Degree | Institute | Years | Note (note optional)</p>
      <div class="field"><label>Entries</label><textarea id="e-edu" style="min-height:180px">${esc(txt)}</textarea></div>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveEducation()">Save changes</button>
      </div>`);
  },
  async saveEducation() {
    try {
      this.data.education = val('e-edu').split('\n').map(l => l.split('|').map(s => s.trim())).filter(a => a.length >= 3)
        .map((a, i) => ({ id: 'e' + (i + 1), degree: a[0], inst: a[1], years: a[2], note: a[3] || '' }));
      await this.persist(); this.renderResume(); this.closeModals(); this.toast('Education saved.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },

  editCert(id) {
    if (!this.guard()) return;
    const c = id ? this.data.certs.find(x => x.id === id) : { id: null, title: '', issuer: '', img: null };
    this.modal(`
      <h3>${id ? 'Edit' : 'Add'} certification</h3>
      <p class="hint">Upload a photo/scan of the certificate so visitors can view and download it.</p>
      <div class="field"><label>Title</label><input id="e-ctitle" value="${escAttr(c.title)}"></div>
      <div class="field"><label>Issuer / note</label><input id="e-cissuer" value="${escAttr(c.issuer)}"></div>
      <div class="field"><label>Certificate image ${c.img ? '(already attached — choose a file to replace)' : ''}</label><input type="file" id="e-cimg" accept="image/jpeg,image/png,image/webp"></div>
      <div class="modal-actions">
        ${id ? `<button class="btn-del" data-action="App.deleteCert('${escAttr(id)}')">Delete</button>` : ''}
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveCert('${escAttr(id || '')}')">${id ? 'Save changes' : 'Add certification'}</button>
      </div>`);
  },
  async saveCert(id) {
    try {
      const f = document.getElementById('e-cimg').files[0];
      let img = id ? (this.data.certs.find(x => x.id === id) || {}).img : null;
      if (f) {
        const blob = await compressImage(f, 1300, 0.78);
        const up = await Api.upload(blob, 'certificate.jpg');
        img = up.url;
      }
      const cert = { id: id || 'c' + Date.now(), title: val('e-ctitle') || 'Untitled', issuer: val('e-cissuer'), img };
      if (id) { const i = this.data.certs.findIndex(x => x.id === id); this.data.certs[i] = cert; } else this.data.certs.push(cert);
      await this.persist(); this.renderResume(); this.closeModals(); this.toast(id ? 'Certification updated.' : 'Certification added.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },
  async deleteCert(id) {
    if (!confirm('Delete this certification?')) return;
    this.data.certs = this.data.certs.filter(x => x.id !== id);
    try { await this.persist(); } catch (e) { this.toast('⚠ ' + e.message); return; }
    this.renderResume(); this.closeModals(); this.toast('Certification deleted.');
  },

  /* ----- blogs ----- */
  editBlog(id) {
    if (!this.guard()) return;
    const b = id ? this.data.blogs.find(x => x.id === id) : { id: null, title: '', date: new Date().toISOString().slice(0, 10), excerpt: '', content: '', youtube: '' };
    this.modal(`
      <h3>${id ? 'Edit' : 'New'} blog post</h3>
      <p class="hint">To embed a video, just paste any YouTube link — it will play inside the post.</p>
      <div class="field"><label>Title</label><input id="e-btitle" value="${escAttr(b.title)}"></div>
      <div class="field"><label>Date</label><input type="date" id="e-bdate" value="${escAttr(b.date)}"></div>
      <div class="field"><label>Excerpt (card preview)</label><textarea id="e-bexcerpt" style="min-height:70px">${esc(b.excerpt)}</textarea></div>
      <div class="field"><label>Content</label><textarea id="e-bcontent" style="min-height:220px">${esc(b.content)}</textarea></div>
      <div class="field"><label>YouTube link (optional)</label><input id="e-byt" placeholder="https://www.youtube.com/watch?v=..." value="${escAttr(b.youtube || '')}"><p class="err" id="ytErr">That doesn't look like a valid YouTube link.</p></div>
      <div class="modal-actions">
        ${id ? `<button class="btn-del" data-action="App.deleteBlog('${escAttr(id)}')">Delete</button>` : ''}
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveBlog('${escAttr(id || '')}')">${id ? 'Save changes' : 'Publish post'}</button>
      </div>`);
  },
  async saveBlog(id) {
    const yt = val('e-byt').trim();
    if (yt && !ytId(yt)) { document.getElementById('ytErr').style.display = 'block'; return; }
    try {
      const post = {
        id: id || 'b' + Date.now(), title: val('e-btitle') || 'Untitled', date: val('e-bdate') || new Date().toISOString().slice(0, 10),
        excerpt: val('e-bexcerpt'), content: val('e-bcontent'), youtube: yt,
      };
      if (id) { const i = this.data.blogs.findIndex(x => x.id === id); this.data.blogs[i] = post; } else this.data.blogs.push(post);
      await this.persist(); this.renderBlogs(); this.showBlogList(); this.closeModals(); this.toast(id ? 'Post updated.' : 'Post published.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },
  async deleteBlog(id) {
    if (!confirm('Delete this blog post permanently?')) return;
    this.data.blogs = this.data.blogs.filter(x => x.id !== id);
    try { await this.persist(); } catch (e) { this.toast('⚠ ' + e.message); return; }
    this.renderBlogs(); this.showBlogList(); this.closeModals(); this.toast('Post deleted.');
  },

  /* ----- projects ----- */
  editProject(id) {
    if (!this.guard()) return;
    const p = id ? this.data.projects.find(x => x.id === id) : { id: null, title: '', desc: '', tech: [], link: '' };
    this.modal(`
      <h3>${id ? 'Edit' : 'New'} project</h3>
      <div class="field"><label>Title</label><input id="e-ptitle" value="${escAttr(p.title)}"></div>
      <div class="field"><label>Description</label><textarea id="e-pdesc">${esc(p.desc)}</textarea></div>
      <div class="field"><label>Technologies (comma separated)</label><input id="e-ptech" value="${escAttr(p.tech.join(', '))}"></div>
      <div class="field"><label>Link (optional)</label><input id="e-plink" value="${escAttr(p.link || '')}" placeholder="https://..."></div>
      <div class="modal-actions">
        ${id ? `<button class="btn-del" data-action="App.deleteProject('${escAttr(id)}')">Delete</button>` : ''}
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveProject('${escAttr(id || '')}')">${id ? 'Save changes' : 'Add project'}</button>
      </div>`);
  },
  async saveProject(id) {
    try {
      const proj = {
        id: id || 'p' + Date.now(), title: val('e-ptitle') || 'Untitled', desc: val('e-pdesc'),
        tech: val('e-ptech').split(',').map(s => s.trim()).filter(Boolean), link: val('e-plink').trim(),
      };
      if (id) { const i = this.data.projects.findIndex(x => x.id === id); this.data.projects[i] = proj; } else this.data.projects.push(proj);
      await this.persist(); this.renderProjects(); this.closeModals(); this.toast(id ? 'Project updated.' : 'Project added.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },
  async deleteProject(id) {
    if (!confirm('Delete this project?')) return;
    this.data.projects = this.data.projects.filter(x => x.id !== id);
    try { await this.persist(); } catch (e) { this.toast('⚠ ' + e.message); return; }
    this.renderProjects(); this.closeModals(); this.toast('Project deleted.');
  },

  /* ----- contact ----- */
  editContact() {
    if (!this.guard()) return;
    const c = this.data.contact;
    this.modal(`
      <h3>Edit contact info</h3><p class="hint">Leave a field empty to hide it from the page.</p>
      <div class="field"><label>Email</label><input id="e-cemail" value="${escAttr(c.email)}"></div>
      <div class="field"><label>Phone</label><input id="e-cphone" value="${escAttr(c.phone)}"></div>
      <div class="field"><label>Location</label><input id="e-cloc" value="${escAttr(c.location)}"></div>
      <div class="field"><label>Website</label><input id="e-cweb" value="${escAttr(c.website || '')}"></div>
      <div class="field"><label>GitHub URL</label><input id="e-cgit" value="${escAttr(c.github)}"></div>
      <div class="field"><label>LinkedIn URL</label><input id="e-clink" value="${escAttr(c.linkedin)}"></div>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.saveContact()">Save changes</button>
      </div>`);
  },
  async saveContact() {
    try {
      Object.assign(this.data.contact, { email: val('e-cemail'), phone: val('e-cphone'), location: val('e-cloc'), website: val('e-cweb'), github: val('e-cgit'), linkedin: val('e-clink') });
      await this.persist(); this.renderContact(); this.closeModals(); this.toast('Contact info saved.');
    } catch (e) { this.toast('⚠ ' + e.message); }
  },

  /* ----- password ----- */
  changePass() {
    if (!this.guard()) return;
    this.modal(`
      <h3>⚙ Change admin password</h3><p class="hint">Minimum 10 characters. Verified server-side.</p>
      <div class="field"><label>Current password</label><input type="password" id="e-oldpass"></div>
      <div class="field"><label>New password</label><input type="password" id="e-newpass"></div>
      <div class="field"><label>Confirm new password</label><input type="password" id="e-newpass2"></div>
      <p class="err" id="passErr"></p>
      <div class="modal-actions">
        <button class="btn-cancel" data-action="App.closeModals()">Cancel</button>
        <button class="btn-save" data-action="App.savePass()">Update password</button>
      </div>`);
  },
  async savePass() {
    const err = document.getElementById('passErr');
    const show = m => { err.textContent = m; err.style.display = 'block'; };
    if (val('e-newpass') !== val('e-newpass2')) return show('Passwords do not match.');
    try {
      await Api.changePassword(val('e-oldpass'), val('e-newpass'));
      this.closeModals(); this.toast('🔒 Password updated.');
    } catch (e) { show(e.message); }
  },

  async persist() { await Api.saveContent(this.data); },

  toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.classList.add('show');
    clearTimeout(this._toastT);
    this._toastT = setTimeout(() => t.classList.remove('show'), 4200);
  },
};

window.App = App;
App.init();
