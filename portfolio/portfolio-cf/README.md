# Muhammad Abuzar — Portfolio (Cloudflare Workers + KV + R2)

A portfolio website with a fully server-side admin CMS.

## Architecture
- **Worker** (`src/worker.js`) — serves the static site, exposes the JSON API, enforces ALL authorization server-side.
- **KV** (`CONTENT_KV`) — site content, admin password hash, session records, login rate-limit counters.
- **R2** (`MEDIA`) — uploaded files (certificate images, photos, resume PDFs) served at `/media/<key>`.
- **Frontend** (`public/`) — static SPA. Contains zero secrets. The `isAdmin` flag only controls what is drawn; every write is re-verified by the Worker.

## Security measures
| Layer | Measure |
|---|---|
| Passwords | PBKDF2-SHA256, 100,000 iterations, random 16-byte salt (never plain SHA-256, never plaintext) |
| Sessions | 256-bit random Bearer token; only its SHA-256 hash is stored in KV; 8 h absolute lifetime + sliding refresh; server-side logout |
| Login | Rate-limited: 10 attempts / IP / 10 minutes; identical error message whether account exists or not |
| First-run | `/api/setup` requires the `SETUP_KEY` secret — nobody can race you to claim the admin account after deploy |
| Writes | Every mutating endpoint (`PUT /api/content`, `POST /api/upload`, `DELETE /api/media/*`, password change) calls `requireAdmin()` — flipping the client flag in DevTools just gets you 401s |
| Uploads | 5 MB cap, MIME allowlist (JPEG/PNG/WebP/PDF), magic-byte sniffing, random object keys (no traversal/overwrite) |
| Headers | Strict CSP (`script-src 'self'`, no inline handlers anywhere), `X-Frame-Options: DENY`, `nosniff`, HSTS, Referrer-Policy, Permissions-Policy |
| XSS | All user content passes through `esc()` before rendering, and CSP is the second line of defense |
| CSRF | Not applicable — auth is an explicit Bearer header, not a cookie |
| Timing | Constant-time comparison for hashes and the setup key |
| Payloads | Content JSON capped at 400 KB; body-size checks on every write |

## Deploy (one time, ~5 minutes)

```bash
# 0) Prereqs: Node 18+, a free Cloudflare account
npm install
npx wrangler login

# 1) Create the KV namespace, copy the printed id into wrangler.toml
npx wrangler kv namespace create CONTENT_KV

# 2) Create the R2 bucket (name must match wrangler.toml)
npx wrangler r2 bucket create abuzar-portfolio-media

# 3) Set the one-time setup key (pick any long random string, keep it private)
npx wrangler secret put SETUP_KEY

# 4) Ship it
npx wrangler deploy
```

You'll get a URL like `https://abuzar-portfolio.<your-subdomain>.workers.dev`.
Add a custom domain later in the Cloudflare dashboard → Workers → your worker → Settings → Domains & Routes.

## First login
1. Open the site, press **Ctrl+Shift+A** (or triple-click the logo, or open `/#/admin`).
2. The form is in **setup mode**: enter your `SETUP_KEY` and choose an admin password (min 10 chars).
3. You're in — green ✎ pins appear on every section. Upload your certificate images from the Resume page.

## Local development
```bash
npm run dev   # http://localhost:8787 with local KV/R2 emulation
```

## Notes
- Login sessions live in `sessionStorage` (cleared when the tab closes).
- The resume "Download" button serves `/assets/resume.pdf` until you upload a replacement from the admin ✎ next to it.
- To rotate the admin password: Contact page → ⚙ card (verified server-side).
- To reset everything: delete the `auth:admin` / `site:content` keys in the KV dashboard.
