import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

// Resolve __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Config
const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;
const PROCTOR_SEED = process.env.PROCTOR_SEED || '';
const CODE_STEP_SECONDS = process.env.CODE_STEP_SECONDS ? Number(process.env.CODE_STEP_SECONDS) : 30; // 30s window
const DRIFT_STEPS = process.env.DRIFT_STEPS ? Number(process.env.DRIFT_STEPS) : 1; // ±1 allowed
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const FRAME_ANCESTORS = (process.env.FRAME_ANCESTORS || '').split(',').map(s => s.trim()).filter(Boolean);

if (!PROCTOR_SEED) {
  console.warn('[WARN] PROCTOR_SEED not set. Set PROCTOR_SEED in environment for deterministic codes.');
}

// Database (SQLite) for per-session per-window usage tracking
const dbPath = path.join(__dirname, 'data.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS used_codes (
  window INTEGER NOT NULL,
  sid TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (window, sid)
);
`);

// Helpers
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) {
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function makeSid() {
  return crypto.randomBytes(16).toString('hex');
}

function setSecurityHeaders(res) {
  if (FRAME_ANCESTORS.length) {
    // CSP frame-ancestors for embedding control
    res.setHeader('Content-Security-Policy', `frame-ancestors ${FRAME_ANCESTORS.join(' ')}; default-src 'self' 'unsafe-inline' 'unsafe-eval' data:`);
  }
  // Allow simple embedding if not configured; do not set X-Frame-Options in that case
}

function hmacSha256(keyBytes, msgBytes) {
  return crypto.createHmac('sha256', keyBytes).update(msgBytes).digest();
}

function textToBytes(str) {
  return Buffer.from(str, 'utf8');
}

function numTo8ByteBE(num) {
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = num & 0xff; num = Math.floor(num / 256); }
  return buf;
}

function deriveKeyBytes(seed) {
  return crypto.createHash('sha256').update(textToBytes(seed)).digest();
}

function dynamicTruncate(hmacBuf) {
  const offset = hmacBuf[hmacBuf.length - 1] & 0x0f;
  const bin = ((hmacBuf[offset] & 0x7f) << 24) | (hmacBuf[offset + 1] << 16) | (hmacBuf[offset + 2] << 8) | (hmacBuf[offset + 3]);
  return bin >>> 0; // ensure unsigned
}

function totpForCounter(seed, counter, digits = 6) {
  const key = deriveKeyBytes(seed);
  const msg = numTo8ByteBE(counter);
  const mac = hmacSha256(key, msg);
  const bin = dynamicTruncate(mac);
  const mod = 10 ** digits;
  return String(bin % mod).padStart(digits, '0');
}

function currentWindow(nowMs = Date.now(), stepSec = CODE_STEP_SECONDS) {
  const t = Math.floor(nowMs / 1000);
  return Math.floor(t / stepSec);
}

function validCodes(seed, nowMs = Date.now()) {
  const ctr = currentWindow(nowMs);
  return {
    window: ctr,
    codes: [
      totpForCounter(seed, ctr - DRIFT_STEPS),
      totpForCounter(seed, ctr),
      totpForCounter(seed, ctr + DRIFT_STEPS),
    ],
    expiresIn: CODE_STEP_SECONDS - (Math.floor(nowMs / 1000) % CODE_STEP_SECONDS)
  };
}

// App
const app = express();

// CORS (for API routes only)
if (ALLOWED_ORIGINS.length) {
  app.use('/api', cors({ origin: ALLOWED_ORIGINS, credentials: true }));
}

app.use('/api', express.json());

// Session endpoint: establishes a session cookie if missing
app.get('/api/session', (req, res) => {
  const cookies = parseCookies(req.headers.cookie || '');
  let sid = cookies['sid'];
  if (!sid) {
    sid = makeSid();
    res.setHeader('Set-Cookie', `sid=${encodeURIComponent(sid)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`); // 30 days
  }
  setSecurityHeaders(res);
  res.json({ ok: true });
});

// Verify one-time code for this session and current window
app.post('/api/verify-code', (req, res) => {
  const cookies = parseCookies(req.headers.cookie || '');
  let sid = cookies['sid'];
  if (!sid) {
    sid = makeSid();
    res.setHeader('Set-Cookie', `sid=${encodeURIComponent(sid)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);
  }

  const { code } = req.body || {};
  if (!code || typeof code !== 'string' || code.length < 6) {
    return res.status(400).json({ ok: false, error: 'invalid_code' });
  }
  if (!PROCTOR_SEED) {
    return res.status(500).json({ ok: false, error: 'server_not_configured' });
  }

  const { window: win, codes, expiresIn } = validCodes(PROCTOR_SEED);
  // Enforce one-time per session per window
  const check = db.prepare('SELECT 1 FROM used_codes WHERE window = ? AND sid = ?').get(win, sid);
  if (check) {
    setSecurityHeaders(res);
    return res.status(409).json({ ok: false, error: 'already_used', window: win, expiresInSeconds: expiresIn });
  }

  if (!codes.includes(code)) {
    setSecurityHeaders(res);
    return res.status(401).json({ ok: false, error: 'invalid_code', window: win, expiresInSeconds: expiresIn });
  }

  db.prepare('INSERT OR IGNORE INTO used_codes (window, sid, created_at) VALUES (?, ?, ?)').run(win, sid, Date.now());
  setSecurityHeaders(res);
  return res.json({ ok: true, window: win, expiresInSeconds: expiresIn });
});

// Optionally serve static files (index.html) from project root for easy local testing
const rootDir = path.resolve(__dirname, '..');
app.use(express.static(rootDir));

app.get('*', (req, res) => {
  setSecurityHeaders(res);
  res.sendFile(path.join(rootDir, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[server] listening on http://localhost:${PORT}`);
});