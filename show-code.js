// Utility script to print the current one-time code and neighbors
// Usage:
//   PROCTOR_SEED=your-secret CODE_STEP_SECONDS=30 DRIFT_STEPS=1 node show-code.js

import crypto from 'crypto';

const PROCTOR_SEED = process.env.PROCTOR_SEED || '';
const CODE_STEP_SECONDS = process.env.CODE_STEP_SECONDS ? Number(process.env.CODE_STEP_SECONDS) : 30;
const DRIFT_STEPS = process.env.DRIFT_STEPS ? Number(process.env.DRIFT_STEPS) : 1;

if (!PROCTOR_SEED) {
  console.error('Missing PROCTOR_SEED');
  process.exit(1);
}

function textToBytes(str){ return Buffer.from(str, 'utf8'); }
function numTo8ByteBE(num){ const buf = Buffer.alloc(8); for (let i=7;i>=0;i--){ buf[i]=num&0xff; num=Math.floor(num/256);} return buf; }
function deriveKeyBytes(seed){ return crypto.createHash('sha256').update(textToBytes(seed)).digest(); }
function hmacSha256(key, msg){ return crypto.createHmac('sha256', key).update(msg).digest(); }
function dynamicTruncate(h){ const o=h[h.length-1]&0x0f; const bin=((h[o]&0x7f)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|(h[o+3]); return bin>>>0; }
function totp(seed, counter, digits=6){ const k=deriveKeyBytes(seed); const m=numTo8ByteBE(counter); const mac=hmacSha256(k,m); const bin=dynamicTruncate(mac); return String(bin % (10**digits)).padStart(digits,'0'); }

const now = Date.now();
const t = Math.floor(now/1000);
const ctr = Math.floor(t / CODE_STEP_SECONDS);
const codes = [ totp(PROCTOR_SEED, ctr-DRIFT_STEPS), totp(PROCTOR_SEED, ctr), totp(PROCTOR_SEED, ctr+DRIFT_STEPS) ];
const expiresIn = CODE_STEP_SECONDS - (t % CODE_STEP_SECONDS);

console.log(JSON.stringify({ window: ctr, code: codes[1], neighbors: codes, expiresIn }, null, 2));