// Worker outbound signing toolkit (A2 read signer + A3 v2 device-bound envelopes).
// The ONLY place worker-side read/command signatures are built. Live binding: env.GW_SIGN_PRIVATE
// (pkcs8 base64) - the private key never leaves the worker. Canonical strings are byte-identical
// to the PC-side verifiers (verifyReadAuth / validEnvelope); the shared contract lives in
// src/lib/command-contract.js. AUTHORITY SCOPE: a signature proves the sender key authorized this
// envelope - it is NOT proof of a user's consent to any specific command; device ownership and
// user consent are verified by the owner backend BEFORE this helper is ever called.
const CMD_TTL_MS = 60000; // command envelope validity: short - replay windows stay small
const { signerId, assertKind, assertNoReserved, assertTtl } = require('../src/lib/command-contract.js');
const READ_PATHS = new Set(['/task', '/info']); // exact paths only - the signing oracle never signs arbitrary routes
const READ_QUERY_CAP = 200; // bytes

async function signerKey(env) {
  if (!env || !env.GW_SIGN_PRIVATE) throw new Error('GW_SIGN_PRIVATE missing');
  return crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(env.GW_SIGN_PRIVATE), c => c.charCodeAt(0)), { name: 'Ed25519' }, false, ['sign']);
}
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const NO_CTRL = s => !/[\x00-\x1f\x7f]/.test(s); // no newline/control chars in ANY canonical field
async function signCanon(key, fields) {
  for (const f of fields) if (!NO_CTRL(f)) throw new Error('control char in canonical field');
  return hex(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(fields.join('\n'))));
}

// A2: read signer. Authorizes ONE read on ONE device: the caller (owner backend / sender client)
// attaches the returned headers to its request to the device's tunnel URL. The six canonical
// fields are [method, path, query, ts, nonce, device] - exactly what verifyReadAuth checks.
// GET only; /task?id=<strict id> or /info with an empty query; nothing else is signable.
async function signReadRequest(env, { device, method, path, query }) {
  const key = await signerKey(env);
  method = String(method || 'GET').toUpperCase(); path = String(path || ''); query = String(query || '');
  device = String(device || '');
  if (!/^[0-9a-f]{16}$/.test(device)) throw new Error('bad device id');
  if (method !== 'GET') throw new Error('read signer signs GET only');
  if (!READ_PATHS.has(path)) throw new Error('read path not allowed');
  if (Buffer.byteLength(query) > READ_QUERY_CAP) throw new Error('query too long');
  const parts = query ? query.split('&') : [];
  if (new Set(parts.map(p => p.split('=')[0])).size !== parts.length) throw new Error('duplicate query param');
  if (path === '/task') {
    const m = /^id=([\w-]{1,80})$/.exec(query); // exactly one id param, strict ledger shape
    if (!m || !signerId(m[1])) throw new Error('/task requires id=<strict id>');
  } else if (query !== '') throw new Error('/info takes no query');
  const ts = Date.now();
  const nonceBytes = new Uint8Array(12); crypto.getRandomValues(nonceBytes);
  const nonce = [...nonceBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const sig = await signCanon(key, [method, path, query, String(ts), nonce, device]);
  return { ts, nonce, device, sig }; // headers: X-GW-Read-Ts / X-GW-Read-Nonce / X-GW-Read-Device / X-GW-Read-Sig
}

// A3: command envelopes. v2 is device-first six-field (strict-ready); v1 is the legacy five-field
// for the pre-strict window. data is canonicalized ONCE (JSON.stringify of the exact object sent).
async function buildCommandEnvelope(env, { id, kind, device, data, ttlMs }) {
  if (!signerId(String(id || ''))) throw new Error('bad command id'); // shared contract: subset of the ledger shape, no prototype names
  assertKind(kind); kind = String(kind); // closed allowlist - never length-only
  assertNoReserved(data); // a payload may never smuggle envelope fields the PC would refuse
  assertTtl(ttlMs);
  const key = await signerKey(env);
  const ts = Date.now(), exp = ts + (ttlMs == null ? CMD_TTL_MS : ttlMs);
  const payload = JSON.stringify(data && typeof data === 'object' && !Array.isArray(data) ? data : {});
  if (device != null) { // v2: device-first canonical
    device = String(device); if (!/^[0-9a-f]{16}$/.test(device)) throw new Error('bad device id');
    const sig = await signCanon(key, [device, String(id), kind, String(ts), String(exp), payload]);
    return { id: String(id), kind, device, ts, exp, sig, data: JSON.parse(payload) };
  }
  const sig = await signCanon(key, [String(id), kind, String(ts), String(exp), payload]); // v1 legacy
  return { id: String(id), kind, ts, exp, sig, data: JSON.parse(payload) };
}

if (typeof module !== 'undefined' && module.exports) module.exports = { signReadRequest, buildCommandEnvelope, CMD_TTL_MS };
