// Worker outbound signing toolkit (A2 read signer + A3 v2 device-bound envelopes).
// The ONLY place worker-side read/command signatures are built. Live binding: env.GW_SIGN_PRIVATE
// (pkcs8 base64) - the private key never leaves the worker. Canonical strings are byte-identical
// to the PC-side verifiers (verifyReadAuth / validEnvelope); the shared contract lives in
// src/lib/command-contract.js. AUTHORITY SCOPE: a signature proves the sender key authorized this
// envelope - it is NOT proof of a user's consent to any specific command; device ownership and
// user consent are verified by the owner backend BEFORE this helper is ever called.
const CMD_TTL_MS = 60000; // command envelope validity: short - replay windows stay small
const { signerId, assertKind, assertNoReserved, assertTtl } = require('../src/lib/command-contract.js');
const READ_PATHS = new Set(['/task', '/info', '/file']); // exact paths only - the signing oracle never signs arbitrary routes
const READ_QUERY_CAP = 200; // bytes
const FILE_QUERY_CAP = 900; // /file?path= carries an encoded absolute path
const DATA_BYTES_CAP = 8192; // max serialized data payload - the helper must never emit an unbounded wire body for a late network reject
const DATA_DEPTH_CAP = 8; // max nesting depth of the serialized data object

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
// GET only; /task?id=<strict id>, /info with an empty query, or /file?path=<encoded> (stage-3
// streaming route; the server still enforces its own roots/deny policy per request).
async function signReadRequest(env, { device, method, path, query }) {
  const key = await signerKey(env);
  method = String(method || 'GET').toUpperCase(); path = String(path || ''); query = String(query || '');
  device = String(device || '');
  if (!/^[0-9a-f]{16}$/.test(device) && device !== '-') throw new Error('bad device id'); // '-' is the documented not-yet-enrolled address (preEnroll reads) - the PC verifier accepts exactly that literal
  if (method !== 'GET') throw new Error('read signer signs GET only');
  if (!READ_PATHS.has(path)) throw new Error('read path not allowed');
  const queryCap = path === '/file' ? FILE_QUERY_CAP : READ_QUERY_CAP;
  if (new TextEncoder().encode(query).length > queryCap) throw new Error('query too long'); // TextEncoder, not Buffer: the live Worker is ESM with NO node-compat flag
  const parts = query ? query.split('&') : [];
  if (new Set(parts.map(p => p.split('=')[0])).size !== parts.length) throw new Error('duplicate query param');
  if (path === '/task') {
    const m = /^id=([\w-]{1,80})$/.exec(query); // exactly one id param, strict ledger shape
    if (!m || !signerId(m[1])) throw new Error('/task requires id=<strict id>');
  } else if (path === '/file') {
    if (!/^path=[^&]{1,600}$/.test(query)) throw new Error('/file requires exactly path=<encoded>');
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
  assertTtl(ttlMs);
  if (data == null) data = {};
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('data must be a plain object'); // no silent array/primitive -> {}
  // pre-roundtrip: every object value in data must be a PLAIN object or an array - a Date (or any
  // class instance) would silently serialize to a string and change meaning on the wire. Refuse early.
  (function plain(o, d, seen, count) {
    if (d > DATA_DEPTH_CAP) throw new Error('data too deep'); // depth bounded HERE too - the prewalk must never recurse unbounded before the cap
    if ((count.n += Object.keys(o).length) > 10000) throw new Error('data too wide'); // node-count guard: bounded validation, no deep-stack DoS
    for (const k of Object.keys(o)) { const v = o[k];
      if (typeof v === 'function') throw new Error('function in data');
      if (v && typeof v === 'object') {
        if (seen.has(v)) throw new Error('cyclic data refused'); // a cycle would RangeError the recursion - refuse it as a validation error instead
        seen.add(v);
        const p = Object.getPrototypeOf(v); if (p !== Object.prototype && p !== null && !Array.isArray(v)) throw new Error('non-plain object in data (Date/class instances serialize ambiguously)');
        plain(v, d + 1, seen, count);
      }
    }
  })(data, 0, new Set([data]), { n: 0 });
  let canonData; try { canonData = JSON.parse(JSON.stringify(data)); } catch { throw new Error('unserializable data'); }
  // the SERIALIZED object must STILL be a plain object: a toJSON() returning [] / 7 / null (or a Date,
  // which serializes to a string) used to slip past the pre-roundtrip check and get signed - the PC
  // normalizes non-object data to {} so the signature then fails the wire. Refuse before reserved/sign.
  if (typeof canonData !== 'object' || canonData === null || Array.isArray(canonData)) throw new Error('data must serialize to a plain object');
  let payloadJson; try { payloadJson = JSON.stringify(canonData); } catch { throw new Error('unserializable data'); }
  if (new TextEncoder().encode(payloadJson).length > DATA_BYTES_CAP) throw new Error('data too large'); // byte cap at the helper, not at the network
  (function depth(o, d) { if (d > DATA_DEPTH_CAP) throw new Error('data too deep'); if (o && typeof o === 'object') for (const k of Object.keys(o)) depth(o[k], d + 1); })(canonData, 0); // nested arrays are fine - only the nesting DEPTH is capped; own keys only
  assertNoReserved(canonData); // reserved check on the SERIALIZED object - a toJSON spoof ({id:'spoof'}) can never smuggle an envelope field past it
  const key = await signerKey(env);
  const ts = Date.now(), exp = ts + (ttlMs == null ? CMD_TTL_MS : ttlMs);
  const payload = payloadJson;
  if (device != null) { // v2: device-first canonical
    device = String(device); if (!/^[0-9a-f]{16}$/.test(device)) throw new Error('bad device id');
    const sig = await signCanon(key, [device, String(id), kind, String(ts), String(exp), payload]);
    return { id: String(id), kind, device, ts, exp, sig, data: canonData };
  }
  const sig = await signCanon(key, [String(id), kind, String(ts), String(exp), payload]); // v1 legacy
  return { id: String(id), kind, ts, exp, sig, data: canonData };
}

if (typeof module !== 'undefined' && module.exports) module.exports = { signReadRequest, buildCommandEnvelope, CMD_TTL_MS, DATA_BYTES_CAP, DATA_DEPTH_CAP };
