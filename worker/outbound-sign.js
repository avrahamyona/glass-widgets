// Worker outbound signing toolkit (A2 read signer + A3 v2 device-bound envelopes).
// The ONLY place worker-side read/command signatures are built. Live binding: env.GW_SIGN_PRIVATE
// (pkcs8 base64) - the private key never leaves the worker. Canonical strings are byte-identical
// to the PC-side verifiers (src/lib/agent.js verifyReadAuth / validEnvelope); keep them in sync.
const CMD_TTL_MS = 60000; // command envelope validity: short - replay windows stay small
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/; // the existing strict id contract - no new id scheme

async function signerKey(env) {
  if (!env || !env.GW_SIGN_PRIVATE) throw new Error('GW_SIGN_PRIVATE missing');
  return crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(env.GW_SIGN_PRIVATE), c => c.charCodeAt(0)), { name: 'Ed25519' }, false, ['sign']);
}
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function signCanon(key, fields) {
  return hex(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(fields.join('\n'))));
}

// A2: read signer. Authorizes ONE read on ONE device: the caller (owner backend / sender client)
// attaches the returned headers to its request to the device's tunnel URL. The six canonical
// fields are [method, path, query, ts, nonce, device] - exactly what verifyReadAuth checks.
async function signReadRequest(env, { device, method, path, query }) {
  const key = await signerKey(env);
  method = String(method || 'GET').toUpperCase(); path = String(path || ''); query = String(query || '');
  device = String(device || '');
  if (!/^[0-9a-f]{16}$/.test(device)) throw new Error('bad device id');
  if (!/^\/[A-Za-z0-9/_-]{0,64}$/.test(path)) throw new Error('bad read path');
  const ts = Date.now();
  const nonceBytes = new Uint8Array(12); crypto.getRandomValues(nonceBytes);
  const nonce = [...nonceBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const sig = await signCanon(key, [method, path, query, String(ts), nonce, device]);
  return { ts, nonce, device, sig }; // headers: X-GW-Read-Ts / X-GW-Read-Nonce / X-GW-Read-Device / X-GW-Read-Sig
}

// A3: command envelopes. v2 is device-first six-field (strict-ready); v1 is the legacy five-field
// for the pre-strict window. data is canonicalized ONCE (JSON.stringify of the exact object sent).
async function buildCommandEnvelope(env, { id, kind, device, data, ttlMs }) {
  if (!ID_RE.test(String(id || ''))) throw new Error('bad command id');
  kind = String(kind || ''); if (!kind || kind.length > 40) throw new Error('bad kind');
  const key = await signerKey(env);
  const ts = Date.now(), exp = ts + Math.min(Math.max(+ttlMs || CMD_TTL_MS, 1000), 300000);
  const payload = JSON.stringify(data && typeof data === 'object' && !Array.isArray(data) ? data : {});
  if (device != null) { // v2: device-first canonical
    device = String(device); if (!/^[0-9a-f]{16}$/.test(device)) throw new Error('bad device id');
    const sig = await signCanon(key, [device, String(id), kind, String(ts), String(exp), payload]);
    return { id: String(id), kind, device, ts, exp, sig, data: JSON.parse(payload) };
  }
  const sig = await signCanon(key, [String(id), kind, String(ts), String(exp), payload]); // v1 legacy
  return { id: String(id), kind, ts, exp, sig, data: JSON.parse(payload) };
}

if (typeof module !== 'undefined' && module.exports) module.exports = { signReadRequest, buildCommandEnvelope, CMD_TTL_MS, ID_RE };
