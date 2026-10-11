// Worker route v4: quick-tunnel discovery with per-device signed publishes, monotonic ordering
// with TOMBSTONE clears, and an allowlisted enrollment path with a device limit.
//
// ONE-TIME schema (run once in the D1 console / migration - NEVER per request):
//   CREATE TABLE devices (device_id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, enrolled_at INTEGER NOT NULL);
//   CREATE TABLE tunnel_pointer (device_id TEXT PRIMARY KEY, url TEXT NOT NULL, v TEXT, ts INTEGER NOT NULL, at INTEGER NOT NULL);
//
// Sender auth: header X-GW-Reply-Key (never URL query). Missing env/binding -> clean fail-closed (503).
// Publish auth: Ed25519 device signature over deviceId+"\n"+url+"\n"+ts, verified against the
// enrolled pubkey. Ordering: a publish/clear applies ONLY when its signed ts is strictly newer
// than the stored ts (one atomic conditional upsert for BOTH). A clear is a TOMBSTONE (url=''),
// never a DELETE - the stored ts survives, so a replayed old publish can never resurrect a
// cleared pointer. at stores the SIGNED ts (freshness by signed time); GET reports stale when
// Date.now()-at > 90s and down when the pointer is a tombstone.
//
// Enrollment: sender-authenticated, real Ed25519 SPKI only, allowlisted device-id format, and a
// device LIMIT (env.GW_MAX_DEVICES, default 2) - a new device beyond the limit is refused (409);
// re-enrolling an existing device_id updates its pubkey (explicit rotation by the sender).
// signEnrollCommand(env, id) builds the worker-signed enroll_device envelope for the SSE send
// path (needs env.GW_SIGN_PRIV, pkcs8 base64) - the private key never leaves the worker, and the
// PC-side handler is idempotent so delivery retries are safe.

const BODY_CAP = 4096;
const MAX_DEVICES_DEFAULT = 2;

async function readJsonCapped(request) {
  const len = +(request.headers.get('content-length') || 0);
  if (len > BODY_CAP) return null;
  const text = await request.text();
  if (text.length > BODY_CAP) return null;
  try { return JSON.parse(text); } catch { return null; }
}

async function signEnrollCommand(env, id) {
  const ts = Date.now(), exp = ts + 300000, data = {};
  const payload = JSON.stringify(data);
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(env.GW_SIGN_PRIV), c => c.charCodeAt(0)), { name: 'Ed25519' }, false, ['sign']);
  const sigBytes = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode([id, 'enroll_device', String(ts), String(exp), payload].join('\n')));
  const sig = [...new Uint8Array(sigBytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  return { id, kind: 'enroll_device', ts, exp, sig, data };
}

async function handleTunnel(request, env, url) {
  if (!env || !env.AVI_ACCOUNT_DB || !env.GW_REPLY_KEY) return new Response('unavailable', { status: 503 });
  const DB = env.AVI_ACCOUNT_DB;
  const isSender = request.headers.get('X-GW-Reply-Key') === env.GW_REPLY_KEY; // fail-closed: unset env already 503d

  if (url.pathname === '/glasswidgets/agent/enroll') {
    if (!isSender) return new Response('auth', { status: 403 });
    if (request.method !== 'POST') return new Response('method', { status: 405 });
    const b = await readJsonCapped(request);
    const id = String(b && b.device_id || '').slice(0, 64), pk = String(b && b.pubkey || '');
    if (!/^[0-9a-f]{16}$/.test(id)) return new Response('bad_id', { status: 400 });
    try { await crypto.subtle.importKey('spki', Uint8Array.from(atob(pk), c => c.charCodeAt(0)), { name: 'Ed25519' }, false, ['verify']); }
    catch { return new Response('bad_pubkey', { status: 400 }); } // real Ed25519 SPKI only
    const max = +env.GW_MAX_DEVICES || MAX_DEVICES_DEFAULT;
    const existing = await DB.prepare("SELECT pubkey FROM devices WHERE device_id=?").bind(id).first();
    if (!existing) {
      const c = await DB.prepare("SELECT COUNT(*) AS n FROM devices").first();
      if ((c && c.n || 0) >= max) return new Response('device_limit', { status: 409 }); // allowlist cap: no silent fleet growth
    }
    await DB.prepare("INSERT INTO devices (device_id,pubkey,enrolled_at) VALUES (?,?,?) ON CONFLICT(device_id) DO UPDATE SET pubkey=excluded.pubkey").bind(id, pk, Date.now()).run();
    return Response.json({ ok: true });
  }

  if (url.pathname === '/glasswidgets/agent/tunnel') {
    if (request.method === 'GET') {
      if (!isSender) return new Response('auth', { status: 403 });
      const dev = String(url.searchParams.get('device') || '');
      if (!/^[0-9a-f]{16}$/.test(dev)) return new Response('bad_id', { status: 400 }); // per-device selector, never an arbitrary first row
      const row = await DB.prepare("SELECT p.url,p.v,p.ts,p.at,d.pubkey FROM tunnel_pointer p JOIN devices d ON d.device_id=p.device_id WHERE p.device_id=?").bind(dev).first();
      if (!row) return new Response('never_published', { status: 404 });
      if (row.url === '') return Response.json({ deviceId: dev, url: '', down: true, stale: true, ts: row.ts, at: row.at, pubkey: row.pubkey }); // tombstone: explicitly down, never a stale-looking url
      return Response.json({ deviceId: dev, url: row.url, v: row.v, ts: row.ts, at: row.at, pubkey: row.pubkey, stale: Date.now() - row.at > 90000 });
    }
    if (request.method === 'POST') {
      const b = await readJsonCapped(request);
      if (!b) return new Response('bad_json', { status: 400 });
      const id = String(b.deviceId || ''), u = String(b.url || ''), ts = +b.ts, sig = String(b.sig || '');
      if (!/^[0-9a-f]{16}$/.test(id)) return new Response('bad_id', { status: 400 });
      if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 300000) return new Response('stale', { status: 400 }); // freshness by SIGNED ts
      if (!(u === '' || /^https:\/\/[a-z0-9-]{1,63}\.trycloudflare\.com$/.test(u))) return new Response('bad_url', { status: 400 });
      if (!/^[0-9a-f]{128}$/.test(sig)) return new Response('bad_sig', { status: 400 });
      const dev = await DB.prepare("SELECT pubkey FROM devices WHERE device_id=?").bind(id).first();
      if (!dev) return new Response('unenrolled', { status: 403 });
      const key = await crypto.subtle.importKey('spki', Uint8Array.from(atob(dev.pubkey), c => c.charCodeAt(0)), { name: 'Ed25519' }, false, ['verify']);
      const ok = await crypto.subtle.verify('Ed25519', key, Uint8Array.from(sig.match(/../g).map(h => parseInt(h, 16))), new TextEncoder().encode(id + '\n' + u + '\n' + ts)).catch(() => false);
      if (!ok) return new Response('bad_sig', { status: 403 });
      // ONE atomic conditional upsert for BOTH publish and clear (tombstone url=''): applies only
      // when strictly newer. A tombstone KEEPS the row and its ts, so publish100 -> clear200 ->
      // replay100 is rejected (409) instead of resurrecting the cleared pointer.
      const r = await DB.prepare(
        "INSERT INTO tunnel_pointer (device_id,url,v,ts,at) VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET url=excluded.url,v=excluded.v,ts=excluded.ts,at=excluded.at WHERE excluded.ts>tunnel_pointer.ts"
      ).bind(id, u, u === '' ? '' : String(b.v || '').slice(0, 20), ts, ts).run();
      if (r.meta.changes === 0) return new Response('stale_publish', { status: 409 });
      return Response.json({ ok: true });
    }
    return new Response('method', { status: 405 });
  }
  return new Response('not_found', { status: 404 });
}

if (typeof module !== 'undefined' && module.exports) module.exports = { handleTunnel, signEnrollCommand, readJsonCapped };
