// Worker-side ENROLL COMPLETION verifier (challenge plan, PC 0.4.64+ / 513b474 pairing gate).
// The PC's enroll_device terminal receipt is the ONLY basis for a registry write, and it is
// verified HERE, before any D1 mutation:
//   result = { deviceId, pubkey, challengeSig, pairing: { fingerprint, approvedAt, cardId } }
// Checks (ALL fail closed):
//   1. deviceId DERIVES from pubkey (sha256(pubkey-b64-string)[:16]) - never self-declared.
//   2. challengeSig: Ed25519 over [challenge,pubkey,deviceId].join("\n") - the episode-bound
//      proof from src/lib/enroll-challenge.js (subtle port, ONE canonical).
//   3. cardId === 'local-approve-'+sha256(cmdId)hex[:32] - the deterministic episode card id
//      (src/lib/agent.js pairingCardId); ties the approval evidence to THIS command.
//   4. fingerprint recomputed from pubkey (src/lib/fingerprint.js canonical xxxx-4x).
//   5. approvedAt: integer, (cmdTs, cmdTs+APPROVAL_WINDOW_MS], never in the future (SKEW_MS).
//      The human tap cannot precede the command and cannot postdate the card's own TTL.
// A receipt WITHOUT pairing evidence (a bare already-enrolled terminal) is NOT registrable
// through this path - same refusal as the orchestrator's 'without on-PC pairing evidence'.
//
// ONE-TIME schema (run once in the D1 console - NEVER per request):
//   CREATE TABLE pending_registrations (cmd_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
//     pubkey TEXT NOT NULL, challenge TEXT NOT NULL UNIQUE, approved_at INTEGER NOT NULL,
//     card_id TEXT NOT NULL, created_at INTEGER NOT NULL, confirmed_at INTEGER);
// challenge is UNIQUE: a one-time episode nonce can never back two registrations.
//
// DUAL-MODE: plain functions, no Buffer/node requires (the live Worker is ESM without the
// node-compat flag). crypto comes from globalThis (Worker) or node:crypto.webcrypto (tests).
const CHALLENGE_RE = /^[A-Za-z0-9_-]{8,64}$/; // same shape as src/lib/enroll-challenge.js
const APPROVAL_WINDOW_MS = 180000; // PC card TTL (120s) + 60s execution/clock slack
const SKEW_MS = 30000;
const subtle = () => (globalThis.crypto && globalThis.crypto.subtle) || require('crypto').webcrypto.subtle;
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const b64Bytes = s => Uint8Array.from(atob(String(s)), c => c.charCodeAt(0));
const enc = s => new TextEncoder().encode(String(s));
async function sha256hex(s) { return hex(await subtle().digest('SHA-256', enc(s))); }
const deviceIdFromPub = async pubB64 => (await sha256hex(pubB64)).slice(0, 16);
const fingerprintOf = async pubB64 => { const h = await sha256hex(pubB64); return h.slice(0, 4) + '-' + h.slice(4, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16); };
const pairingCardId = async cmdId => 'local-approve-' + (await sha256hex(cmdId)).slice(0, 32);

async function verifyEnrollTerminal({ cmdId, cmdTs, challenge, result, now }) {
  const no = reason => ({ ok: false, reason });
  try {
    now = now == null ? Date.now() : +now;
    cmdId = String(cmdId || ''); cmdTs = +cmdTs; challenge = String(challenge || '');
    if (!CHALLENGE_RE.test(challenge)) return no('bad_challenge');
    if (!Number.isFinite(cmdTs) || !Number.isFinite(now)) return no('bad_episode_clock');
    const r = result && typeof result === 'object' && !Array.isArray(result) ? result : null;
    if (!r) return no('bad_result');
    if (Object.keys(r).sort().join(',') !== 'challengeSig,deviceId,pairing,pubkey') return no('result_shape'); // EXACT key set - no smuggled fields
    const deviceId = String(r.deviceId || ''), pubkey = String(r.pubkey || ''), sig = String(r.challengeSig || '');
    if (!/^[0-9a-f]{16}$/.test(deviceId)) return no('bad_device_id');
    if (!/^[0-9a-f]{128}$/.test(sig)) return no('bad_sig_shape');
    let key;
    try { key = await subtle().importKey('spki', b64Bytes(pubkey), { name: 'Ed25519' }, false, ['verify']); }
    catch { return no('bad_pubkey'); } // real Ed25519 SPKI only
    if (await deviceIdFromPub(pubkey) !== deviceId) return no('device_id_not_derived');
    const canon = [challenge, pubkey, deviceId].join('\n'); // src/lib/enroll-challenge.js challengeCanonical
    const sigOk = await subtle().verify('Ed25519', key, Uint8Array.from(sig.match(/../g).map(h => parseInt(h, 16))), enc(canon)).catch(() => false);
    if (!sigOk) return no('bad_challenge_sig');
    const p = r.pairing && typeof r.pairing === 'object' && !Array.isArray(r.pairing) ? r.pairing : null;
    if (!p || Object.keys(p).sort().join(',') !== 'approvedAt,cardId,fingerprint') return no('missing_pairing_evidence');
    if (String(p.cardId || '') !== await pairingCardId(cmdId)) return no('card_id_mismatch');
    if (String(p.fingerprint || '') !== await fingerprintOf(pubkey)) return no('fingerprint_mismatch');
    const at = +p.approvedAt;
    if (!Number.isInteger(at) || at <= 0) return no('bad_approved_at');
    if (at <= cmdTs) return no('approval_precedes_command');
    if (at > cmdTs + APPROVAL_WINDOW_MS) return no('approval_window_exceeded');
    if (at > now + SKEW_MS) return no('approval_in_future');
    return { ok: true, device: { deviceId, pubkey, fingerprint: String(p.fingerprint), approvedAt: at, cardId: String(p.cardId) } };
  } catch { return no('verify_error'); } // any malformed proof fails CLOSED
}

// Records the VERIFIED episode as a pending registration. Exactly-once per cmd_id: an
// identical replay is idempotent, a conflicting one is refused. challenge UNIQUE enforces
// one-time episode nonces at the database layer (schema above).
async function recordPendingRegistration(DB, { cmdId, challenge, device }) {
  if (!DB) return { ok: false, reason: 'no_db' };
  cmdId = String(cmdId || ''); challenge = String(challenge || '');
  const d = device || {};
  try {
    await DB.prepare('INSERT INTO pending_registrations (cmd_id,device_id,pubkey,challenge,approved_at,card_id,created_at) VALUES (?,?,?,?,?,?,?)')
      .bind(cmdId, d.deviceId, d.pubkey, challenge, d.approvedAt, d.cardId, Date.now()).run();
    return { ok: true };
  } catch {
    const won = await DB.prepare('SELECT device_id,pubkey,challenge,approved_at,card_id FROM pending_registrations WHERE cmd_id=?').bind(cmdId).first();
    if (won && won.device_id === d.deviceId && won.pubkey === d.pubkey && won.challenge === challenge && +won.approved_at === +d.approvedAt && won.card_id === d.cardId) return { ok: true, already: true };
    return { ok: false, reason: 'episode_conflict' }; // same id, different episode: refuse loudly
  }
}

// Confirms a pending registration into the devices registry: the SAME atomic capped INSERT as
// tunnel-route.js's enroll route (the limit holds inside the INSERT itself). Idempotent:
// re-confirming the same device+pubkey is ok; a conflicting row refuses and the pending
// record SURVIVES for reconciliation.
async function confirmRegistration(DB, cmdId, maxDevices) {
  if (!DB) return { ok: false, reason: 'no_db' };
  const max = +maxDevices || 2;
  const p = await DB.prepare('SELECT device_id,pubkey,confirmed_at FROM pending_registrations WHERE cmd_id=?').bind(String(cmdId || '')).first();
  if (!p) return { ok: false, reason: 'no_pending' };
  const existing = await DB.prepare('SELECT pubkey FROM devices WHERE device_id=?').bind(p.device_id).first();
  if (existing) {
    if (existing.pubkey !== p.pubkey) return { ok: false, reason: 'id_conflict' };
    if (p.confirmed_at == null) await DB.prepare('UPDATE pending_registrations SET confirmed_at=? WHERE cmd_id=?').bind(Date.now(), String(cmdId)).run();
    return { ok: true, already: true, deviceId: p.device_id };
  }
  let r;
  try {
    r = await DB.prepare('INSERT INTO devices (device_id,pubkey,enrolled_at) SELECT ?,?,? WHERE (SELECT COUNT(*) FROM devices) < ?').bind(p.device_id, p.pubkey, Date.now(), max).run();
  } catch {
    const won = await DB.prepare('SELECT pubkey FROM devices WHERE device_id=?').bind(p.device_id).first();
    if (won && won.pubkey === p.pubkey) { await DB.prepare('UPDATE pending_registrations SET confirmed_at=? WHERE cmd_id=?').bind(Date.now(), String(cmdId)).run(); return { ok: true, already: true, deviceId: p.device_id }; }
    return { ok: false, reason: 'id_conflict' };
  }
  if (r.meta.changes === 0) return { ok: false, reason: 'device_limit' }; // pending record survives
  await DB.prepare('UPDATE pending_registrations SET confirmed_at=? WHERE cmd_id=?').bind(Date.now(), String(cmdId)).run();
  return { ok: true, deviceId: p.device_id };
}

if (typeof module !== 'undefined' && module.exports) module.exports = { verifyEnrollTerminal, recordPendingRegistration, confirmRegistration, CHALLENGE_RE, APPROVAL_WINDOW_MS };
