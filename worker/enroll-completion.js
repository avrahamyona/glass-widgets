// Worker-side ENROLL COMPLETION adapter (challenge plan, PC 0.4.64+ / 513b474 pairing gate).
//
// AUTHORITY MODEL (ops review gate): a PC terminal receipt proves KEY POSSESSION for an
// episode, NEVER user approval - the terminal's pairing fields are self-asserted and a holder
// of its own minted key plus a known challenge can fabricate them. Registration therefore
// requires TWO independent evidence chains, and this module keeps them separate:
//   A. ISSUED EPISODE (worker-authored, at SEND time): the challenge/cmdTs this module later
//      verifies against come ONLY from the worker's own enroll_episodes row - never from the
//      caller's completion request. A fabricated terminal must match a challenge the worker
//      actually issued (one-time, UNIQUE).
//   B. OWNER APPROVAL (out-of-band, original channel): the user's OWN approval message on the
//      original conversation channel (WhatsApp), recovered independently by the caller (main/
//      ops from the observation record) and passed as a structured record. This module only
//      BINDS it: exact cmdId, exact recomputed pubkey fingerprint, channel allowlist, strict
//      shapes. The pure verifiers never fabricate authority - no approval record, no INSERT.
// Only after BOTH chains verify does confirmRegistration run the devices INSERT (atomic
// capped, a la tunnel-route.js), with conditional status transitions for exactly-once.
//
// ONE-TIME schema (run once in the D1 console - NEVER per request):
//   CREATE TABLE enroll_episodes (cmd_id TEXT PRIMARY KEY, challenge TEXT NOT NULL UNIQUE,
//     issued_at INTEGER NOT NULL, user_instruction_ref TEXT NOT NULL,
//     status TEXT NOT NULL DEFAULT 'issued',
//     term_device_id TEXT, term_pubkey TEXT, term_approved_at INTEGER,
//     approval_channel TEXT, approval_ref TEXT, approval_fingerprint TEXT, approved_at INTEGER,
//     confirmed_at INTEGER);
// status: issued -> approved (terminal verified + owner approval bound) -> confirmed (in registry).
//
// CALLER COMPOSITION (who calls what - the deploy wiring ops asked for):
//   1. send route: after minting the signed enroll_device envelope, recordIssuedEpisode(
//        cmdId=envelope.id, challenge, issuedAt=envelope.ts, userInstructionRef) - same request.
//   2. terminal poll: the sender/orchestrator delivers the PC's done terminal; caller runs
//      verifyEnrollTerminal against the EPISODE ROW (challenge/issued_at read from D1, not the
//      request) - preparation only.
//   3. owner approval: main/ops recovers the user's approval message from the ORIGINAL channel
//      (WhatsApp wamid) - the message that approves the exact fingerprint shown for THIS cmdId;
//      caller passes {channel:'whatsapp', ref:<wamid>, fingerprint, cmdId, approvedAt}.
//   4. recordApproval(cmdId, terminalResult, approval): verifies BOTH chains and flips
//      status issued->approved in ONE conditional UPDATE (replay-safe).
//   5. confirmRegistration(cmdId, maxDevices): status must be 'approved'; atomic capped
//      INSERT; conditional flip to 'confirmed'. Failures keep the row for reconciliation.
// Step 1 in the live route is one D1 batch (cmd row + episode row) BEFORE notify; see the patch
// referenced at issueEpisodeThen below. issueEpisodeThen is the ordering-only helper.
//
// DUAL-MODE: plain functions, no Buffer/node requires (live Worker is ESM, no node-compat).
const CHALLENGE_RE = /^[A-Za-z0-9_-]{8,64}$/;
const CMD_ID_RE = /^[\w-]{1,80}$/; // strict ledger id shape (same as the PC's journal ids)
const APPROVAL_WINDOW_MS = 180000; // PC pairing-card TTL (120s) + 60s execution/clock slack
const SKEW_MS = 30000;
const OWNER_APPROVAL_CHANNELS = new Set(['whatsapp']); // closed allowlist (Set.has - no prototype tricks)
// Grounded per-channel original-message reference formats (NOT fixture-invented): real WhatsApp
// wamids are 'wamid.' + a base64url-ish token that commonly ends with '=' padding.
const APPROVAL_REF_RES = { whatsapp: /^wamid\.[A-Za-z0-9_-]{10,160}={0,2}$/ };
const subtle = () => (globalThis.crypto && globalThis.crypto.subtle) || require('crypto').webcrypto.subtle;
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const b64Bytes = s => Uint8Array.from(atob(String(s)), c => c.charCodeAt(0));
const enc = s => new TextEncoder().encode(String(s));
async function sha256hex(s) { return hex(await subtle().digest('SHA-256', enc(s))); }
const deviceIdFromPub = async pubB64 => (await sha256hex(pubB64)).slice(0, 16);
const fingerprintOf = async pubB64 => { const h = await sha256hex(pubB64); return h.slice(0, 4) + '-' + h.slice(4, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16); };
const pairingCardId = async cmdId => 'local-approve-' + (await sha256hex(cmdId)).slice(0, 32);

// CHAIN A (preparation only): verifies the PC terminal against the ISSUED episode. Pure - the
// result is derived facts, not authority. STRICT types BEFORE any crypto: nothing coerced.
async function verifyEnrollTerminal({ cmdId, cmdTs, challenge, result, now }) {
  const no = reason => ({ ok: false, reason });
  try {
    if (typeof cmdId !== 'string' || !CMD_ID_RE.test(cmdId)) return no('bad_cmd_id');
    if (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge)) return no('bad_challenge');
    if (!Number.isFinite(cmdTs) || !Number.isFinite(now)) return no('bad_episode_clock');
    const r = result && typeof result === 'object' && !Array.isArray(result) ? result : null;
    if (!r) return no('bad_result');
    if (Object.keys(r).sort().join(',') !== 'challengeSig,deviceId,pairing,pubkey') return no('result_shape'); // EXACT key set
    if (typeof r.deviceId !== 'string' || !/^[0-9a-f]{16}$/.test(r.deviceId)) return no('bad_device_id');
    if (typeof r.pubkey !== 'string' || r.pubkey.length < 40 || r.pubkey.length > 80) return no('bad_pubkey_shape');
    if (typeof r.challengeSig !== 'string' || !/^[0-9a-f]{128}$/.test(r.challengeSig)) return no('bad_sig_shape');
    let key;
    try { key = await subtle().importKey('spki', b64Bytes(r.pubkey), { name: 'Ed25519' }, false, ['verify']); }
    catch { return no('bad_pubkey'); } // real Ed25519 SPKI only
    if (await deviceIdFromPub(r.pubkey) !== r.deviceId) return no('device_id_not_derived');
    const canon = [challenge, r.pubkey, r.deviceId].join('\n'); // src/lib/enroll-challenge.js challengeCanonical
    const sigOk = await subtle().verify('Ed25519', key, Uint8Array.from(r.challengeSig.match(/../g).map(h => parseInt(h, 16))), enc(canon)).catch(() => false);
    if (!sigOk) return no('bad_challenge_sig');
    const p = r.pairing && typeof r.pairing === 'object' && !Array.isArray(r.pairing) ? r.pairing : null;
    if (!p || Object.keys(p).sort().join(',') !== 'approvedAt,cardId,fingerprint') return no('missing_pairing_evidence');
    if (typeof p.cardId !== 'string' || p.cardId !== await pairingCardId(cmdId)) return no('card_id_mismatch');
    if (typeof p.fingerprint !== 'string' || p.fingerprint !== await fingerprintOf(r.pubkey)) return no('fingerprint_mismatch');
    if (typeof p.approvedAt !== 'number' || !Number.isInteger(p.approvedAt) || p.approvedAt <= 0) return no('bad_approved_at'); // STRICT - no string coercion
    if (p.approvedAt <= cmdTs) return no('approval_precedes_command');
    if (p.approvedAt > cmdTs + APPROVAL_WINDOW_MS) return no('approval_window_exceeded');
    if (p.approvedAt > now + SKEW_MS) return no('approval_in_future');
    return { ok: true, device: { deviceId: r.deviceId, pubkey: r.pubkey, fingerprint: p.fingerprint, approvedAt: p.approvedAt, cardId: p.cardId } };
  } catch { return no('verify_error'); } // any malformed proof fails CLOSED
}

// Chain A write: the worker records the episode it ISSUED (send time). Exactly-once per
// cmd_id; one-time challenge via UNIQUE; conflicting replay refused loudly.
async function recordIssuedEpisode(DB, { cmdId, challenge, issuedAt, userInstructionRef }) {
  if (!DB) return { ok: false, reason: 'no_db' };
  if (typeof cmdId !== 'string' || !CMD_ID_RE.test(cmdId)) return { ok: false, reason: 'bad_cmd_id' };
  if (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge)) return { ok: false, reason: 'bad_challenge' };
  if (typeof issuedAt !== 'number' || !Number.isInteger(issuedAt) || issuedAt <= 0) return { ok: false, reason: 'bad_issued_at' };
  if (typeof userInstructionRef !== 'string' || !userInstructionRef.trim() || userInstructionRef.length > 250) return { ok: false, reason: 'explicit_instruction_required' };
  try {
    await DB.prepare("INSERT INTO enroll_episodes (cmd_id,challenge,issued_at,user_instruction_ref,status) VALUES (?,?,?,?,'issued')")
      .bind(cmdId, challenge, issuedAt, userInstructionRef).run();
    return { ok: true };
  } catch {
    const won = await DB.prepare('SELECT challenge,issued_at,user_instruction_ref FROM enroll_episodes WHERE cmd_id=?').bind(cmdId).first();
    if (won && won.challenge === challenge && +won.issued_at === issuedAt && won.user_instruction_ref === userInstructionRef) return { ok: true, already: true };
    return { ok: false, reason: 'episode_conflict' };
  }
}

// CHAIN B (binding only): the owner approval record the caller INDEPENDENTLY recovered from
// the original channel. This module never fetches it and never treats its mere presence as
// proof - it binds exact identifiers. Returns the bound evidence or a refusal.
async function verifyOwnerApproval({ cmdId, fingerprint, approval, issuedAt, now }) {
  const no = reason => ({ ok: false, reason });
  if (typeof cmdId !== 'string' || !CMD_ID_RE.test(cmdId)) return no('bad_cmd_id');
  if (typeof fingerprint !== 'string' || !/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/.test(fingerprint)) return no('bad_fingerprint');
  const a = approval && typeof approval === 'object' && !Array.isArray(approval) ? approval : null;
  if (!a) return no('missing_owner_approval'); // NO approval record - NO authority
  if (Object.keys(a).sort().join(',') !== 'approvedAt,channel,cmdId,fingerprint,ref') return no('approval_shape');
  if (typeof a.channel !== 'string' || !OWNER_APPROVAL_CHANNELS.has(a.channel)) return no('approval_channel_not_allowed');
  if (typeof a.ref !== 'string' || !APPROVAL_REF_RES[a.channel].test(a.ref)) return no('bad_approval_ref'); // the ORIGINAL message id, per-channel grounded format
  if (a.cmdId !== cmdId) return no('approval_cmd_mismatch'); // the approval names THIS episode
  if (a.fingerprint !== fingerprint) return no('approval_fingerprint_mismatch'); // the owner approved THIS exact key fingerprint
  if (typeof a.approvedAt !== 'number' || !Number.isInteger(a.approvedAt) || a.approvedAt <= 0) return no('bad_approval_time');
  if (Number.isFinite(issuedAt) && a.approvedAt <= issuedAt) return no('approval_precedes_episode'); // the owner cannot approve an episode before it was ISSUED (and its fingerprint shown)
  if (Number.isFinite(now) && a.approvedAt > now + SKEW_MS) return no('approval_in_future');
  return { ok: true, evidence: { channel: a.channel, ref: a.ref, approvedAt: a.approvedAt } };
}

// Joins BOTH chains in ONE conditional transition: episode must be 'issued', the terminal must
// verify against the EPISODE ROW's own challenge/issued_at, and the owner approval must bind to
// the terminal's recomputed fingerprint + this cmdId. Anything less: no status change, no INSERT.
async function recordApproval(DB, cmdId, terminalResult, approval, now) {
  if (!DB) return { ok: false, reason: 'no_db' };
  now = now == null ? Date.now() : +now;
  const ep = await DB.prepare('SELECT challenge,issued_at,status FROM enroll_episodes WHERE cmd_id=?').bind(String(cmdId || '')).first();
  if (!ep) return { ok: false, reason: 'no_issued_episode' }; // the challenge MUST come from a worker-issued record
  if (ep.status !== 'issued') {
    if (ep.status === 'approved' || ep.status === 'confirmed') { // idempotent replay ONLY on FULL exact evidence
      const cur = await DB.prepare('SELECT term_device_id,term_pubkey,term_approved_at,approval_channel,approval_ref,approval_fingerprint,approved_at FROM enroll_episodes WHERE cmd_id=?').bind(String(cmdId)).first();
      const t = await verifyEnrollTerminal({ cmdId: String(cmdId), cmdTs: +ep.issued_at, challenge: ep.challenge, result: terminalResult, now });
      if (!t.ok) return { ok: false, reason: 'terminal_' + t.reason }; // a replay must still pass the pure verifier
      const o = await verifyOwnerApproval({ cmdId: String(cmdId), fingerprint: t.device.fingerprint, approval, issuedAt: +ep.issued_at, now });
      if (!o.ok) return { ok: false, reason: 'owner_' + o.reason }; // AND the owner-binding verifier - no skipping on replay
      const same = !!(cur
        && cur.term_device_id === t.device.deviceId && cur.term_pubkey === t.device.pubkey && +cur.term_approved_at === t.device.approvedAt
        && cur.approval_channel === o.evidence.channel && cur.approval_ref === o.evidence.ref
        && cur.approval_fingerprint === t.device.fingerprint && +cur.approved_at === o.evidence.approvedAt); // EVERY stored field exact
      if (same) return { ok: true, already: true, device: t.device };
    }
    return { ok: false, reason: 'episode_not_issued' };
  }
  const t = await verifyEnrollTerminal({ cmdId: String(cmdId), cmdTs: +ep.issued_at, challenge: ep.challenge, result: terminalResult, now });
  if (!t.ok) return { ok: false, reason: 'terminal_' + t.reason };
  const o = await verifyOwnerApproval({ cmdId: String(cmdId), fingerprint: t.device.fingerprint, approval, issuedAt: +ep.issued_at, now });
  if (!o.ok) return { ok: false, reason: 'owner_' + o.reason };
  const r = await DB.prepare("UPDATE enroll_episodes SET status='approved',term_device_id=?,term_pubkey=?,term_approved_at=?,approval_channel=?,approval_ref=?,approval_fingerprint=?,approved_at=? WHERE cmd_id=? AND status='issued'")
    .bind(t.device.deviceId, t.device.pubkey, t.device.approvedAt, o.evidence.channel, o.evidence.ref, t.device.fingerprint, o.evidence.approvedAt, String(cmdId)).run();
  if (r.meta.changes === 0) return { ok: false, reason: 'episode_race' }; // a concurrent transition won - reconcile, never double-approve
  return { ok: true, device: t.device };
}

// Final step: status 'approved' required; atomic capped INSERT a la tunnel-route.js; the flip
// to 'confirmed' is conditional. Replay with the same evidence is idempotent; conflicts keep
// the row for reconciliation.
async function confirmRegistration(DB, cmdId, maxDevices) {
  if (!DB) return { ok: false, reason: 'no_db' };
  const max = +maxDevices || 2;
  const p = await DB.prepare('SELECT status,term_device_id,term_pubkey FROM enroll_episodes WHERE cmd_id=?').bind(String(cmdId || '')).first();
  if (!p) return { ok: false, reason: 'no_episode' };
  if (p.status === 'confirmed') {
    const ex = await DB.prepare('SELECT pubkey FROM devices WHERE device_id=?').bind(String(p.term_device_id)).first();
    if (ex && ex.pubkey === p.term_pubkey) return { ok: true, already: true, deviceId: p.term_device_id };
    return { ok: false, reason: 'confirmed_but_registry_mismatch' }; // reconcile - never silently re-insert
  }
  if (p.status !== 'approved') return { ok: false, reason: 'owner_approval_required' }; // the gate: NO approved row, NO INSERT
  const existing = await DB.prepare('SELECT pubkey FROM devices WHERE device_id=?').bind(p.term_device_id).first();
  if (existing) {
    if (existing.pubkey !== p.term_pubkey) return { ok: false, reason: 'id_conflict' };
    await DB.prepare("UPDATE enroll_episodes SET status='confirmed',confirmed_at=? WHERE cmd_id=? AND status='approved'").bind(Date.now(), String(cmdId)).run();
    return { ok: true, already: true, deviceId: p.term_device_id };
  }
  let r;
  try {
    r = await DB.prepare('INSERT INTO devices (device_id,pubkey,enrolled_at) SELECT ?,?,? WHERE (SELECT COUNT(*) FROM devices) < ?').bind(p.term_device_id, p.term_pubkey, Date.now(), max).run();
  } catch {
    const won = await DB.prepare('SELECT pubkey FROM devices WHERE device_id=?').bind(p.term_device_id).first();
    if (won && won.pubkey === p.term_pubkey) { await DB.prepare("UPDATE enroll_episodes SET status='confirmed',confirmed_at=? WHERE cmd_id=? AND status='approved'").bind(Date.now(), String(cmdId)).run(); return { ok: true, already: true, deviceId: p.term_device_id }; }
    return { ok: false, reason: 'id_conflict' };
  }
  if (r.meta.changes === 0) return { ok: false, reason: 'device_limit' }; // approved row survives
  await DB.prepare("UPDATE enroll_episodes SET status='confirmed',confirmed_at=? WHERE cmd_id=? AND status='approved'").bind(Date.now(), String(cmdId)).run();
  return { ok: true, deviceId: p.term_device_id };
}

// SEND/RECORD ORDERING (ops gap 5). HONEST SCOPE: this helper is NOT a transaction. It only
// enforces ORDER for callers that hold a plain D1 handle: deliver() runs strictly AFTER the
// episode row is stored, and an episode failure aborts the send undelivered. The ATOMIC
// cmd+episode write (one D1 batch, same signed `now`, before notify) lives in the live send route
// - see worker-atomic-issuance.patch, simulated against the real worker code. If a send response
// is lost, recovery is the authenticated challenge lookup on /glasswidgets/cmd/status?challenge=
// (returns id + issued_at), never a blind retry. Exactly-once is NOT claimed across crashes:
// the one-time challenge (UNIQUE) and the conditional status transitions make a repeated
// completion/issuance fail closed or return 'already', not execute twice.
async function issueEpisodeThen(DB, episode, deliver) {
  const r = await recordIssuedEpisode(DB, episode);
  if (!r.ok) return { ok: false, reason: 'episode_' + r.reason, delivered: false };
  const result = await deliver(); // hub notify / SSE delivery happens strictly AFTER the durable episode
  return { ok: true, delivered: true, result };
}

if (typeof module !== 'undefined' && module.exports) module.exports = { verifyEnrollTerminal, verifyOwnerApproval, recordIssuedEpisode, recordApproval, confirmRegistration, issueEpisodeThen, CHALLENGE_RE, APPROVAL_WINDOW_MS };
