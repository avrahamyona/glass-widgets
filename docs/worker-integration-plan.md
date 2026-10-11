# Live-worker integration plan (no deploy in this phase)

Status legend: EXISTS = code reviewed statically | MISSING = not written | UNVERIFIED = written, no live proof.
Base: agent through PR #70 (4849b70), worker route v4 (PR #69, df5b311), contract: docs/sender-tunnel-contract.md.

## Architecture direction (user-directed, 2026-10-11)

Local-first: the "brain" of the server-side product lives ENTIRELY on the user's PC. The PC is
the brain; any cloud component (worker, tunnel) is a dumb relay only - no quotas, no external
limits, no logic the user depends on. An always-open window/process on the PC is an accepted
cost (explicit user choice). The standalone server (server/index.js) is designed to this: state,
identity, ledger and ops are all local; the plan below must keep cloud pieces replaceable.
Quota rollout / external-service gates are never on the critical path of the PC brain.

## A. Live worker wiring

### A1. Enrollment wiring (MISSING end-to-end)
- What (safe bootstrap order - the PC never receives a sender secret):
  1. Owner backend (holds X-GW-Reply-Key / GW_REPLY_KEY - a private sender credential that must NEVER be provisioned to the PC) authorizes and signs the enroll intent.
  2. PC mints its device keypair locally and persists it ACL-hardened + atomically (EXISTS in src/lib/agent.js; the standalone server skeleton now does the same - tmp exclusive-create + rename + load-time private/public pair check).
  3. The PC answers the enroll CHALLENGE: the owner backend issues a one-time nonce over the verified PC channel, and the PC signs {challenge, pubkey, deviceId} with its fresh device key. A bare self-signed pubkey proves NOTHING (anyone can mint a pair) - only the challenge-bound signature ties the key to the actual PC in this enrollment episode.
  4. Owner backend verifies the signature against the published pubkey, checks the challenge is the exact nonce it issued to this PC session, and only then accepts the device identity.
  5. Worker enroll registry records device_id = sha256(pubkey)[:16] with the atomic device limit (route EXISTS, static-cleared).
  6. Signed tunnel-pointer publish + nonce proof (health nonce flow EXISTS).
  The code as written only mints worker-signed enroll_device envelopes; the /enroll endpoint requires the private reply key, so the order above is the only safe wiring.
- Locus: worker/tunnel-route.js (enroll route EXISTS), src/lib/agent.js enroll_device handler (EXISTS, idempotent), src/lib/tunnel.js publish loop (EXISTS).
- Verify: live round-trip on a staging worker: fresh profile enrolls, re-enroll same id+pubkey is idempotent, different pubkey refused, device limit enforced, and the PC config/data dir provably contains NO sender secret. Evidence: worker logs + agent audit + ledger record.

### A2. Read signer (MISSING)
- What: worker route that authorizes /task (and /info) reads: signs the six-field read canonical exactly as the handler verifies it - [method, path, query, ts, nonce, device] joined by newlines - with GW_SIGN_PRIVATE, so the agent's verifyReadAuth (EXISTS, device-bound) returns 200; wrong sig / stale ts / replayed nonce -> 403 read_auth. (403 device_required is only the STRICT_ENVELOPES v1-command refusal; read failures surface as read_auth.)
- Locus: new worker route (e.g. /glasswidgets/agent/read-sign or proxied read), agent verifyReadAuth in src/lib/agent.js:881 (EXISTS).
- Verify: read proof - signed read 200 with correct body, tampered sig 403 read_auth, replayed stale ts 403 read_auth, replayed nonce 403 read_auth.

### A3. v2 device wiring (MISSING live)
- What: worker stamps every command envelope with the enrolled device field and signs the device-first 6-field canonical; agent STRICT_ENVELOPES gate (EXISTS, opt-in env GLASSWIDGETS_STRICT_ENVELOPES=1) then refuses v1 with device_required.
- Locus: worker envelope construction (to write), agent validEnvelope v1/v2 + strict gate (EXISTS, covered by ui-test 15k).
- Verify: on enrolled+strict device: v1 -> 403, v2 -> 202; on legacy device: v1 still 202 (no regression).

### A4. Capabilities exchange (PARTIAL)
- What: agent already advertises caps on the SSE registration query (approve,update,media,clip,web,sig,ui,shot,island - EXISTS). The advertisement is INFORMATIONAL ONLY: it is sent under the baked, public command key and must never grant authority. Authoritative capability comes from the device-signed registration (enrolled device key) plus the verified code capability of the running build; the worker routes only kinds the device's signed registration advertised, and the sender must not offer commands the device cannot run.
- Locus: worker command intake (to write), agent caps source src/lib/agent.js:853 (EXISTS).
- Verify: worker refuses/queues a kind the device did not advertise in its signed registration; caps refresh on relaunch; a forged advertisement over the public key changes nothing.

### A5. Sender client (MISSING)
- What: the component that turns a user intent into a signed command envelope: id under the EXISTING strict id contract (the current ULID/UUID format and its uniqueness rules - no new id scheme), kind from the closed allowlist, data JSON, ts/exp, 5- or 6-field Ed25519 signature with GW_SIGN_PRIVATE, POST to worker with X-GW-Reply-Key, then task polling for terminal status. Idempotent retry: SAME id + same payload; a 409 duplicate means accepted/ran/unknown - never a new id. done/unknown are NOT authorization to re-execute.
- Locus: new component (worker-side route or ops backend); contract sections already written in docs/sender-tunnel-contract.md.
- Verify: unit + live: build/sign/post/poll cycle; duplicate POST returns cached outcome; expired envelope refused without effect.

## B. E2E proofs (TARGET behaviors - none of these exist as verified features yet)

### B1. Tunnel proof
command -> worker intake 202 -> tunnel publish -> agent intake (durable accepted) -> exec -> terminal ledger record -> ack; duplicate delivery -> cached re-ack, effect never re-runs; expired transport -> refusal record only for NEW intakes (replay resolves as duplicate first).

### B2. Read proof
as A2 verify, against the live worker + real device.

### B3. Task poll
sender polls /task?id=...: accepted -> running -> terminal transitions visible; terminal exactly-once via ack; crash between running and terminal leaves 'unknown' -> manual reconciliation (exactly-once across crashes is NOT claimed).

### B4. Crash / ack retry E2E (TARGET behavior - the retry path is NOT built yet)
kill the agent mid-run -> ledger shows running/unknown on restart -> no blind re-execution.
Ack retry with backoff: MISSING on the agent side. The worker's current updated=1 write is NOT an idempotent receipt (it ACKs WHERE pending, so a replayed ack updates 0 rows and looks like a failure) - a receipt/reconcile contract is needed: the worker records the ack by id idempotently (replay returns the stored outcome), and the agent reconciles non-terminal ledger records against it on restart. Unfittable ack body -> audited, never transmitted blind (EXISTS, ack-unit).

## C. Cutover (after A+B verified)

- C1. STRICT_ENVELOPES=1 ON at the multidevice cutover (opt-in flag EXISTS; documented single-device until then).
- C2. Multidevice: device registry UI, per-device ledger namespacing, no cross-device replay (v2 device binding is the mechanism).
- C3. SSE stays the command path until B1-B4 pass live; cutover behind a feature flag with .bak / git tag recovery. The 03:00 rollout (worker/indexes) is independent of this plan.

## Gates (unchanged)
1. ~~#69 Windows runtime ACL fixture~~ CLOSED 2026-10-11 22:04 IDT: the user ran tools/acl-windows-fixture.js (41ca75e) on the real Windows target - FIXTURE: PASS 4/4, verified pixel-by-pixel by ops. No rerun at 03:00.
2. This plan's A-items.
3. Strict device active at multidevice cutover.
4. B-proofs live.
No merge/deploy of #69/#70 until 1-4. SSE stays. Strict device stays opt-in, single-device documented.
