# Live-worker integration plan (no deploy in this phase)

Status legend: EXISTS = code reviewed statically | MISSING = not written | UNVERIFIED = written, no live proof.
Base: agent through PR #70 (4849b70), worker route v4 (PR #69, df5b311), contract: docs/sender-tunnel-contract.md.

## A. Live worker wiring

### A1. Enrollment wiring (MISSING end-to-end)
- What: agent boot -> if no device keypair, mint -> enroll publish to worker /glasswidgets/agent/enroll (worker verifies sender auth X-GW-Reply-Key, binds device_id=sha256(pubkey)[:16], enforces GW_MAX_DEVICES atomically) -> worker delivers worker-signed enroll_device envelope (signEnrollCommand, SSE) -> agent handler persists device (idempotent, ACL-hardened file).
- Locus: worker/tunnel-route.js (enroll route EXISTS, static-cleared), src/lib/agent.js enroll_device handler (EXISTS), src/lib/tunnel.js publish loop (EXISTS).
- Verify: live round-trip on staging worker: fresh profile enrolls, re-enroll same id+pubkey is idempotent, different pubkey refused, device limit enforced. Evidence: worker logs + agent audit + ledger record.

### A2. Read signer (MISSING)
- What: worker route that authorizes /task (and /info) reads: signs the 6-field read canonical (path, query, device, ts0) with GW_SIGN_PRIVATE so the agent's verifyReadAuth (EXISTS, device-bound) returns 200; wrong sig / stale ts0 -> 403.
- Locus: new worker route (e.g. /glasswidgets/agent/read-sign or proxied read), agent verifyReadAuth in src/lib/agent.js:881 (EXISTS).
- Verify: read proof - signed read 200 with correct body, tampered sig 403, replayed stale ts0 403, v1 read on strict-enrolled device 403 device_required.

### A3. v2 device wiring (MISSING live)
- What: worker stamps every command envelope with the enrolled device field and signs the device-first 6-field canonical; agent STRICT_ENVELOPES gate (EXISTS, opt-in env GLASSWIDGETS_STRICT_ENVELOPES=1) then refuses v1 with device_required.
- Locus: worker envelope construction (to write), agent validEnvelope v1/v2 + strict gate (EXISTS, covered by ui-test 15k).
- Verify: on enrolled+strict device: v1 -> 403, v2 -> 202; on legacy device: v1 still 202 (no regression).

### A4. Capabilities exchange (PARTIAL)
- What: agent already advertises caps on the SSE registration query (approve,update,media,clip,web,sig,ui,shot,island - EXISTS). Worker must persist caps per device and route only advertised kinds; sender UI/agent must not offer commands the device cannot run.
- Locus: worker command intake (to write), agent caps source src/lib/agent.js:853 (EXISTS).
- Verify: worker refuses/queues a kind the device did not advertise; caps refresh on relaunch.

### A5. Sender client (MISSING)
- What: the component that turns a user intent into a signed command envelope: id (ULID), kind from the closed allowlist, data JSON, ts/exp, 5- or 6-field Ed25519 signature with GW_SIGN_PRIVATE, POST to worker with X-GW-Reply-Key, then task polling for terminal status. Idempotent retry: SAME id + same payload; a 409 duplicate means accepted/ran/unknown - never a new id. done/unknown are NOT authorization to re-execute.
- Locus: new component (worker-side route or ops backend); contract sections already written in docs/sender-tunnel-contract.md.
- Verify: unit + live: build/sign/post/poll cycle; duplicate POST returns cached outcome; expired envelope refused without effect.

## B. E2E proofs (all UNVERIFIED)

### B1. Tunnel proof
command -> worker intake 202 -> tunnel publish -> agent intake (durable accepted) -> exec -> terminal ledger record -> ack; duplicate delivery -> cached re-ack, effect never re-runs; expired transport -> refusal record only for NEW intakes (replay resolves as duplicate first).

### B2. Read proof
as A2 verify, against the live worker + real device.

### B3. Task poll
sender polls /task?id=...: accepted -> running -> terminal transitions visible; terminal exactly-once via ack; crash between running and terminal leaves 'unknown' -> manual reconciliation (exactly-once across crashes is NOT claimed).

### B4. Crash / ack retry E2E
kill the agent mid-run -> ledger shows running/unknown on restart -> no blind re-execution; ack retry with backoff -> worker dedups by id (updated:1 idempotent); unfittable ack body -> audited, never transmitted blind.

## C. Cutover (after A+B verified)

- C1. STRICT_ENVELOPES=1 ON at the multidevice cutover (opt-in flag EXISTS; documented single-device until then).
- C2. Multidevice: device registry UI, per-device ledger namespacing, no cross-device replay (v2 device binding is the mechanism).
- C3. SSE stays the command path until B1-B4 pass live; cutover behind a feature flag with .bak / git tag recovery. The 03:00 rollout (worker/indexes) is independent of this plan.

## Gates (unchanged)
1. #69 Windows runtime ACL fixture (user can run it now - tools/acl-windows-fixture.js, commit 41ca75e).
2. This plan's A-items.
3. Strict device active at multidevice cutover.
4. B-proofs live.
No merge/deploy of #69/#70 until 1-4. SSE stays. Strict device stays opt-in, single-device documented.
