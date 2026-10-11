# Sender ↔ own-server (tunnel-first) contract — stage A

Ordered rules for the sender switching from the worker SSE leg to the direct tunnel leg.
The SSE fallback stays CONNECTED until E2E + ledger are proven; nothing in stage A disconnects it.

1. **Discovery first, payload second.** The sender resolves the device via the authenticated
   worker pointer (`GET /glasswidgets/agent/tunnel?device=<id>`), then proves the endpoint with
   `GET /health?nonce=<nonce>`: the response carries `deviceId` + an Ed25519 signature over
   `deviceId\n<nonce>` with the enrolled device key. Only after the proof verifies against the
   enrolled pubkey (from the worker's device registry) may any command payload flow.
2. **Commands are private-authority only.** `POST /cmd` accepts ONLY worker-signed envelopes
   {id,kind,ts,exp,sig,data}; the baked X-GW-Key is public and gates nothing by itself.
3. **Reads are private-authority too, request-bound AND device-bound.** `GET /task` and
   `GET /info` require X-GW-Read-Ts/Nonce/Device/Sig over
   `METHOD\nPATH\nQUERY\nTS\nNONCE\nDEVICE_ID` (worker key), ts within 60s, nonce
   replay-cached, DEVICE_ID equal to the enrolled device (`-` while unenrolled). A read
   captured at one device never authorizes another. Responses - including errors - are
   device-signed over `DEVICE_ID\nMETHOD\nPATH\nQUERY\nREAD_TS\nREAD_NONCE\nSTATUS\nSHA256(BODY)`
   (X-GW-Device / X-GW-Device-Sig), so a signed response can never be replayed onto another
   request, endpoint, nonce or status. `/task` is closed (503) until a device is enrolled.
4. **202 != executed, and exp is NOT the result TTL.** An accepted command is a durable
   ledger record whose lifecycle is `accepted -> running -> done/failed`. The sender polls
   `GET /task?id=` until a TERMINAL record (`terminal:true`). Terminal records are final and
   retained 24h REGARDLESS of the envelope exp (the envelope exp bounds dedup only). A 404
   means "this id was NEVER accepted" - the effect cannot have run, so the sender may create
   a NEW id and retry. A 404/timeout/disconnect after a 202 means the outcome is UNKNOWN:
   poll until terminal; the sender NEVER auto-retries the same id.
5. **Replay stability and crash honesty.** A replayed envelope gets a stable 409 at intake
   AND its record stays pollable - one transactional ledger, no crash window between replay
   guard and result store. Records that were `accepted`/`running` when the app last exited
   reload as `unknown` (terminal): evidence that the outcome is not known, never
   auto-retried, still deduping (409) forever within the dedup window. When the live window
   is saturated (200 non-terminal records), intake REFUSES new commands with 429 -
   live tombstones are never evicted, so an unexpired envelope can never re-execute.
6. **Fallback.** A stale/down pointer (no heartbeat within 90s, or `down:true`) means the
   sender returns to SSE. Cutover happens only after E2E tests pass on the live tunnel with
   the ledger proving no lost commands.
