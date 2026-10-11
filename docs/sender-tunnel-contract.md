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
3. **Reads are private-authority too, request-bound.** `GET /task` and `GET /info` require
   X-GW-Read-Ts/Nonce/Sig over `METHOD\nPATH\nQUERY\nTS\nNONCE` (worker key), ts within 60s,
   nonce replay-cached. Responses are device-signed over the exact body (X-GW-Device /
   X-GW-Device-Sig); `/task` is closed (503) until a device is enrolled.
4. **202 != executed.** An accepted command is a durable ledger record (state `accepted`),
   not a result. The sender polls `GET /task?id=` until a TERMINAL record (`done`/`failed`,
   `terminal:true`). Terminal records are final and retained 24h; an `accepted` record expires
   with its envelope — a 404 after acceptance means "lost, retry the command".
5. **Replay stability.** A replayed envelope gets a stable 409 at intake AND its terminal
   record stays pollable — one transactional ledger, no crash window between replay guard
   and result store.
6. **Fallback.** A stale/down pointer (no heartbeat within 90s, or `down:true`) means the
   sender returns to SSE. Cutover happens only after E2E tests pass on the live tunnel with
   the ledger proving no lost commands.
