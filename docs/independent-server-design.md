# Independent server design (self-hosted, free, no quota-bearing dependency)

Direction (user, 2026-10-13 20:43): base the technology 100% on the methods Efi uses.
Efi's pattern (reconfirmed 2026-10-13 via his Instinct): local Node server on his machine,
exposed via OUTBOUND cloudflared Cloudflare Quick Tunnels with temporary addresses; a
supervisor restarts failed tunnels and updates a state file with the current address
(migrated from ngrok). Earlier direction still holds: local-first (PC is the brain), free
only, no external servers with limits. Trigger: the Cloudflare D1 quota blocked a deploy.

## 1. The honest trade-off

Quick Tunnels still pass through Cloudflare's edge - but as a dumb, free, account-less pipe:
no account, no D1, no quota that applies to this use, no SLA. The hostname rotates on every
restart; the supervisor + state-file pointer absorb that. Latency is slightly higher than a
direct connection. All state and logic stay on the PC (ledger.json, device.json); Cloudflare
is a replaceable relay, never a store. Truly Cloudflare-free options (direct IPv6, router
port-forward, mesh overlay) are documented as PARKED - the 2026-10-13 probe evidence
(DIRECT-IPV6 CANDIDATE, public non-CGNAT IPv4, router blocks inbound v6 by default) stays
valid if the direction ever reopens.

## 2. What already exists (all tested on this branch)

- server/index.js - standalone Electron-free "PC brain": local-file state only (ledger.json,
  device.json, audit log), signed command envelopes, signed device-bound reads, ACL-hardened
  identity mint. No D1 anywhere.
- src/lib/tunnel.js - cloudflared quick-tunnel manager: binary pinned by version AND sha256,
  exact-host URL validation, respawn supervisor with exponential backoff, onUrl/onDown
  lifecycle. Electron-free by design.
- src/lib/localserver.js - the HTTP leg: /health nonce proof, /info, /task, /cmd; every
  request key-gated; reads signed-read authorized; responses device-signed.
- server/lib/tunnel-supervisor.js (this change) - the Efi composition: wraps tunnel.js for
  the standalone server, records every pointer change to tunnel-state.json (atomic
  tmp+rename, down:true on death/stop) and pushes it through pluggable hooks.

## 3. Architecture (Efi 1:1)

PC: server/index.js (binds 127.0.0.1 ONLY - no firewall pinhole, no router change)
  -> cloudflared tunnel --url http://127.0.0.1:<port> (OUTBOUND only)
  -> supervisor: respawn on death with backoff; every new temporary URL -> tunnel-state.json
     {url,deviceId,since,down} + publish hooks.
Sender: reads the pointer, then proves the endpoint BEFORE any payload:
  GET /health?nonce= -> deviceId + Ed25519 signature over deviceId\nnonce, verified against
  the enrolled device pubkey. Only then signed command envelopes / signed reads. A stale or
  wrong pointer fails closed - the pointer itself is public and untrusted.

## 4. The pointer rendezvous (the one remaining design seam)

The state file is the local source of truth. How the sender receives pointer updates without
the worker discovery record:
- Phase A: publish hook -> the user's own channel (the app/server already has audited
  outbound paths; the pointer is a public, non-secret value).
- Phase B (optional): the existing worker discovery record stays as ONE hook among several -
  useful while the worker exists, never required.
The verification flow (health nonce + device key + signed envelopes) is transport-independent
and does not change with the rendezvous.

## 5. Phases

0. DONE (this change): tunnel-supervisor.js composition + GW_TUNNEL opt-in wiring in
   server/index.js (default OFF) + tunnel-supervisor-unit suite (8 cases PASS: state write,
   rotation, down/clear, no-device no-publish, unsupported platform, fail-closed reads,
   hook-failure isolation, real boot with GW_TUNNEL=1). Full server suite green.
1. Source: sender-client accepts a pointer from the phase-4 rendezvous (verification
   unchanged); contract addendum: transport swaps never change authority.
2. Live (APPROVAL-GATED): run server+supervisor on the PC (GW_TUNNEL=1), rotation drill
   (kill cloudflared -> supervisor respawns -> state file updates -> sender re-resolves ->
   signed command e2e). THEN demote the worker to optional.

The enroll-completion seam stays BLOCKED exactly as reviewed (503
trusted_approval_source_unavailable) - this work changes transport, never authority. No live
deploy/install/mutation without explicit approval.
