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
   captured at one device never authorizes another. Command envelopes: v2 carries a signed
   `device` field bound to the enrolled device (403 wrong_device otherwise); v1 (no device
   field) is a bootstrap/SINGLE-device path only - with strict envelopes enabled
   (GLASSWIDGETS_STRICT_ENVELOPES=1, required before tunnel-first multi-device) an enrolled
   device refuses v1 with 403 device_required. /info advertises envelopeVersions for
   negotiation. Responses - including errors - are
   device-signed over `DEVICE_ID\nMETHOD\nPATH\nQUERY\nREAD_TS\nREAD_NONCE\nSTATUS\nSHA256(BODY)`
   (X-GW-Device / X-GW-Device-Sig), so a signed response can never be replayed onto another
   request, endpoint, nonce or status. `/task` is closed (503) until a device is enrolled.
4. **202 != executed, and exp is NOT the result TTL.** An accepted command is a durable
   ledger record whose lifecycle is `accepted -> running -> done/failed`. The sender polls
   `GET /task?id=` until a TERMINAL record (`terminal:true`). Terminal records are final and
   retained 24h REGARDLESS of the envelope exp (the envelope exp bounds dedup only). A 404 is
   NOT proof of non-execution: result retention expiry, dead-window eviction or ledger-file
   loss can all return 404 for an effect that DID run, and a 202 response can itself be lost
   before the sender sees it. Therefore: any POST whose response was not grounded (202 lost,
   timeout, disconnect) is an UNKNOWN outcome - the sender polls /task until a TERMINAL
   record; a 404 after an ungrounded send is still "unknown", never "safe to retry". Retry
   authorization splits by intake outcome:
   - ABSOLUTE intake rejects, BEFORE any commit - 400 (validation), 403 (unsigned/wrong
     device), 429 (ledger full): the id was NOT consumed; the sender may fix the cause and
     send a NEW id.
   - 409 duplicate: the id WAS already consumed (accepted/ran/unknown). NEVER grounds a
     new-id retry - poll /task for the ORIGINAL id until terminal.
   - A terminal record: `done` means executed (never re-execute); `unknown` means the outcome
     is not known (manual reconciliation, never auto-retried); `failed` may still be a
     PARTIAL effect - it is evidence, not permission to re-run. An unsafe effect is never
     auto-retried without a grounded human/owner decision.
5. **Replay stability and crash honesty.** A replayed envelope gets a stable 409 at intake
   AND its record stays pollable - one transactional ledger, no crash window between replay
   guard and result store. "At most once" holds INSIDE the command's authority window: the
   signed exp (tunnel/pre-approved) or the worker's private transport expiry (SSE
   expires_at); an unsigned SSE command without either gets a bounded 10-minute dedup window
   (a fallback resend keeps the SAME id inside that window). Expired authority refuses
   BEFORE any effect. Records that were `accepted`/`running` when the app last exited
   reload as `unknown` (terminal): evidence that the outcome is not known, never
   auto-retried, still deduping (409) forever within the dedup window. When the live window
   is saturated (200 non-terminal records), intake REFUSES new commands with 429 -
   live tombstones are never evicted, so an unexpired envelope can never re-execute.
6. **Fallback.** A stale/down pointer (no heartbeat within 90s, or `down:true`) means the
   sender returns to SSE. Cutover happens only after E2E tests pass on the live tunnel with
   the ledger proving no lost commands.

### Execution-time authority gate (round 5)
Every execution branch (auto-run timer, approval tap, media session grant) passes one shared
gate in execPending: the effect dies when min(signed exp, transport expiry) has passed, with a
terminal failed record + ack. Preapproval cards of EVERY kind (run_command, web_task, ui_automation, island_control) store
that same min as their private expiry, and the media session grant carries the transport expiry
into the gate as texp.
On SSE, duplicate resolution runs BEFORE expiry evaluation: a replay - expired or not - of a
known id returns the cached terminal result (done/failed), stays silent for accepted/running/
unknown, and never rewrites a live record. Only a NEW expired intake gets the refusal record.
Ack results are shape-safe: null/primitives wrap to {value}, cycles/functions serialize to
{unserializable:true}; the canonical path can never throw before the ledger write.

### Transport swap: state-file pointer (standalone-server / Efi pattern)
The tunnel pointer may arrive from a tunnel-state record ({url,deviceId,since,down} -
server/lib/tunnel-supervisor.js) relayed through any rendezvous, instead of the worker
discovery record. Candidacy gating (server/lib/pointer-source.js): down/empty closes, device
mismatch closes, exact trycloudflare host only, `since` older than the 90s stale window (or
far-future) closes. The supervisor refreshes `since` every 45s while an episode is live, so
a dead PC is distinguishable from a quiet one. NOTHING else changes: the pointer stays public
and untrusted, the /health nonce proof against the enrolled device key still gates every
payload, and all envelope/read/replay rules apply verbatim on either transport.
