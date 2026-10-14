# Pointer rendezvous design (phase 3.1) - how the sender learns the current tunnel URL

The state file (tunnel-state.json) is the PC-side source of truth, but the sender runs off
the PC, so the pointer needs a delivery channel. Ground rules (unchanged): the pointer is
PUBLIC and untrusted - delivery only needs transport, never secrecy; the /health nonce proof
against the enrolled device key authenticates the endpoint (docs/sender-tunnel-contract.md);
every candidate passes pointer-source gating (down/device/exact-host/staleness fail closed);
a wrong or spoofed pointer therefore costs one failed health proof, never a leak.

Verified channel facts (2026-10-13, this branch):
- The worker discovery record (POST/GET /glasswidgets/agent/tunnel) exists and is reviewed -
  the APP publishes to it today (src/lib/agent.js publishTunnel, device-signed + heartbeat).
- No app->user notification relay (Green API or otherwise) exists in this branch. Do not
  design around one.
- The user's Instinct can read: the user's Gmail (with wake subscriptions - instant fire),
  the Instinct DM channels, i2i peers. It CANNOT read the user's personal WhatsApp inbound
  from third-party senders, and cannot hold long-lived sockets.

## Options

A. Worker discovery record (ZERO new PC code for the app; one small publish client for the
   standalone server). Signed, reviewed, already heartbeating. But it IS the dependency the
   independence direction designs out - acceptable only as ONE hook among several, never
   the required path.

B. EMAIL rendezvous (recommended independent primary). The server mails each pointer change
   to the user's Gmail (SMTP submission, app-password vaulted on the PC with the same
   owner-only ACL treatment as device.json). The user's Instinct gets a gmail wake
   subscription on the pointer subject/sender - new pointer = instant wake, zero polling.
   Message body = the tunnel-state JSON. Ordering: highest `since` wins; staleness via the
   90s window + heartbeat. Failure mode is benign: a lost mail leaves the last-known pointer
   (health proof still gates); a dead PC's pointer goes stale within 90s of the last
   heartbeat. New component: server/lib/pointer-mailer.js - zero-dependency SMTP client
   (submission 587 STARTTLS, AUTH LOGIN, one small text mail per pointer event, bounded
   retries into the audit log). Testable with a fake SMTP server in-process, same style as
   the existing suites. Secrets: one Gmail app-password (16-char, revocable) - the only new
   secret in the whole design.

C. ntfy.sh public topic (interim/rehearsal-grade). PC POSTs the JSON to one unguessable
   topic; the Instinct polls on demand (web_fetch) before issuing commands, no subscription
   needed. Public-writable topic means anyone can post - safe here BECAUSE the pointer is
   untrusted by contract (spoofs fail device binding + health proof; worst case is noise).
   Free hosted ntfy has rate limits; self-hostable later. Good fallback, not the end state.

D. i2i native client on the server (proper end state: the PC becomes an Instinct peer).
   Large new component. PARKED.

E. Manual relay (the user pastes the state file) - the rehearsal pattern. Always the floor.

## Recommendation

- SHIPPED (2026-10-14, source): pointer-mailer.js + GW_MAILER=1 wiring + guided config
  fixture + autostart draft + go-live runbook (docs/mailer-go-live.md). Pending live: the
  user's app-password, config on the PC, and the Instinct-side gmail wake subscription.
- Ship B as the independent primary (only new component: pointer-mailer.js + one vaulted
  secret), keep A as a convenience hook while the worker lives, document C as the
  zero-config fallback. Sender side (Instinct): gmail wake subscription on the pointer
  mails -> on wake (or before any command, on demand) read the LATEST pointer mail ->
  resolvePointer -> construct a sender-client for that deviceUrl (origins are immutable per
  client; a new pointer = a new client, resetIdentity semantics) -> health proof -> command.
- Message contract: Subject "GW-POINTER <deviceId>", body = the tunnel-state JSON verbatim.
  One mail per state change (URL up/down) - heartbeats stay file-local, never one mail per
  beat. Freshness semantics DIFFER from the worker rendezvous deliberately: a heartbeat
  record proves liveness by recency, but a mailed pointer proves liveness by CONTACT - the
  sender uses the latest non-down pointer regardless of age and lets the /health nonce proof
  gate (a dead tunnel fails it; cost: one failed request). A down:true mail is the
  authoritative clear. If health fails, the sender re-reads mail for a newer pointer; none +
  failing health = treat as down. pointer-source's stale window stays as-is for the
  heartbeat/state-file rendezvous; the mail path passes ttlMs that disables age-rejection.
