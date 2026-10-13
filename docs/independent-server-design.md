# Independent server design (self-hosted, free, no quota-bearing dependency)

Direction (user, 2026-10-13): the server-side product must not depend on external servers
with limits. Trigger: the Cloudflare D1 quota blocked a deploy. Constraint: free only -
no paid tier is ever proposed. Local-first stays the rule (docs/worker-integration-plan.md,
2026-10-11): the PC is the brain; anything else is a replaceable dumb relay.

## 1. What the standalone server already is (EXISTS, tested)

server/index.js + src/lib/localserver.js: an Electron-free Node process ON the user's PC.
State, identity, ledger, ops - all local files (ledger.json, device.json, audit log). No D1,
no database server, no npm service dependencies. Boot, identity minting, signed command
intake, durable ledger, signed reads are covered by server-skeleton / agent-server /
agent-ledger / sender-client / sender-outbox suites (all PASS on this branch).

## 2. The Cloudflare dependency points today

| Point | Role today | Independence path |
|---|---|---|
| Cloudflare Worker | command queue/relay routes, chat/cards store | standalone server owns all state; worker becomes optional relay or is retired |
| D1 | quota-bearing store | file ledger on the PC (EXISTS) - no quota |
| cloudflared tunnel | inbound reachability to the PC | section 3 - the only real gap |
| Green API | WhatsApp relay for app notifications | separate concern; not on the command critical path |

## 3. Reachability without Cloudflare (the real gap)

cloudflared is the current inbound path. Replacements, all free; which ones are REAL depends
on the user's home network - facts come from docs/fixtures/win-netprobe.txt (read-only probe):

1. **Direct IPv6** - if the ISP delegates native IPv6 (probe: global address with
   RouterAdvertisement origin + v6 gateway), the server binds a global v6 address
   (GW_SERVER_HOST, bind is already supported and audited) with a Windows firewall pinhole
   (a separate explicit owner step). No relay, no quota, no third party. Needs a live
   inbound test before it counts.
2. **Router port-forward (IPv4)** - viable only if the external IPv4 is NOT carrier-grade
   NAT. Probe discovers the router's IGD (UPnP, read-only); a mapping is a separate explicit
   owner step. If the external IPv4 sits in 100.64.0.0/10 (CGNAT), this path is dead.
3. **LAN-only** - always available (audited bind_lan opt-in EXISTS). Covers phone/PC on the
   same network only; not a full answer for a cloud-side sender.
4. **Mesh overlay (Tailscale/WireGuard style)** - free for personal use, works through
   CGNAT, but adds an external coordination dependency. An option, not a first choice, and
   only ever as transport: state and logic never leave the PC.
5. **Rendezvous through the user's own Instinct channel** - the one always-on component the
   user already has. The PC publishes its current pointer (address/port + health-nonce
   proof, the signed pointer-publish pattern that EXISTS in src/lib/tunnel.js) and the
   sender reads it from there. This is not a quota-bearing external server and carries no
   state; it replaces the pointer-publish target, nothing else.

## 4. Phased path (each step independently verified before the next)

0. **Facts** (this prep): win-netprobe on the PC -> which of 3.1/3.2 are real. DESIGN ONLY.
1. **Reachability live test**: pick the probe-supported option; one explicit owner-approved
   change (firewall pinhole or router mapping); live inbound proof.
2. **Pointer publish retarget**: tunnel.js publish loop learns a second, worker-independent
   target (phase 3.5). Signed pointer + health nonce flow unchanged.
3. **Worker demoted to optional relay**: the command path runs direct sender<->PC; the
   worker, where kept, is a stateless fallback.
4. **D1-free operation** for the GlassWidgets flows: file ledger already local; nothing to
   migrate off the PC because nothing critical lives only in D1.

The enroll-completion seam stays BLOCKED exactly as reviewed (503
trusted_approval_source_unavailable) - independence work changes transport and state, never
authority. No step performs a live deploy/install/mutation without explicit approval.
