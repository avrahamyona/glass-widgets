# PC expansion plan (whole-PC operation, requested by the user 2026-10-14 20:21 via main)

Staged, no-stop build. Every stage ships as a repo release + ONE PC paste ask. The trust
model is unchanged: Ed25519-signed envelopes, device-bound, at-most-once ledger. Standing
constraints baked in: no delete op exists anywhere, no spend/publish ops exist anywhere,
secrets are typed locally only, background work is invisible (UI work happens on the live
screen by nature).

## Stage 1 (this release, server-0.2.0): whole-profile file scope
- Roots widened to the user profile (config change in the upgrade block).
- Always-on denylist (ops.js, not removable by config; config `deny` can only ADD):
  prefix denies = server data dir (device key, config with mailer app-password + token,
  ledger, tunnel state), ~/.ssh, ~/.gnupg; basename denies anywhere = browser credential
  stores (Login Data, Web Data, Cookies...), Firefox key dbs, id_rsa/id_ed25519/...
  Denied paths fail with the same outside_roots refusal - no oracle.
- New op write_file: create ('wx' - never overwrites, symlink-preplant safe) or append.
  1MB bound. No overwrite mode, no delete.
- tests: server-skeleton-unit (deny + write_file coverage), server-caps-unit updated
  (fictional unmapped op is now delete_file; write_file is mapped to 'files').

## Stage 2 (next): launch op
Signed process launch: visible or hidden window, background with stdout to file. Zero-dep.

## Stage 3: screenshot + click/type
Inbox Windows APIs only (PowerShell/user32 via a spawned helper), screenshot saved to a
file then fetched signed. Interactive session only; the user sees the mouse/keys live.

## Stage 4: fully invisible autostart
Hidden launcher (vbs-style) replacing the console-window .cmd, plus periodic health to me.
