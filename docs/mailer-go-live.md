# Email rendezvous go-live runbook (tomorrow, with the user)

Approved 2026-10-14 01:00 (user: "do what's needed"; hands-on parts tomorrow). No live
actions were taken tonight - everything below is prepared and waiting.

## Ready already
- vault link for the app-password (kind=login "Gmail GlassWidgets PC", password field only) -
  held by main; the user fills it when convenient. The password's REAL destination is the PC
  config (typed into a masked prompt there); the vault is the user's safe store.
- server/lib/pointer-mailer.js + GW_MAILER=1 wiring (10 suites green).
- docs/fixtures/win-mailer-config.txt - guided, masked prompt, redacted verify, -TestSend.
- docs/fixtures/win-autostart.txt - user-level Scheduled Task (-Install/-Uninstall).

## Tomorrow, one step per message
1. Vault: fill the link (app-password from myaccount.google.com/apppasswords - needs 2FA on;
   name suggestion: "GlassWidgets PC"). Keep the 16 letters somewhere safe - the PC prompt
   needs them typed once.
2. Deploy node portable (same block as the rehearsal, into %USERPROFILE%\gw-server\node).
3. Deploy repo zip (fresh archive of the current branch, into %USERPROFILE%\gw-server\repo).
4. Server setup fixture (fresh production values baked at go-time: locally generated token,
   new production sender pubkey - private key stays with ops/Instinct only).
5. Mailer config: run win-mailer-config.ps1 -TestSend -> one real mail must land in the
   user's Gmail (I confirm receipt from my side).
6. Autostart: win-autostart.ps1 -Install, then Start-ScheduledTask (no reboot needed).
7. Live proof: tunnel rotates (or taskkill drill) -> GW-POINTER mail fires my wake -> I
   resolvePointer -> health proof -> one signed read_file e2e. Then the worker is demoted
   to optional-relay (separate decision).

## Rollback (any point)
win-autostart.ps1 -Uninstall; remove the "mailer" object from config.json; revoke the
app-password at myaccount.google.com/apppasswords; delete %USERPROFILE%\gw-server.

## Notes
- The token in the production config is generated ON the PC and is public-class by design
  (the baked-key model) - the real gates stay the signed envelopes/read-auth/device key.
- GW_SERVER_PORT: pick a port distinct from 47700 if the Electron app's embedded server may
  run simultaneously (bind conflict is loud, not silent - but let's not rely on it).
