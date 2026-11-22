# Windows validation snapshot

This branch tests the prepared desktop receive fix and an isolated native process-handle library. It is not a release and is not ready for installation.

- Only manual workflow dispatch on this exact validation branch is enabled.
- Standard Windows runner, read-only repository contents permission, no stored checkout credentials.
- No repository secret injection, release, tag, updater upload, repository cache or retained build artifact.
- Transport tests use synthetic fixtures and loopback or fake network only.
- The dummy-only harness remains available as reviewed source, but is not invoked by the current workflow. Run 44999012756 stopped before dummy creation because the current-session logon SID prerequisite was not satisfied. That check has not been removed or relaxed.
- Native source hashes are checked before compilation-only checks under Windows PowerShell and PowerShell 7. Neither compilation check invokes the native process-control methods.
- A separately named runtime-verification gate intentionally stays red to record the missing behavioral proof. It is not a new runtime attempt. Independent receive-package checks can run without concealing that open gate.
- Existing media and cloud helper sources are built only to support the package recipe. No cloud account is connected.
- Package verification checks candidate hashes inside ASAR and the transient installer. It does not install or run the desktop application.

The native controller is not integrated in this installer. Server start, installed IPC, desktop integrity compatibility, normal-user privileges, server recovery, visual UI and real end-to-end response delivery remain unverified. Standard hosted Windows runners use administrator privileges, so their results do not prove ordinary-user desktop behavior.

Source-hashes.json identifies the exact prepared application and native source under test. No backup, installed archive, account configuration, real messages, credentials or user-machine diagnostic records are included in this snapshot.

The installer is built only in the disposable runner. A successful run does not retain an installer for download. Only minimal test status and file hashes are logged.
