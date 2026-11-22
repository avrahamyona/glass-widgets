# Windows validation snapshot

This branch checks the prepared desktop receive fix and an isolated native process-handle library. It is not a release and is not ready for installation.

## Current workflow

- Manual dispatch on this exact public validation branch only.
- Standard Windows runner, read-only repository contents permission, no stored checkout credentials.
- No repository secret injection, release, tag, updater upload, repository cache or retained build artifact.
- Exact source hashes are checked before tests. Four source files retain LF bytes on Windows through narrowly scoped Git attributes.
- Receive tests use synthetic fixtures and loopback or fake network only.
- Native tests create their own new child and accept no existing PID or user-computer connection. They retain the strict creation-time, executable, owner and logon-SID identity checks, observation-only restrictions, cancellation, one termination request and exit/disposal verification.
- The expected logon SID comes from the current Windows session through the built-in whoami /logonid command. Output is captured and must contain exactly one valid logon SID. No SID is synthesized or logged. WindowsIdentity.Groups is not used because it deliberately excludes Logon ID groups.
- The unchanged native source is compiled and exercised under Windows PowerShell and PowerShell 7 separately.

## Separate package evidence

The current workflow checks packaging in a separate job. It builds the existing media/cloud helpers and a transient installer, then checks the candidate hashes inside ASAR. It has no cloud-account credentials, does not launch or install the desktop application, and does not retain the installer for download. Native and package jobs must both pass for overall workflow success.

Earlier run https://github.com/avrahamyona/glass-widgets/actions/runs/44999487869 built an installer, but its archive inspection failed. The inspection fixture passed POSIX paths to ASAR 3.4.1 on Windows, whose directory traversal uses the native path separator. The checker now normalizes those paths; it does not skip the missing-file or hash checks. The application and native source hashes are unchanged. Consult the exact current run results rather than assuming either native or package success.

That earlier run retains an explicit red native-runtime gate because it did not test behavior. The current workflow runs the corrected identity fixture instead of treating that earlier gate as passed.

## Fixture correction

The earlier runtime attempt stopped before dummy creation while seeking the Logon SID through WindowsIdentity.Groups. Microsoft's documentation and source confirm that this property filters that group out. The fixture query was corrected, not the required identity or the production library.

- https://learn.microsoft.com/en-us/archive/blogs/shawnfa/which-groups-does-windowsidentity-groups-return
- https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/WindowsIdentity.cs
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami

## Limits

The native controller is not integrated in the receive installer. Server start, installed IPC, desktop integrity compatibility, normal-user privileges, server recovery, visual UI and real end-to-end response delivery remain unverified. Hosted Windows runners use administrator privileges, so passing their tests does not prove ordinary-user desktop behavior.

No backup, installed archive, account configuration, real messages, credentials or user-machine diagnostic records are included in this snapshot. Compilation, native behavior and packaging are separate claims and must be reported separately with their actual evidence.
