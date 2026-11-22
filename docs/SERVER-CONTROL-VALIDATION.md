# Server-control validation branch

This workflow validates source and test-owned processes on a standard public Windows hosted runner. It is not a release workflow.

It checks the private Node/C# process transport, policy persistence, the durable uncertainty barrier, native timestamp precision and the IPC origin boundary. The native integration creates one Node supervisor and one child dummy, captures their exact native identities, rejects an incorrect creation tick, checks cancellation while a real native wait is pending, and stops only those two reviewed instances. Read-only process-parent metadata is used to refuse unexpected descendants. No other process is a stop target.

The temporary test directory has its inherited permissions removed, receives access only for the current runner user, SYSTEM and Administrators, and has that access list checked. No machine-wide permissions, execution policy, startup setting or security setting is changed.

The workflow uses the runner's existing SDK to build the .NET 10 host with the pinned current runtime patch. It does not install a system SDK, inject repository secrets, upload artifacts, build an installer, create a release or change the default branch. If the runner cannot build the target, validation fails rather than changing protections.

A successful run proves only the reported test conditions. The IPC window is a harness, not a rendered installed Electron window. The managed-start actuator creates the dummy graph, not the production server. Production main-process enrollment, a policy-aware real launcher, process discovery, recovery after an uncertain operation, current UI review, installation and real-answer end-to-end checks remain separate work.
