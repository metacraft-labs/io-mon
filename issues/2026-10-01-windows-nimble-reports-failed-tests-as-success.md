# Windows Nimble reports a failing test task as success

Status: open. At `13d12f3`, Windows x64 native cross-check
[job 110470523118](https://github.com/metacraft-labs/io-mon/actions/runs/36892096089/job/110470523118)
prints a real test failure but finishes successfully. The focused
[control at `e13a98f`](https://github.com/metacraft-labs/io-mon/actions/runs/36900671607/job/110498730652)
downloads and verifies the exact Nim 2.2.10 and Just 1.51.0 archives selected by
Reprobuild. A minimal Nimble task executes `cmd /c exit 17`: Nimble prints the
OSError and returns zero, then `just test` also returns zero. No Reprobuild or
monitor participates in this control.

The required native test gate must fail when a compiled test fails. This follows
from `metacraft-dev-guidelines/policies/ci-shared-dev-env.md` and its requirement
that CI run the project's real local entrypoints. Change the Just test commands
to invoke a plain NimScript runner directly. Share the existing sorted directory
catalog with the Nimble compatibility tasks, preserving every compiler command,
host selection and assertion. Check both successful and failing real programs
through the new entrypoint, including the pinned Windows compiler.

Fetched `agents` / `dev` at `e7e554b` / `2d07041` and searched open and archived
Windows exit-status, Nimble and cross-check issues. The neighboring relative-path
fixture issue owns the DLL-discovery repair; this file owns truthful test status.
Evidence: `/tmp/io-mon-windows-native-exit-control.log`.
