# tests/windows — Windows-only tests (placeholder)

This directory holds tests that exercise io-mon's **Windows-only** live
behaviour: the injected-hook shim (`src/io_mon/shim/windows_interpose.nim`,
`src/io_mon/shim/windows_iat_patcher.nim`,
`src/io_mon/shim/windows_hook_registry.nim`,
`src/io_mon/windows_injector.nim`) — IAT patching / `CreateRemoteThread`-style
injection into a recorded process.

It is selected by the suite only `when defined(windows)` (see the `test` task in
`io_mon.nimble`). Any `test_*.nim` added here runs automatically on a Windows
host.

## What belongs here (vs. elsewhere)

- **Here (`windows/`):** behaviour specific to the Windows injection mechanism
  (IAT patching, DLL injection, the hook registry) and to Win32 surfaces
  (`NtCreateFile`, handle semantics) with no POSIX analogue. Windows is NOT a
  POSIX host, so it does **not** run `tests/posix/`; the cross-POSIX snoop-CLI
  capture must be re-expressed here if the Windows injector should be live-tested.
- **`portable/`:** the shared writer/merge/codec/completeness logic on synthetic
  records already runs on Windows via the `portable/` selection — do NOT
  duplicate it here.

No Windows-only live tests exist yet. Add them here as the Windows injector
matures; until then the portable suite still validates the shared core on
Windows.
