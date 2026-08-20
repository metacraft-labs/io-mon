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

## Synthetic fragments are not enough

Most tests here drive the writer with fragments the test process writes
itself. That is fast and hermetic, and it is blind to an entire class of
defect: anything about *where* the shim emits from, or whether its hooks
installed at all.

`test_io_mon_windows_process_start_survives.nim` is deliberately live for that
reason. It runs a real monitored child through `runMonitored` and asserts both
that a `mrProcessStart` record reaches the depfile and that the run grades
`mcComplete`. The defect it pins — the shim's process-start being emitted from
the injector's remote thread, whose per-`(osPid, threadId)` fragment batch was
never flushed before that thread exited — was invisible to every synthetic
test, and made every Windows build uncacheable: with no process-start
surviving, `childIsMonitored` answered false for every spawn, which is an
unknown-scope loss, which skips action-cache publication.

The general shape worth remembering: **a monitoring failure looks like a
process with no dependencies.** Tests that assert on the records that *are*
present cannot see it; assert on the completeness grade as well.

Not covered here, because it needs an i686 toolchain the suite cannot assume:
the WOW64 path (32-bit children). `nim-stackable-hooks`'
`tests/test_windows_wow64_injection.nim` covers the injector side and skips
when the 32-bit artefacts are absent.
