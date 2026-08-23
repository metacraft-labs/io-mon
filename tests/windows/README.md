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

`test_io_mon_windows_spawn_resume_invariant.nim` is live for a different
reason: what it pins is not a record but a *process state*. The spawn hooks
force `CREATE_SUSPENDED` into every child so they can inject before it runs,
which makes them the owner of a suspension the caller never asked for, and
the defect they had was leaving on a path that skipped the `ResumeThread` —
producing parentless `cc1.exe`/`gcc.exe` frozen before their first
instruction, each holding the injected shim image open (which is why
relinking `build/lib/librepro_monitor_shim.dll` intermittently failed with
`Permission denied`). No assertion on the depfile can see that; the test
spawns real children and asserts they reach their own `quit`.

Two of its cases need an abnormal exit from the hook, and neither can be
provoked from outside the process — one turns on a thread-local, the other on
a raise the hook's own `except` swallows. The shim exposes them through
`REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE` (`return`/`raise`), read once at init.
Prefer that pattern over asserting on source shape when the property under
test is a live process's.

**But compile-gate the knob, and build the gated shim from the test.** That
one is behind `-d:ioMonShimSpawnEscapeTest`; the test compiles a second shim
into `build/test-bin/`, uses it for those two cases only, and runs the other
two against the real `build/lib` artefact. The reason is specific to a
monitor: taking either escape suppresses the spawn record *and* the
injection, so the child subtree goes unwatched while the run still grades
`mcComplete` — precisely the "monitoring failure that looks like a process
with no dependencies" above, reachable by anyone who can set an environment
variable in the build's environment. A fault-injection switch whose
effect is "produce clean-looking evidence for something you did not watch"
must not exist in the artefact that ships. The gated shim is rebuilt on every
run rather than cached, for the same reason a stale `build/lib` invalidates
any mutation test of this file.

Not covered by it, and not fixable by the same means: a parent killed with
`TerminateProcess` *between* `CreateProcessW` returning and the hook's
`finally` unwinds nothing, so a tree-kill of a monitored build can still
strand the child it was mid-way through injecting.

Not covered here, because it needs an i686 toolchain the suite cannot assume:
the WOW64 path (32-bit children). `nim-stackable-hooks`'
`tests/test_windows_wow64_injection.nim` covers the injector side and skips
when the 32-bit artefacts are absent.
