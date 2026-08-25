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

## The M5 capability tests, and why they come in pairs

`test_io_mon_windows_ipc_connect.nim`,
`test_io_mon_windows_external_content.nim` and
`test_io_mon_windows_non_determinism.nim` cover the three capability gaps M5
closed. They share `tests/helpers/windows_channel_fixture.nim`, and each test
binary re-invokes *itself* as the monitored program (the
`--io-mon-channel-fixture <mode> [arg]` dispatch), following
`test_io_mon_windows_spawn_resume_invariant.nim`.

Three conventions in there are worth copying:

- **The fixture reports whether the channel was exercised.** Every mode returns
  a distinct non-zero code on failure and the tests assert `exitCode == 0`
  before asserting on records. Without that, a fixture that silently failed to
  open its pipe would produce a run with no IPC record and a records-only
  assertion would call it a pass — the same shape as the monitoring failure
  being tested.
- **Provenance is tested in both directions.** For each channel there is an
  in-tree case that must stay `mcComplete` and an out-of-tree case that must
  grade `mcIncomplete`. Only one of the two would pass against an
  implementation that always answered the same way, and the false-downgrade
  direction is as damaging as the false-complete one: it makes every build
  that uses a pipe uncacheable.
- **The out-of-tree peer is the test process itself.** It serves the named
  pipe / owns the named section while staying outside the monitored tree, so
  the breakaway-daemon case needs no daemon installed on the host.

The `pipe`-directory cases in the IPC test exist because the first
implementation got them wrong in two ways that only mutation testing found: a
*relative* `pipe\x.txt` is byte-for-byte the NT object form after the `\??\`
strip, and an *extended-length* `\\?\C:\...\pipe\x.txt` passes any
first-character filter while containing `\pipe\`. Both were recorded as
connections to an unknown peer, which downgrades the capture. An absolute
`C:\...\pipe\x.txt` never reaches the classifier at all, so testing only that
spelling pins nothing.

### The cases a *successful* channel cannot reach

Review found four branches with no test, and the pattern behind all four is
worth stating once: **every case exercised a channel that worked.** A fixture
that connects to a live listener, opens a pipe that exists, or creates a
section under a fresh name can never reach the code that decides what to do
when the call *fails* or when somebody else got there first — and those are
exactly the branches where a wrong answer is a false grade rather than a
missing detail. The added cases are therefore all about the *other* outcome:

- `socket-connect-refused` — a `connect` to a closed port. A refusal reached no
  peer, and recording it as an ipc-connect to an unknown peer downgrades the
  whole capture over a connection that never happened. Build hosts probe
  localhost constantly, so this is not rare.
- `socket-connect-nonblocking` — the opposite direction of the same guard. A
  non-blocking connect returns `WSAEWOULDBLOCK` and completes asynchronously:
  the peer *is* reached, so accepting only `rc == 0` would make an async
  client's out-of-tree daemon invisible.
- `pipe-client-missing` — the pipe-arm counterpart of the refused connect.
- `shm-create-existing` — `CreateFileMapping` over a name the test process
  already owns. It does not fail on an existing name; it opens the section and
  sets `ERROR_ALREADY_EXISTS`, so the same call is both producer and consumer
  and only the last-error tells them apart. Both pre-existing shm cases used a
  *fresh* name, so the branch that decides "this content came from outside the
  tree" had no coverage at all.
- `nt-pipe-client` — `NtCreateFile` called **directly**. `CreateFileW` lowers to
  it, so every other pipe case fires the kernel32 arm first and would pass with
  the NT arm deleted. The NT arm sees a path whose `\??\` prefix has been
  stripped, leaving `pipe\<name>` — byte-for-byte the ordinary relative open the
  classifier must *reject* — which is why it classifies on
  `objectAttributesRawName` instead.
- `anon-pipe-inherit` — create in one process, read in another. `pipe:<server>:
  <client>` is claimed to be process-independent, and an in-process fixture
  makes *any* key look process-independent, including one with the caller's own
  pid in it.

Each fixture mode **asserts the outcome it needs** rather than assuming it: the
refused connect requires `WSAECONNREFUSED`, the pre-owned section requires
`ERROR_ALREADY_EXISTS`, the non-blocking connect requires `WSAEWOULDBLOCK`. A
mode that silently got the *other* outcome would make a
"no record was emitted" assertion pass for the wrong reason — the same failure
shape as the monitoring bug being tested.

Not covered here, because it needs an i686 toolchain the suite cannot assume:
the WOW64 path (32-bit children). `nim-stackable-hooks`'
`tests/test_windows_wow64_injection.nim` covers the injector side and skips
when the 32-bit artefacts are absent. Note that `nt-pipe-client` is therefore
64-bit-only, and `objectAttributesToString` reads `ObjectName` at the x64
offset unconditionally — so a 32-bit client calling `NtCreateFile` directly on
a pipe has no coverage *and* no classification. The kernel32 arm covers every
client that goes through `CreateFileW`, which is nearly all of them.
