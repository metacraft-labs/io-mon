# Windows: a 32-bit root child with no 32-bit shim fails the whole monitored command

| | |
|---|---|
| Status | open |
| Recorded | 2026-10-03 |
| Observed in | io-mon @ `e750199` (code re-checked at `origin/agents` `b9c7330`); nim-stackable-hooks @ `71f2aae` (re-checked at `origin/agents` `3cbca0a`); consumer reprobuild @ `637714ce` |
| Area | `src/io_mon/fs_snoop.nim` Windows arm of `waitForMonitorRoot` / `collectMonitorEvidence`; nim-stackable-hooks `windows_injector.runWithMonitorShim` |

## Observed

On a Windows x64 host with no i686 toolchain, neither io-mon's
`scripts/build_shim.sh` nor reprobuild's build graph produces
`librepro_monitor_shim32.dll`. Both say so and continue, which is the
documented degradation. What that degradation then does depends on where the
32-bit process sits in the tree:

- **32-bit grandchild** (`cmd.exe /c <32-bit exe>`): the command runs and
  exits 0. The depfile records the injection failure as an unmonitored-subtree
  event loss.
- **32-bit root child**: the command never runs. The monitor terminates the
  suspended child and exits 1:

```text
repro internal io monitor: error: child is a 32-bit (WOW64) process but the 32-bit shim is missing: D:\m\dev\reprobuild\build\lib\librepro_monitor_shim32.dll — build it with `nim c --cpu:i386` and place it beside the 64-bit shim, or call setWow64ShimPath
```

The common case is a Scoop PATH shim. Scoop's `shims\python3.exe` is a PE32
(`i386`, machine `0x014C`) launcher for the 64-bit
`apps\python\current\python.exe`. So any monitored action whose argv[0]
resolves to it fails. One example is reprobuild-packages' lint gate
(`repro lint`). Its `packages.check-catalog` action and its sibling actions run
`inlineExecCall(["python3", …])`, so the gate is red on every host whose
`python3` on PATH is a Scoop shim. See *Evidence*.

## Expected

Run the 32-bit root unmonitored, and record that as an unmonitored-subtree
event loss so the capture grades `mcIncomplete`. Do not refuse to run the
command.

- io-mon [Architecture §2, Correctness Contract](../docs/contributors/architecture.md):
  "Every uncertainty downgrades to `mcIncomplete`". The same document's
  Windows *Child architecture* paragraph already applies this to the other
  child io-mon cannot inject, a native ARM64 child: it "is resumed without
  injection, with an unsupported-machine spawn diagnostic and missing
  process-start loss evidence."
- The consumer's documented degradation for exactly this artefact is that 32-bit
  children "cannot be injected without them; their subtrees run
  UNMONITORED, which grades as an unknown-scope evidence loss and makes the
  owning action uncacheable". That wording is in reprobuild's
  `missingI686ToolchainNote()` in `repro.nim`, and in
  `reprobuild-specs/milestones/Windows-Cacheable-Builds-Session-Residuals.milestones.org`,
  S1 *"Degradation, exercised rather than asserted"*. That milestone tested
  the degradation only for the build itself (8 actions dropped to 5, exit 0).
  It never ran a monitored 32-bit root afterwards.

The two upstream documents disagree. nim-stackable-hooks
`docs/windows-wow64-injection.md` *Failure policy* says "a missing
`<name>32.dll` fails before anything is written into the child". At the
injector layer that is reasonable, because it refuses to inject the wrong
shim. But io-mon passes that refusal on as a failure of the user's command.
For the fork-runtime refusal, io-mon already turns it into
`monitoringSkipped` plus an `mrEventLoss` record in `collectMonitorEvidence`.

## Evidence

Measured 2026-10-03 on the Windows 11 x64 workstation, using
`D:\m\dev\reprobuild\build\bin\reprobuild.exe` (`repro 0.2.2`, built
2026-09-28 17:33 from the checkout at `637714ce`). Its `build\lib` holds only
the 64-bit `librepro_monitor_shim.dll`.

```powershell
# PE machine of the Scoop shim vs the real interpreter
#   C:\Users\zahary\scoop\shims\python3.exe               machine=0x014C (i386)
#   C:\Users\zahary\scoop\apps\python\current\python.exe  machine=0x8664

reprobuild.exe internal io monitor --depfile py3.iomon -- C:\Users\zahary\scoop\shims\python3.exe --version
#   -> the error above, exit 1
reprobuild.exe internal io monitor --depfile py64.iomon -- C:\Users\zahary\scoop\apps\python\current\python.exe --version
#   -> Python 3.14.7, exit 0
reprobuild.exe internal io monitor --depfile cmd32.iomon -- C:\Windows\SysWOW64\cmd.exe /c echo hi
#   -> the same error, exit 1
reprobuild.exe internal io monitor --depfile cmd64.iomon -- C:\Windows\System32\cmd.exe /c C:\Users\zahary\scoop\shims\python3.exe --version
#   -> Python 3.14.7, exit 0   (32-bit grandchild: runs)
```

With the session's `REPRO_MONITOR_SHIM_LIB` pointing at
`D:\m\dev\io-mon\build\lib\librepro_monitor_shim.dll`, the error is the same
and names `D:\m\dev\io-mon\build\lib\librepro_monitor_shim32.dll`. That
directory has no 32-bit shim either.

The lint gate run through the same engine, in a fresh worktree of
reprobuild-packages at `origin/agents` `4e2fd1d`
(`repro lint --tool-provisioning=path --daemon=off`, `REPRO_MONITOR_SHIM_LIB`
unset):

```text
checking graph actions=2
[########################] checked=2/2 built=2/2 running=0 failed python3 scr...
repro build: action failed: check-catalog (exit code 1)
repro internal io monitor: error: child is a 32-bit (WOW64) process but the 32-bit shim is missing: D:\m\dev\reprobuild\build\lib\librepro_monitor_shim32.dll — build it with `nim c --cpu:i386` and place it beside the 64-bit shim, or call setWow64ShimPath

repro build: action failed: check-source-tests (exit code 1)
repro internal io monitor: error: child is a 32-bit (WOW64) process but the 32-bit shim is missing: D:\m\dev\reprobuild\build\lib\librepro_monitor_shim32.dll — build it with `nim c --cpu:i386` and place it beside the 64-bit shim, or call setWow64ShimPath
```

The same two checks pass outside the monitor in the same worktree
(`python3 scripts/check_catalog.py` → "Validated 302 source recipes …",
exit 0; `python3 scripts/source_test_catalog.py` → "Validated 238 source-test
graph entries.", exit 0). So the red gate is caused by the monitor, not by the
catalog. That lint run printed none of the `missingI686ToolchainNote()` text.
That is expected, because the note is a `repro dev-env` diagnostic of the
reprobuild project, not of the consumer's build.

Code path (symbols at `origin/agents`):

- nim-stackable-hooks `windows_injector.runWithMonitorShim` checks
  `processIsWow64` and `wow64ShimPathFor`. If the file is missing, it raises
  `OSError("child is a 32-bit (WOW64) process but the 32-bit shim is
  missing: …")`. The outer `except OSError` calls `TerminateProcess` and
  re-raises.
- io-mon `waitForMonitorRoot` (Windows arm) calls `runWithMonitorShim` with
  no handler, so the exception becomes the CLI's error exit. The
  `monitoringSkipped` / `skipReason` path that `collectMonitorEvidence` already
  turns into an `mrEventLoss` "unmonitored subtree/peer" record is never
  reached.

The grandchild case already degrades the way this issue asks the root case to.
Searching the raw bytes of `cmd64.iomon` (it was not decoded: the
`io-mon inspect` on this host is an August build that answers "unknown RMDF
magic") finds the `CreateProcessW` spawn record annotated
`inject=ioInjectFailed`, followed by an event-loss record with the text
`unmonitored subtree/peer (un-injectable spawn child, SETEXEC into a hardened
image, or IPC connect to an out-of-tree breakaway daemon)`. This filing did
not read the final completeness grade.

## Workarounds

- Put a 64-bit `python3` first on PATH. For example, call
  `scoop\apps\python\current\python.exe` directly, or use an interpreter whose
  `python3.exe` is not a PE32 shim. Then the root child is x64. Not exercised
  through `repro lint` here; the direct
  `internal io monitor -- …\apps\python\current\python.exe --version` run
  above succeeds.
- Run the checks directly (`python3 scripts/check_catalog.py`,
  `python3 scripts/source_test_catalog.py`) outside the monitor. Verified
  above.
- Provision an i686 mingw toolchain (`pacman -S mingw-w64-i686-gcc`, or
  `IO_MON_I686_GCC`) and rebuild, so that `librepro_monitor_shim32.dll`,
  `stackable_hooks_wow64_probe32.exe` and `stackable_hooks_inject64.exe` are
  staged.

## Impact

Any monitored command whose root process is 32-bit fails outright on a host
without the 32-bit artefacts. Scoop shims are 32-bit, so this covers every
action that names a Scoop-shimmed tool by bare name. In particular,
reprobuild-packages' `repro lint` (also its pre-commit/pre-push hook) is red
for anyone whose PATH resolves `python3` to `scoop\shims\python3.exe`. The
failure shows only the monitor's error, not the action's own output, so it
looks like a broken check rather than an unprovisioned host.

## Suggested direction

Option 1: catch the missing-32-bit-shim refusal in io-mon's Windows arm and
resume the root unmonitored, as `monitoringSkipped = true` with a `skipReason`
that names the missing file. `collectMonitorEvidence` then emits its existing
`mrEventLoss` record and the edge grades `mcIncomplete`. This is what reprobuild
already documents. The cost: the action runs but is uncacheable, and the
warning appears only as evidence loss unless the CLI also prints it.

Option 2: have nim-stackable-hooks return a skipped result
(`monitoringSkipped`, as it already does for the fork-runtime refusal) instead
of raising. This changes the injector's documented *Failure policy*, so its
own doc needs updating.

Either way, a typed refusal is better than matching the error string.
Separately, reprobuild could provision the i686 toolchain on Windows so
that the degradation is rare, but that does not remove the need to degrade
correctly.

## Related

- reprobuild `libs/repro_dsl_stdlib/src/repro_dsl_stdlib/monitor_shim_artifacts.nim`
  (module doc: "The injector meets a 32-bit child, finds no `<name>32.dll`,
  refuses, and the child's whole subtree goes unmonitored"). That holds for a
  grandchild but not for the root.
- reprobuild-specs `milestones/Windows-Build-Correctness-Bitness-And-Capabilities.milestones.org`
  M2/M3 (WOW64 injection) and M10 residual (WOW64 arm unverified, no i686
  toolchain on the verification host).
- reprobuild `libs/repro_dsl_stdlib/src/repro_dsl_stdlib/packages/make.nim`
  records the same class of failure for Scoop's 32-bit `make.exe`.
- Archive search: no matches for `shim32`, `32-bit shim is missing` or
  `librepro_monitor_shim32` in io-mon `issues/` history (all refs) or
  reprobuild-specs `issues/` history (`origin/latest`). The `WOW64` matches in io-mon
  history (`8384b2d`, `5e71adf`) concern native ARM64 children, not a missing
  32-bit shim.
