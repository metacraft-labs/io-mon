# Linux shim runtime settings diverge from the injected-library policy

Status: open. Observed at io-mon `80a7c4a`; the same Linux build path is
present at `5e71adf` and `4b2bb3`.

## Observed

`scripts/build_shim.sh` supplies `useMalloc` but no Linux memory-manager,
trace or signal-handler settings. There is no `linux_preload.nim.cfg`.
The actual old/current build logs in control
[36633929242](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36633929242)
both report `mm: orc`. The existing portable signal-handler policy test
describes every injected shim but checks only Windows and macOS.

That control also reproduces RunQuota's Linux heap corruption. The identical
real process fixture, SHA256
`e3948fe9a7824d78ecf84d1d354ece929b0532839169514f121a0aabf7ce7165`,
passes three native runs and three bootstrap-monitor runs. Both separately
built old/current shims fail two of three runs after ten assertions pass.
One abort reports `realloc(): invalid old size` from the child-output reader's
`streams.fsReadData`; others report a double free. This establishes a repeatable
monitored failure, not its allocation owner or the responsible runtime setting.

## Expected and investigation

[Shim build policy](../docs/contributors/shim-build-policy.md#build-settings)
requires deterministic ARC, disabled stack/line traces and `noSignalHandler`
for injected POSIX libraries. The shim must preserve the host's execution and
fault handling. Windows retains its separately documented ORC configuration.

Compare the retained real binary with the original shim, ARC alone, and the
complete documented POSIX settings. Keep source, assertions and deadlines
unchanged. Capture the failing thread with GDB before attributing the heap
defect. If the policy settings repair it, apply them through a Linux project
configuration so direct builds and Reprobuild edges agree, and extend the real
runtime regression and configuration checks.

Fetched dev `07cc4af` and searched open and deleted signal-handler, ORC and
heap issues before filing. RunQuota's
`2026-09-30-linux-monitored-process-fixture-aborts-with-heap-corruption.md`
records the consumer failure. Local retained evidence is under
`/tmp/runquota-linux-heap-878-evidence`.

## ARM compiler crash, 2026-10-04

At RunQuota `f369c3429c83be2403b8dd91d25e137207b30575`, native ARM
diagnostic [37162127465](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/37162127465)
reproduces a GCC driver crash on the fifth fresh monitored provider build.
The exact failed compiler command succeeds when replayed directly. The
bootstrap uses Reprobuild `1f85ace0037d0a70e966fe8eee645d766522b1ab` and
io-mon `3df08c24ee91900b950ed20a3827923d213f2a9c`. The injected library SHA256
is `f4ed062210997fbbc5b371f23642d07c1ede7f3e7ed7e41b06717cb0404b6f8a`.

Artifact `11288671254` retains the generated C, exact failed command, replay
result and argument-free core backtrace. The GCC process reaches
`repro_hook_close`, `callDepthLimitReached`, then `auxWriteStackTrace`; the
shim's own signal handler recursively enters the same stack-trace routine.
Only the shim, system libc and the system loader are listed as shared objects.
Raw cores were deleted after extracting the trace and were not uploaded.

Fresh `agents` at `d8b1e3c` still has the same Linux runtime settings. The
existing vfork repair restores the preload recursion guard, but a successful
child exec also leaves Nim stack frames without a normal return. Shared TLS
retaining those abandoned frames is a hypothesis, not yet a proven cause.
Add a real repeated-vfork regression and compare the unchanged runtime with
the documented POSIX settings. Preserve process exit, capture completeness,
child identity and resumed-parent evidence checks. Also verify host signal
handler ownership with an actual loaded shim. No allocator diagnosis is
inferred from this separate stack-trace crash.
