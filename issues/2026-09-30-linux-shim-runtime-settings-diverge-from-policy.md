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
