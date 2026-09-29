# Windows termination hook raises on native status codes with the high bit set

Status: open. Observed in `originalNtTerminateProcess` at io-mon `08b18fa`.

The hook converts its stored 32-bit exit-status bits through
`int32(uint32(ctx.args[1] and 0xFFFFFFFF'u64))`. With Nim 2.2.4 and
`-d:release`, a real executable passing `0xc0000005` through this expression
raises `RangeDefect` instead of preserving the signed NTSTATUS representation.
The incoming trampoline already transports all 32 bits correctly.

`FsSnoopResult.exitCode` promises the monitored command's exit status;
[Architecture / Scope](../docs/contributors/architecture.md) defines the shim
as an observer. Use a bit-preserving cast at the native ABI boundary, then
compare real native and monitored ExitProcess/TerminateProcess calls for zero,
ordinary nonzero, and high-bit statuses on Windows x64 and an ARM64 host.
Keep read evidence in the regression, and demonstrate that the original shim
fails the same test binary. This is a concrete defect independent of the
still-unattributed successful threaded-program exit failure.

RunQuota `8add804`'s read-only mapping test deliberately terminates its child
with `0xc0000005`; its earlier ARM-host job instead reported 1. That symptom
has not yet been attributed to this conversion with a controlled Windows run.

Fetched dev `9c1d52b` and searched current/deleted `NtTerminateProcess`,
`RangeDefect` and termination-status issues before filing.
