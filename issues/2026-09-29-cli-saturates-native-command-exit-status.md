# Standalone CLI saturates valid native command exit statuses

Status: open. Observed in io-mon `5421a9b`.

`cmd/io_mon_snoop.nim` passes `runFsSnoopCli`'s integer directly to Nim
`quit`. Nim 2.2.4 saturates that integer to a signed 32-bit range on Windows
and a signed 8-bit range on POSIX. Valid Windows statuses above `0x7fffffff`
therefore become `0x7fffffff`; POSIX statuses above 127 become 127.

[CLI usage](../docs/usage.md) promises the monitored command's own exit
status. Preserve the native bit pattern at the final CLI boundary. Validate
actual child execution through the standalone CLI for zero, ordinary nonzero
and high-bit statuses, including on Windows and POSIX; old/new controls must
use the same child bytes. Do not change library result semantics or treat a
failed child as successful.

This also explains why the full process capture in the separate RunQuota
monitor diagnostic is insufficient to recover a high-bit child status:
Reprobuild's command uses Nim's same exit mechanism. A direct io-mon API probe
is required to read the child's value without that outer conversion.

Fetched dev `9c1d52b` and searched open and historical CLI/exit-status issues
before filing. The native NTSTATUS forwarding defect is separately repaired
at `94ac0c1`; this record concerns the final standalone executable boundary.
