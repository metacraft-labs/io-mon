# Linux ARM64 syscall monitoring is incomplete

|             |                                                                     |
| ----------- | ------------------------------------------------------------------- |
| Status      | open                                                                |
| Recorded    | 2026-09-29                                                          |
| Observed in | io-mon `4f467a0`                                                    |
| Area        | Linux raw syscall classification, patching and capture completeness |

## Observed

The real Linux stdio/IPC suite passes on x86_64 but reports 7 passing and
31 failing cases on ARM64 at the same product SHA. Even `fopen`/`fread`
capture is marked `mcIncomplete`; raw `syscall(openat/read)` loses the expected
file observation and relative writes retain the wrong working directory.
The separate 10-case mapping-policy test passes directly and monitored on
both architectures, so that result does not establish backend completeness.

Source inspection finds two independent architecture assumptions:

- `linux_preload.nim` assigns x86_64 syscall numbers unconditionally, including
  `LinuxSysGetcwd = 79` and `LinuxSysOpenat = 257`. ARM64 uses its own syscall
  ABI. The same constants drive real raw syscalls and event classification.
- `linuxRawSyscallSupported()` in nim-stackable-hooks returns unsupported
  outside Linux x86_64. The wrapper patch, inline trap scanner and vDSO
  patching depend on that substrate. Initialization records those unavailable
  mechanisms as event loss, making ordinary ARM64 captures incomplete.

The precise records behind each failing case are being collected. Do not
attribute all 31 failures to one cause or remove the completeness assertions.

## Expected

[Architecture: Correctness Contract](../docs/contributors/architecture.md)
requires uncertainty to remain incomplete. The
[approved release scope](../../metacraft-specs/infrastructure/gosti-io-mon-runquota-releases.md)
includes native Linux ARM64 and requires existing product checks before
publication; only Windows ARM64 was explicitly deferred. A release smoke
that finds one read event cannot substitute for the full backend gates.

Repair ARM64 syscall numbers and independently validate raw classification,
working-directory updates and capture evidence. Completing the architecture's
raw-syscall interception substrate is a separate port, not a signature or
packaging adjustment. Keep that limitation explicit until implemented and
native integration tests pass.

## Evidence

[ARM64 job](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36488563555/job/109151352979),
[x86_64 job](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36488563555/job/109151352703),
product `4f467a0`, diagnostic `fbd03eb`.
Downloaded ARM64 evidence: `/tmp/io-mon-4f4-arm-diagnostics/stdio-ipc.log`.
Refreshed dev `279a17b`; searched current and deleted issues for ARM64 raw
syscalls and unsupported architectures. The earlier inline-assembly fixture
issue covers its missing test guard only, not this backend gap.
