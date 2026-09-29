# x64 shim propagation can modify an ARM64 child's entry point

Status: open. Observed with the io-mon Windows runtime at `4b2bb39`; the same
injection path is present at `af1af0f`.

## Observed

RunQuota `8add804` Windows ARM-host job
[109446771063](https://github.com/metacraft-labs/runquota/actions/runs/36580081181/job/109446771063)
launches the real System32 `whoami /user` from an x64 monitored program.
The child returns `-1073741795` (`0xc000001d`, illegal instruction) with no
output. ACL and independent owner-identity tests fail before their checks.

`injectSpawnedChild` calls the x86 propagation implementation for every child.
The locked stackable-hooks entry-point lookup checks the PE signature but not
its machine type before writing the x86 two-byte parking loop. An ARM64
process is not a WOW64 x86 process, so that old boolean cannot distinguish it
from native x64. This is a concrete unsafe code path; a real old/new control
must still establish whether it accounts for the observed child crash.

## Expected and proposed repair

[Architecture / Correctness Contract](../docs/contributors/architecture.md)
requires uncertain capture to be incomplete. The native Windows ARM64 backend
is deferred by the release scope. The x64 shim must therefore detect a child's
actual process machine before attempting x86 injection, leave unsupported
children runnable, and retain spawn/loss evidence that makes the capture
incomplete. It must not claim native ARM64 monitoring or cacheable completeness.
Use Windows' process-machine API, including its native-machine result when
processMachine is UNKNOWN. Keep existing x64 and WOW64 x86 injection paths.

Validate on a real ARM64 Windows host: an x64 fixture starts the actual
System32 identity tool; native execution and repaired monitoring must return
the same SID and success, while the old shim reproduces the failure. Assert
the repaired capture is incomplete with an explicit unsupported-machine
spawn diagnostic. Keep the corresponding x64-host control in the normal suite.

Fetched dev `9c1d52b` and searched current and resolved architecture issues.
The native ARM64 backend issue is related, but does not cover preserving the
behavior of a child launched by an x64 monitored process.
