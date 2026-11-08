# Linux: on a non-glibc libc the shim recurses when it resolves the real `dlsym`

|             |                                                                                       |
| ----------- | ------------------------------------------------------------------------------------- |
| Status      | open                                                                                  |
| Observed in | io-mon `23556a3` (`agents`), by reading the code; not run (no non-glibc build exists) |
| Recorded    | 2026-11-08                                                                            |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim`, `ct_real_dlsym_fn` (the `#else` branch) |

## Observed

Found while reviewing `23556a3` ("answer dlsym(RTLD_NEXT) relative to the
caller"). On glibc the shim finds the real `dlsym` with
`dlvsym(RTLD_NEXT, "dlsym", <base version>)`, which does not go through the
shim's own exported `dlsym`. On any other libc the `#else` branch uses
`ct_resolve("dlsym")`, which is `stackable_linux_preload_resolve_next`, which
calls `dlsym(RTLD_NEXT, "dlsym")`. The shim is linked so that its own calls
bind to its own definitions, so that call reaches the shim's exported `dlsym`.
With the real pointer not yet published, the entry stub calls
`ct_linux_preload_dlsym_entry_resolve`, which calls `ct_real_dlsym_fn` again,
and the recursion has no end. Before `23556a3` the same path recursed through
the C definition of the exported `dlsym` instead.

Nothing builds or tests the shim against a non-glibc libc, so no run has shown
it.

## Expected

Not specified: the supported Linux targets (x86_64, AArch64, armhf) are all
glibc, and `docs/contributors/architecture.md` names no other libc. Proposed:
either resolve the real `dlsym` on a non-glibc libc without passing through the
shim's export (for musl, a lookup on the libc's own handle), or refuse to
build the shim for a libc other than glibc, so the branch cannot ship
untested.
