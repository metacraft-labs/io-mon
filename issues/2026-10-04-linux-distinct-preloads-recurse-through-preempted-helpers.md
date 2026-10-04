# Distinct Linux monitor images recurse through preempted helpers

|             |                                                     |
| ----------- | --------------------------------------------------- |
| Status      | in progress                                         |
| Recorded    | 2026-10-04                                          |
| Observed in | io-mon `87bc824d99fbd0c58ac6714310213ed7227bf78e`   |
| Area        | Linux shared-library binding and preload forwarding |

## Observed

The new vfork-frame test fails under Repro's enclosing monitor with exit 139.
Run `37170607503` at shared tooling `6e658c9` retains the exact private library,
C probe hashes and argument-free core backtrace. The failing process is
`/bin/sh`, before the probe's main function. Both the enclosing monitor and
private test monitor are loaded. Its stack contains roughly 349,000 repeated
calls to the private library's `dlsym@GLIBC_2.2.5`.

At the bottom, the private library's constructor calls the enclosing library's
`repro_monitor_shim_init`. That initializer reaches its getenv resolver, then
the private dlsym wrapper. The wrapper's call to the exported real-dlsym helper
can also bind to the enclosing image, whose next dlsym is that same wrapper.
Default ELF symbol preemption has connected the two images' private state.

Direct execution of the identical C ELF and private library succeeds, reports
both frame observations null and exits zero. This is a separate defect from
the earlier abandoned vfork frame; disabling Nim traces does not fix it.

## Expected and repair requirements

[Shim build policy](../docs/contributors/shim-build-policy.md) requires preserving
the host program's execution. Library-owned initialization and forwarding
helpers must bind to their owning image while public monitoring exports remain
available. Two distinct preloads must not call recursively through one another
before host main. Preserve hooks, monitoring policy and all frame assertions.

Qualify local function binding with the real two-image loader case, ordinary
symbol lookup and host execution, plus a failing original-binding control.
The enclosing Repro action must also pass unchanged. Do not infer independent
live multi-session evidence delivery from successful library initialization.

## Evidence

- Diagnostic `37170607503`, artifact `io-mon-87bc-repro-frame`: exact patch,
  full Repro report, SHA256 identities, direct result and symbolic backtrace.
  Raw cores were deleted on the disposable runner and not uploaded.
- Ordinary retry `37167428027` and full Repro `37167428001` independently fail
  the same frame action at `87bc824` after successful compilation.
- Refreshed `agents` at `f17733c` and searched current/deleted issue history for
  dlsym recursion and symbol preemption before filing. Existing ARM symbol-version
  and Linux runtime-policy records concern different defects.
