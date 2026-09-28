# Linux predicate test links the whole interposition runtime

|             |                                                                         |
| ----------- | ----------------------------------------------------------------------- |
| Status      | open                                                                    |
| Recorded    | 2026-09-29                                                              |
| Observed in | io-mon `de755e5`, job `109087129022`; source still present at `1aeab2c` |
| Area        | Linux mapping predicate unit test                                       |

The Linux ARM64 Reprobuild run remains at 119/120 actions for over an hour.
Its cancellation cleanup identifies the remaining child as
`test_io_mon_inline_patch_predicate`. That test imports
`io_mon/hooks/linux_preload_runtime` for three mapping-policy functions. The
import also links C interposers such as `open`, `fopen` and `dlsym`, and requires
a fake `repro_linux_sig_safe_flush` body to link a test of mapping policy.

[Monitor-Hook-Shim](../../reprobuild-specs/Monitor-Hook-Shim.md) requires the
outer monitor to observe the test faithfully. A mapping-policy test should
exercise the actual policy without adding its own unrelated libc interposers.
Move the shared policy functions into a focused module, import and re-export
it from the runtime, and have the existing test import it directly. Keep all
assertions and the normal monitored execution policy. Remove the link-only
flush stub; real interposition remains covered by the Linux integration suite.

The exact nested-CI hang has not yet been reproduced in isolation. A direct
and CLI-monitored probe at `d7f0453` both pass all 10 cases on Linux ARM64:
[diagnostic run](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36483883057).
That probe uses the product Nix compiler rather than the source-bootstrap
compiler, so it does not clear the stalled Reprobuild run. Removing the
unnecessary runtime dependency must still be validated through that full graph.

Refreshed dev `279a17b` and searched current/deleted issues for predicate,
preload-runtime and nested Linux monitoring defects before recording.
Evidence: `/tmp/io-mon-de755-linux-arm-repro.log` and
`/tmp/io-mon-linux-predicate-baseline/`.
