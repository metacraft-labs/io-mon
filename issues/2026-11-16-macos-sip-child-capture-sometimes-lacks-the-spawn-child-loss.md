# A synchronous SIP child's capture sometimes lacks the "spawn child missing process-start" loss

|             |                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                                                                |
| Recorded    | 2026-11-16                                                                                                                                          |
| Observed in | io-mon `dev` @ `f62185c` (tree identical to `9b28a81`), CI run 43746664111, job 132911383455 (macos-arm64 — repro build/test), 2026-11-15 19:25 UTC |
| Area        | `tests/macos/test_io_mon_macos_tree_lifetime_guard.nim` case 8a; the macOS spawn-loss recording for a SIP-protected child                           |

## Observed

Case 8a ("a synchronous SIP child keeps the capture incomplete") failed at
line 563:

```text
Check failed: res.depFile.losses.anyIt("spawn child missing process-start" in it)
```

The capture was still graded incomplete and exited 0 (the two earlier checks
passed), so some other loss made it incomplete, but not the spawn-child loss
the case is about. The log does not print the losses that were recorded.

The same tree passed this case on PR #61 at `9b28a81`, and the rerun of the
failed job on the same commit passed. The failing run was on m3 while that
host was overloaded (load 20-50, `/nix` nearly full, all runners dropped
offline at 18:56 UTC), so host load is the likely trigger; see
[2026-11-08-macos-tree-guard-cannot-classify-young-processes-under-host-load.md](./2026-11-08-macos-tree-guard-cannot-classify-young-processes-under-host-load.md).

## Expected

A SIP-protected child that the monitor cannot instrument is always reported
as a "spawn child missing process-start" loss, whatever else the capture
records, so case 8a passes regardless of host load. If the loss can be
legitimately replaced by another one under load, the case should say which
and assert it; it should not depend on scheduling. A first step is to print
`res.depFile.losses` when the check fails, so the next occurrence shows what
was recorded instead.
