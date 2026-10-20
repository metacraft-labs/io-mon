# Linux shim tests fail when `repro test` runs them under the monitor

|             |                                                                                         |
| ----------- | --------------------------------------------------------------------------------------- |
| Status | in-progress (nixos-ci-bare-002:fix-linux-shim-tests-fail-under-repro-test-m) |
| Recorded    | 2026-10-18                                                                              |
| Observed in | io-mon @ `0d7a07d` (`agents`), CI `Test (reprobuild, linux-x64)`                        |
| Area        | `tests/linux/test_io_mon_shim_*`, `tests/linux/test_io_mon_linux_host_entry_points.nim` |

## Observed

CI run [39126325916](https://github.com/metacraft-labs/io-mon/actions/runs/39126325916)
(`workflow_dispatch` on `agents` at `0d7a07d`) ran the suite twice on
linux-x64. `Test (nix)` (`just test`) failed only
`t_every_real_function_slot_is_primed`, which is already recorded in
`2026-10-17-linux-underscore-fork-slot-is-not-primed.md`. `Test (reprobuild)`,
which runs `REPRO_MONITOR_SHIM_LIB=<current-source monitor> repro test`,
failed 12 cases:

- `test_io_mon_linux_host_entry_points.nim`: `t_raw_getdents64_records_the_enumeration`,
  `t_raw_getdents64_on_an_inherited_fd_is_attributed`,
  `t_unknown_raw_syscall_still_fails_closed` (completeness `mcComplete`,
  expected `mcIncomplete` with `unsupported nr=`)
- `test_io_mon_shim_fork_child_evidence.nim`: `t_raw_clone_child_reports_skipped_evidence`
  (`o.missing == 1`, `o.skippedLoss` fail)
- `test_io_mon_shim_host_allocator_isolation.nim`: `t_host_runs_without_shim`
  (`"host shim-loaded=0" in bare.output` fails),
  `t_break_owning_host_keeps_its_break_and_its_pointers`,
  `t_host_allocator_lock_never_reentered`, `t_every_real_function_slot_is_primed`
- `test_io_mon_shim_path_mutations.nim`: `t_path_mutations_are_recorded_and_results_preserved`
- `test_io_mon_shim_private_heap.nim`: `t_private_heap_survives_signals_forks_and_raw_clones`
  (`release, LD_PRELOAD only` and `release, monitored` exit 1)
- `t_small_stack_threads_survive_preload_and_monitoring`,
  `t_node_starts_under_preload_and_monitoring`

`t_host_runs_without_shim` shows the likely mechanism: its "bare" control,
which runs the host with no io-mon shim, reports a shim loaded. Under
`repro test` the outer monitor's preload is inherited by the test's own
children, so the controls are not bare and the shim under test is loaded a
second time beside the outer one. Every failing file was added on
2026-10-15 or 2026-10-16 (first added by `cb1db14`, `51228b5`, `6453936`,
`7b6f7d2` and `f33311e`). The last green CI
run, on `agents-to-dev-2026-10-13` at `3cc29a65`, predates them, and `agents`
has no CI triggers, so this first showed on the dispatch above.

## Expected

`docs/contributors/building-and-testing.md` § "Run the full suite" gives
`just test` and `repro test` as equivalent ways to run the full suite, and
`.github/workflows/ci.yml` requires the `Test (reprobuild)` job. A test must
pass under both, or own its monitor environment (strip the inherited preload
for its bare and monitored children) as the isolated programs of
`repro build .#test-monitor-isolation` do.

## Evidence

The job log of `Test (reprobuild, linux-x64)` in the run above. The failure
is not caused by `0d7a07d` or its parents back to `727725d`: those commits
change only a dev-shell test, docs, the CI dev-shell step and a flake input
whose `repro.lock` pin (`nim-shm-queue@a3564c13`, the sibling CI cloned) was
already in place.
