# Linux environment fixture discovers a shim another test is relinking

|             |                                                   |
| ----------- | ------------------------------------------------- |
| Status      | in-progress                                       |
| Recorded    | 2026-09-29                                        |
| Observed in | io-mon `c88183bf51a96289ff6e690f7720294b1f334a7a` |
| Area        | Linux per-call environment test fixture           |

## Observed

[Linux Reprobuild job 109427598946](https://github.com/metacraft-labs/io-mon/actions/runs/36574798134/job/109427598946)
passes 124 actions and fails the parent-environment case in
`test_io_mon_per_call_env_and_cwd`. The loader reports
`build/lib/librepro_monitor_shim.so ... file too short`; the real reader exits
zero but capture is incomplete and lacks its input read. The other three cases
pass. Several concurrent Linux fixtures rebuild this same library and cache.

The parent-environment case deliberately removes every injection variable,
including the shim override, so its reader uses canonical library discovery.
An override would invalidate that experiment. The earlier macOS fixture issue
(`5c503d8`, resolved by private builds) describes the analogous output race;
this Linux discovery case was not covered by that repair.

## Expected and repair

[Per-call environment contract](../../reprobuild-specs/IoMon-Decomposed-Host-API.milestones.org)
requires monitored launches to leave the parent environment unchanged.
[Shim discovery](../docs/usage.md) supports the executable-relative `../lib`
layout. Run this fixture from its own real executable copy beside a private
production shim and compiler cache. Preserve normal discovery, all absent-env,
concurrency, completeness and input-evidence assertions, and parallel execution.
Use the existing private-build helper with a Linux variant; do not mutate the
shipping shim or weaken capture completeness.

Before recording, fetched dev `9c1d52b`, verified it is an ancestor, and searched
open and deleted issues for partial libraries, shared builds and concurrency.

A second independent [job 109431799681](https://github.com/metacraft-labs/io-mon/actions/runs/36576003727/job/109431799681)
at the same `c88183bf` fails `test_io_mon_evidence_scope_shim_gate`: its final
future-scope arm loads the same partially written shared library and records
zero of the 400 required failed lookups. Give this fixture and the other two
unmonitored Linux fixtures that still use the shipping shim (library closure
and fragment descriptor reuse) private outputs too. The older-shim mutation
fixture and host-session fixture already own private builds. Ordinary monitored
fixtures retain the enclosing monitor's explicit immutable shim pin; the
per-call case deliberately clears that pin, hence its separate layout.

## Remaining fixture ownership failures at `3df08c2`

Native-workflow Reprobuild job `109666724409` in run `36645226098` fails two
programs. The new shared-producer growth regression loads the shipping shim
while another fixture relinks it: the loader reports `invalid ELF header`,
the fork arm retains only eight child paths rather than 16,392 total paths,
and capture is incomplete. Give its default capture a private production
shim, while preserving an explicit shim override for the old/new control.

The older-shim fixture recursively copies `.repro`, including transient
monitor depfiles deleted during the copy. It fails before assertions with
`No such file or directory`. Copy only its required source/configuration
inputs; the mutation build does not consume the build engine's working state.
Keep all mutation, capture and completeness assertions. Refreshed dev
`9c03325` and searched current and archived fixture issues before extending
this record.

## Observation-fold fixture at `53994c0`

Post-merge Linux Reprobuild [job 109820421857](https://github.com/metacraft-labs/io-mon/actions/runs/36694888720/job/109820421857)
at `53994c0ca76f263ff04f046b2f99d98a038d41f3` fails
`test_io_mon_dep_identity_scope` after its first three cases pass. The
file-transport case logs fourteen loader refusals for the canonical
`build/lib/librepro_monitor_shim.so`: `file too short`. Its fan-out runs but
records zero processes instead of thirteen and no library/environment facts.
The fixture rebuilds and discovers that shared output even though its
transport-owning execution correctly runs outside the enclosing monitor.
Other concurrently executing fixtures still rebuild the same path.

Use the existing private production-shim builder on both POSIX hosts and
pass its exact path through the fixture's existing request environment.
Retain every transport, process-count, identity and completeness assertion,
as well as parallel execution. The published product binaries are unchanged.
Before extending this record, fetched dev `53994c0`, searched current issues
and the deleted-issue history for partial libraries and shared builds, and
confirmed this is the same ownership defect.
