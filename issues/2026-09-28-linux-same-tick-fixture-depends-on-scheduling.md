# Linux descendant fixture cannot reliably arrange equal process start ticks

- Status: open
- Observed in: io-mon `c68fb31`
- Area: `tests/linux/test_io_mon_descendant_scan_start_time_prune.nim`

## Observed

[Linux CI](https://github.com/metacraft-labs/io-mon/actions/runs/36379927407/job/108793396362)
executes all 12 attempts, but root and descendant always land in different
kernel clock ticks. Every live descendant is correctly reported incomplete,
and the quiescent control is complete. The fixture's `sameTickSeen` assertion
fails because loader and monitor initialization take longer than one tick.

## Expected and repair

The filesystem monitoring spec's §4.1 descendant-completeness rule requires
that a process with an equal start tick remains eligible for scanning. It
does not require the scheduler to create two particular processes in one tick.
Extract the actual strict comparison into a pure function and test earlier,
equal, later and unavailable timestamps directly. Retain the real detached
process test and quiescent control, and ensure a `<` to `<=` mutation fails.

Refreshed origin/dev (`279a17b`) and origin/agents (`c68fb31`); searched open
issues and issue history for same-tick and start-time-prune findings.
