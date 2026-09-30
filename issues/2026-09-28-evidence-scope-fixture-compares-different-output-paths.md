# Evidence-scope fixture compares commands with different output paths

- Status: open
- Observed in: io-mon `ffcec83`

## Observed

The macOS full suite now reaches `test_io_mon_cli_evidence_scope` after the
Nimble TLS repair. Its equality assertion compares successful lookup keys
for `full.out` with keys for `narrow.out`. Both captures correctly include
those different write-open paths. They each have six successful keys and
differ only in the two spellings (`/tmp` and `/private/tmp`) of that output.

## Expected and repair

The test implements the evidence-scope contract: reads-only removes failed
existence probes while retaining successful lookups. Its own stated fixture
is two captures of the same command. Use the same output path for both,
removing it before each run; keep exact set and record-count equality.

Origin/dev (`279a17b`) and agents (`ffcec83`) were refreshed. Searched open
issues and issue history for `fullOk` and CLI evidence-scope failures.
