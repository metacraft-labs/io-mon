# Dependency identity fixture uses reserved variables and compares process timestamps

- Status: open
- Observed in: io-mon `26e7f08`, full native macOS catalog

## Observed and planned repair

The fixture uses IO*MON_DA1B_MARKER, although macOS intentionally excludes the IO_MON* control namespace. Its fact comparison also includes process start timestamps, which correctly differ between captures. Use a variable outside the control namespace and compare disFactScoped records, retaining the separate census of all record kinds. Expectation: Dependency-Attribution DA-1b distinguishes process identity from observer-independent facts.

Refreshed origin/dev and origin/agents; searched open issues and issue history
for the fixture names and failing expressions before recording.
