# Monitor-isolation CI expects an outdated macOS program count

Status: open.

## Observed

At io-mon `65486cb15e0657e33a1299bd00bc3e164202586d`, the Reprobuild workflow
sets `EXPECTED_ISOLATED_TESTS` to 42 on macOS. Its recipe now selects 45
uncached execution programs: the added syscall-ABI, preload-library and nested
handoff regressions each require their own monitor environment. The full local
report at `b9c733032d22828d86fd5a26931c4a723cc877a5` already contains those
45 dependency actions and successful execution programs. The workflow did not
update its count when those tests were added.

The repeat-execution step in CI job `111186938772` has failed, but its available
log is truncated before the terminal diagnostic. The count mismatch is proven
from the source and local report; it is not yet established as the only CI
failure in that step.

## Expected

[LOCAL-3 and LOCAL-4](https://github.com/metacraft-labs/metacraft-pm/blob/4bf621126eb87ce70b303a922a62df57870bd3f1/infrastructure/tool-release-local-followups.md)
require isolated uncached execution and preserved coverage. The repeat gate
must require all 45 current macOS programs to launch and succeed. Keep the
existing nine Linux and eight Windows program requirements. Preserve the
repeat report as a failure artifact so an inventory or execution failure can
be diagnosed even when console output is incomplete.

## Evidence and archive search

Fetched implementation `agents@6b545a7`; it includes only a new issue beyond
`65486cb`, with the same recipe and workflow. Searched open and resolved issue
history for `EXPECTED_ISOLATED_TESTS` and monitor-isolation inventory. The
existing live-fixture isolation issue concerns runtime evidence, not this
stale workflow count. Local report:
`/tmp/io-mon-nested-handoff-final-repro.json`.
