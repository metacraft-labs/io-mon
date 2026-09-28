# macOS monitor fixtures overwrite a dylib used by concurrent tests

|             |                                                               |
| ----------- | ------------------------------------------------------------- |
| Status      | in-progress                                                   |
| Recorded    | 2026-09-28                                                    |
| Observed in | io-mon `980bdc7e80a2915c83bd6bf31af58fd11b6263d7`             |
| Area        | macOS fixture `buildShim` helpers and S1 FIFO process cleanup |

## Observed

The full macOS graph passes all 179 actions, but the required repeat of the
41 non-cacheable monitor programs fails several loaders and compilers.
`test_io_mon_macos_s1_channels` reports that the inserted
`build/lib/librepro_monitor_shim.dylib` does not exist. Other fixtures fail
`shim not produced` or linking in the shared compiler cache. These helpers
rebuild the same library and use the same intermediate directory concurrently.

The S1 FIFO fixture waits for its out-of-tree feeder before checking the
reader's exit status. When dyld rejects the reader, the feeder remains blocked
in `open(O_WRONLY)` with no reader. A sample of both actual processes confirms
this wait. Terminating only that verified test-owned feeder exposes the
reader failure. Local evidence: `/tmp/io-mon-worker-fd-repeat.json` and
`/tmp/io-mon-s1-feeder-sample.txt`.

## Expected and planned repair

[Release validation](https://github.com/metacraft-labs/metacraft-specs/blob/844a976/infrastructure/gosti-io-mon-runquota-releases.md)
requires every isolated fixture to actually execute successfully again.
Fixtures must own their build outputs. Share a private-build helper between
the macOS tests, cloning the environment and assigning per-process output and
compiler-cache directories. Clean up only those private directories at exit.
Keep every capture/completeness assertion and parallel execution.

Bound both FIFO child waits, retain reader diagnostics, and clean up the
feeder even when reader startup fails. Repeat the whole 41-program collection
and verify real launches; a successful first run alone is insufficient.

Before recording, dev `279a17b` was fetched and verified as an ancestor.
Open issues and deleted history were searched for shared shim builds and
FIFO feeder hangs. The Windows private-shim issue describes the analogous
Windows case; this file records the separate macOS fixture owners.
