# Complete Windows Reprobuild tests expose fixture and monitor isolation failures

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Status      | open                                                       |
| Recorded    | 2026-09-28                                                 |
| Observed in | io-mon `73e4792`, Reprobuild `0d69de55`, Windows x64       |
| Area        | portable tests, Windows injection tests, nested monitoring |

## Evidence

[Native job 109024094897](https://github.com/metacraft-labs/io-mon/actions/runs/36450606215/job/109024094897)
passes the Reprobuild bootstrap and compiles the complete platform catalog.
Seven test programs fail during execution:

- Element-key source audits compare Windows backslashes with POSIX literals.
- Evidence-scope mutation probes cannot find LF anchors in CRLF checkouts.
- Synthetic breakaway fragments carry their own session IDs, but the merge
  falls back to the outer Reprobuild monitor's session and drops those records.
- The escape-shim fixture omits the production-required `-d:useMalloc`.
- Native read capture and the plain spawn probe fail calling the injected
  shim's runtime initializer on its parked main thread.
- The inert-shim root-guard fixture unexpectedly sees a process-start record
  and complete evidence.
- The abandoned-injection probe reports timeout while its child remains alive.

The last three symptoms are not yet attributed. The existing separate Windows
job runs only three selected programs; its success does not validate this
complete catalog. Compare the complete suite directly with the same suite
under Reprobuild before changing the injection or test execution contract.

## Expected

`repro.nim` defines the complete portable plus Windows catalog. The source
mutation tests require both successful mutations and intentional compile
failures. Normalize representation differences while keeping unique-anchor and
exact-source-site assertions. Give synthetic fragment merges their declared
session IDs. Build the escape fixture with the production allocation flags.

[Monitor-Hook-Shim](../../reprobuild-specs/Monitor-Hook-Shim.md) requires honest
root/descendant completeness. Retain native capture, child termination and
root-loss assertions; do not turn a missing record into complete evidence or
skip the failing programs. Any runtime repair needs real Windows execution.

Refreshed `origin/dev` at `279a17b` (already an ancestor of `73e4792`) and
searched open and deleted issues for Windows fixtures, nested monitoring and
CRLF before recording.
