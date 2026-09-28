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

## Direct Windows comparison

At `1cabd874115573fce23e7533b1a4b33d515afc1e`, [job 109054198659](https://github.com/metacraft-labs/io-mon/actions/runs/36459498969/job/109054198659) passes 41 of 42 programs directly, including all native injection, root-guard, child-termination and host-session tests. The remaining eight assertions are in the evidence-scope compiler diagnostic reader: `Stream.readAll` stops on the first short Windows pipe read, retaining only `stack trace: (most recent call last)`.

Drain the pipe to EOF and keep every exact rejection assertion and both successful-compilation controls. This direct result does not yet clear the nested Reprobuild execution failures.

At `303e1ef`, direct job `109065572161` passes all 368 assertions in the
complete 42-program Windows catalog. Reprobuild job `109066010867` at the same
product SHA fails host-session scope, read capture, root guard, abandoned
injection and resume invariant. The outer shim supplies hooks even when the
inner root-guard fixture chooses inert `kernel32.dll`.

The recipe repair isolates these five execution edges using the existing
generated-depfile policy, suppresses the outer shim seed, and marks them
non-cacheable. Their compiles and all other tests retain normal monitoring.
CI repeats the five after the complete suite and checks the real execution
report to prove they launched and passed again. Windows execution is pending.
