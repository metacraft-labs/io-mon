# On Linux, a failed `fopen` is recorded as a successful open

|             |                                                                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                                                                                                              |
| Recorded    | 2026-11-15                                                                                                                                                                                        |
| Observed in | io-mon `35829647` (the pin of reprobuild `agents` `b1961633da`), driven through reprobuild's `internal io monitor run` on Linux x86_64 (NixOS). The code below is unchanged at `agents` `5ecff95` |
| Area        | `src/io_mon/shim/linux_preload.nim`: `recordFopen` (called from `repro_hook_fopen` and `repro_hook_fopen64`)                                                                                      |

## Observed

The Nim compiler looks for `nim.cfg` and `<project>.nim.cfg` in the
project's directory and in every parent, with `fopen(…, "rbe")`. None of
those files existed. Each attempt was captured as:

```text
recordKind: file-open   result: 0   probeResult: prUnknown   detail: stdio:rbe
```

That record cannot be told apart from a successful `fopen` of an existing
file. A failed `open`/`openat` of the same path is recorded with a negative
result.

The cause is in the code. `recordFopen` sets `record.result = 0` for every
record it emits, whether or not `stream` is `nil`. Its doc comment says
this is deliberate ("Deliberately 0 and NOT `if stream == nil: -1 else:
0`"): a failed `fopen` was already encoded as 0 when the field held the
`FILE*`. Making the failure visible would move the reads-only evidence
gate, so the change was "recorded as a finding instead of changed in
passing". `docs/contributors/evidence-scope.md` §3 ("The predicate") and
the `mrFileOpen` arm of the predicate in `src/io_mon/types.nim` describe
the result: a failed `fopen` is **kept** as a read. The stated reason is
that 0 is also a legal descriptor, so dropping it could drop a real input.

So this is a known encoding with a stated trade-off ("over-keeping costs
records; under-keeping costs correctness"). It is filed because the cost is
no longer only extra records, and because the finding has had no open record
in this repository.

## Expected

Not specified. The current behaviour is documented as deliberate, not as
required, and its own comment calls it a finding. Proposed: a failed
`fopen` is recorded like a failed `open`/`openat`, with a negative result
(or `-errno`), or as an `mrPathProbe` with `prAbsent`. The macOS and Windows
shims already behave this way, because `fopen` reaches them as `open` /
`CreateFileW` and a failure carries a negative result or NTSTATUS. The
reads-only predicate's `mrFileOpen` arm would then classify a failed stdio
open as an absence, the same way it classifies a failed `open`. That is the
gate change the comment defers. Its tests would need to cover a successful
`fopen` that returns a stream on descriptor 0.

## Evidence

The record shape above comes from a capture of a Nim compile on Linux
x86_64 (NixOS) at io-mon `35829647`. Reprobuild took it while comparing a
dependency list derived from the io-mon capture with one derived from
strace. The strace-derived list was written. The io-mon-derived one was
refused on the five `nim.cfg` records. The capture was deleted with that scratch tree. It can be
reproduced with any program that `fopen`s a missing file under
`io-mon run`. The code citation is to `recordFopen` at `5ecff95`.

## Impact

- A consumer that takes `file-open` records as reads counts files that were
  never read. For invalidation this errs in the safe direction. A consumer
  that requires every recorded read to name an existing file has to refuse
  the capture instead.
- Reprobuild's dependency-list derivation is that kind of consumer. It reads
  each such record as a read of a file that does not exist, and fails
  closed, so on Linux it cannot use an io-mon capture of any program that
  probes for an optional file with `fopen`. Nim does this for every
  `nim.cfg` it looks for.

## Related

- [`docs/contributors/evidence-scope.md`](../docs/contributors/evidence-scope.md):
  the finding was first written down while working on Reprobuild's
  dependency attribution, as belonging to the evidence-scope axis, the one
  that decides which failed lookups (`recordIsFailedExistenceLookup`) are
  written down.
