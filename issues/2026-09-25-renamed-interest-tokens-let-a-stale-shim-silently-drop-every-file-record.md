# Renaming the `REPRO_MONITOR_INTEREST` tokens lets a stale shim silently drop every file record under `mcComplete`

| | |
|---|---|
| Status | open |
| Recorded | 2026-09-25 |
| Observed in | io-mon @ `0c312f2` + the uncommitted `da-5-split-event-interest-categories-by-consumer` working tree |
| Area | `src/io_mon/types.nim` (`interestToken`, `parseInterestTokens`), `src/io_mon/fs_snoop.nim` (`childEnv`), `docs/contributors/event-interest-filter.md` §3 / §5 |

*Archive search per
[recording-issues.md](../../metacraft-dev-guidelines/policies/recording-issues.md)
§"Searching the archive", run in this repo: `git log --diff-filter=D --name-only
-- issues/` is empty (nothing resolved yet); `git log -i -S'REPRO_MONITOR_INTEREST'
-- issues/` and `git log --all -- 'issues/*interest*' 'issues/*windows*'` return
nothing. Not previously recorded.*

## Observed

The DA-5 split gives six of the eight `EventCategory` members NEW wire tokens
(`file-reads`, `path-probes`, `file-writes`, `env`, `entropy`, `ambient`), and
`childEnv` writes those tokens into the child's `REPRO_MONITOR_INTEREST`
unconditionally — including for the default `FullInterest`, which is what every
invocation that passes no `--interest` flag sends.

A shim built before the rename recognises only `proc` and `lib` in that value.
`parseInterestTokens` ignores the six it does not know (the documented
forward-compat rule), so the shim's `gInterest` becomes
`{ecProcessTree, ecLibraryLoads}` and its `emitRecord` gate suppresses every
file read, every probe, every write, every env read and the IPC connect —
**for a caller that asked for everything.**

Measured on Linux, one `socat UNIX-LISTEN` peer started outside the monitored
tree, the same command line and the same C fixture in all three runs. Only the
shim differs; **no `--interest` flag is passed in any of them**:

```
A) new CLI + new shim
   iomon version=1 records=20 completeness=mcIncomplete
   summary records=20 processes=1 observations=19 eventLoss=1
   1 backend-profile  9 capability-gap  1 env-read  1 event-loss
   1 file-open  1 file-read  1 ipc-connect  2 library-load
   1 process-spawn  1 process-start  1 time-read

B) new CLI + shim built at 0c312f2 (pre-rename)
   iomon version=1 records=14 completeness=mcComplete
   summary records=14 processes=1 observations=14 eventLoss=0
   1 backend-profile  9 capability-gap  2 library-load
   1 process-spawn  1 process-start
                                       <- no file-open, no file-read, no
                                          ipc-connect, no event-loss

C) CLI at 0c312f2 + new shim   (the reverse skew)
   iomon version=1 records=20 completeness=mcIncomplete   -- unaffected
```

Arm B's depfile is not merely short; it is **affirmatively wrong about
itself**:

```
interest=file-reads,path-probes,file-writes,proc,lib,env,entropy,ambient
evidenceComplete=true
completeness=mcComplete
```

It states FULL scope, claims complete evidence, and carries no `mrEventLoss`,
over a record set with **zero file dependencies**. A consumer keyed on
`observedInterestCovers(dep, FullInterest)` accepts it. That is the false
`mcComplete` the interest axis is built to refuse, reached with no flag and no
adversary.

Passing an explicit request does not change it: `--interest file,proc,lib`
against the same stale shim produces the identical 14 records / `mcComplete`,
because the host re-encodes the request into the new vocabulary before it
reaches the child.

## Expected

The repo states the invariant this breaks, in the file the rename edits. Both
passages below are PRE-EXISTING text, unchanged by the split: they were true at
`0c312f2`, because no interest token had ever been renamed, and the rename is
what stops them being true while leaving them in place.

`parseInterestFlag`'s own doc comment:

> A value naming NO known token at all is refused instead: that **cannot be
> version skew (skew keeps the tokens it already had and adds one)**, it is an
> operator typo […]

`docs/contributors/event-interest-filter.md` §3:

> An unknown token is ignored (forward-compat: an older shim silently treats a
> new category as "not in my set" — **safe, because the host also filters,
> §5**).

and §5:

> an older shim that does not honour the env still yields a correctly-filtered
> result (the host is the source of truth)

The host filter only ever **removes** records (`fs_snoop.nim`, the block after
`mergeFragments`); it cannot restore one the shim never emitted. So "the host is
the source of truth" holds for *over*-capture by a shim that ignores the
variable, and does not hold for *under*-capture by a shim that honours it in a
vocabulary the host no longer speaks. The forward-compat rule is sound only
while every release keeps the tokens it already had — which is exactly what the
`parseInterestFlag` comment asserts and what renaming six of eight tokens
stops being true.

The narrower expectation, in the terms this project already uses: **a narrowing
is safe on the depfile READ axis and unsafe on the env WRITE axis, and only the
read axis was accounted for.** DA-5's §3.2 pays for old-bytes→new-reader
(narrower, never wider ⇒ rejection ⇒ cost). New-host→old-shim is the same
"narrower" and there it means dropped records under `mcComplete`.

## Evidence

Reproduction, both shims built from their own isolated tree copies
(`scripts/build_shim.sh`, `IO_MON_BUILD_MODE` default, own `--nimcache` and
`XDG_CACHE_HOME` each):

```sh
# peer started OUTSIDE the monitored tree
socat UNIX-LISTEN:/tmp/peer.sock,fork SYSTEM:'cat >/dev/null' &

# the monitored tool: reads a file, getenv, time(), connect()s to the peer
REPRO_MONITOR_SHIM_LIB=<new>/build/lib/librepro_monitor_shim.so \
  <new>/io-mon-cli run --depfile a.iomon -- ./ipc_client input.txt /tmp/peer.sock
REPRO_MONITOR_SHIM_LIB=<0c312f2>/build/lib/librepro_monitor_shim.so \
  <new>/io-mon-cli run --depfile b.iomon -- ./ipc_client input.txt /tmp/peer.sock

<new>/io-mon-cli inspect a.iomon --format text
<new>/io-mon-cli inspect b.iomon --format text
```

The record set in arm B is exactly what the pre-rename token table predicts:
`{ecProcessTree, ecLibraryLoads}` plus the META kinds, i.e. `process-start`,
`process-spawn`, `library-load`, `backend-profile`, `capability-gap`. The
prediction and the measurement agree kind for kind, so the mechanism is not
inferred.

Reachability is not exotic. `findShimLibrary` resolves
`$REPRO_MONITOR_SHIM_LIB` first and then the canonical `build/lib` layout, and
`nim c cmd/io_mon_snoop.nim` does not rebuild the shim — so a developer who
rebuilds the CLI and not the shim, or a tree with a `build/lib` from before the
rename, lands in arm B with no warning. Whether reprobuild can reach it
depends on whether its host and shim always come from one io-mon store path;
not checked here (reprobuild was not touched, `44ce07a0`).

## Suggested direction

Not specified by any document in this repo; the options differ in what they
cost, and the trade-off should be decided rather than defaulted:

- **Emit the legacy token beside the canonical ones whenever a legacy
  category's members are ALL requested.** `FullInterest` would go out as
  `…,ambient,file,nondet,ipc`. An old shim then reads a superset-or-equal of
  the correct set, over-captures, and the host filter narrows it — the safe
  direction, and the exact mirror of the read-side alias rule. Cost: the value
  gets longer, and two current cases assert the child's value verbatim
  (`t_a_pre_DA5_command_line_still_works_and_is_re_encoded_for_the_child`,
  `t_the_safe_subset_is_expressible_on_the_command_line`).
- **Make the shim treat "recognised nothing, and the value was non-empty" as
  `FullInterest`.** One line, fails toward over-capture, and needs no change to
  what the host writes — but it only helps shims built *after* the fix, so it
  does nothing for the shims already on disk today.
- **Version the channel** (`REPRO_MONITOR_INTEREST_V2`, or a
  `REPRO_MONITOR_ABI` the shim must match). Most explicit, most moving parts.
  Note the second bullet's limitation applies here too.

Whatever is chosen, §3's "safe, because the host also filters" and
`parseInterestFlag`'s "skew keeps the tokens it already had and adds one"
should be corrected: the first is false for a shim that honours the variable in
an older vocabulary, and the second is the assumption a token rename retires.

## Related

- `docs/contributors/event-interest-filter.md` §3, §3.2, §5 — the alias rule
  that covers the depfile read direction and not this one.
- `docs/contributors/evidence-scope.md` §"the host is the source of truth" —
  the `REPRO_MONITOR_EVIDENCE` channel has the same shape but not the same
  exposure: a shim predating it ignores it and over-captures, and no
  `EvidenceScope` token has ever been renamed.
- `issues/2026-09-24-codec-memory-safety-is-graded-by-nothing.md` — unrelated
  defect, same repo.
