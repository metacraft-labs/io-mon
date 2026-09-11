# io-mon Event-Interest Filter

**Status:** draft (for review).
**Motivation.** A consumer often does not care about every class of observation
io-mon can capture. reprobuild's build engine wants file, process-tree and
library-load dependencies; it does **not** care that a monitored tool read the
clock, the environment, a sysctl, or some other non-deterministic source. Today
io-mon installs the hooks for all of that and spends resources detecting,
constructing and publishing those records into the gset regardless. This feature
lets a consumer declare which **event categories** it wants, so io-mon skips the
work for the rest.

## 1. Categories

A single enum over `MonitorRecordKind`, grouping the *observation* kinds a
consumer can opt in/out of:

```nim
type EventCategory* = enum
  ecFileDeps       ## mrFileOpen, mrFileRead, mrFileWrite, mrPathProbe,
                   ## mrDirectoryEnumerate, mrPathMutation
  ecProcessTree    ## mrProcessStart, mrProcessExec, mrProcessSpawn
  ecLibraryLoads   ## mrLibraryLoad
  ecNonDeterminism ## mrNonDeterministic, mrTimeRead, mrEnvRead, mrSysctlRead,
                   ## mrExternalContent
  ecIpc            ## mrIpcConnect
```

`categoryOf(kind: MonitorRecordKind): Option[EventCategory]` maps a record kind
to its category. Kinds with **no** category are META and are **never gated**:
`mrEventLoss` (LF-1 — loss markers must always flow, or a dropped input becomes a
false `mcComplete`), `mrBackendProfile`, `mrCapabilityGap`. Gating a loss marker
is forbidden by construction: `categoryOf(mrEventLoss) == none`, and the gate
only ever suppresses kinds whose category is *present and disabled*.

## 2. Request API

`FsSnoopRequest` gains:

```nim
interest*: set[EventCategory]   ## default: FullInterest (all categories)
```

`const FullInterest* = {EventCategory.low .. EventCategory.high}`. A zero/`{}`
interest is normalised to `FullInterest` on ingest, so an unset field never
silently disables everything (the safe default is "capture all", matching current
behaviour). The public host API (`runMonitored`/`startMonitor`) carries it
through unchanged.

## 3. Reaching the shim

The shim is a separate injected library; it learns the interest set the same way
it learns the fragment dir / dep-shm segment — an env var on the child spawn,
composed in `childEnv` alongside the other `REPRO_MONITOR_*` variables (never via
`putEnv` on the host):

```
REPRO_MONITOR_INTEREST = <comma-separated category tokens>   # e.g. "file,proc,lib"
```

Tokens: `file` `proc` `lib` `nondet` `ipc`. Absent/empty ⇒ all (back-compat). An
unknown token is ignored (forward-compat: an older shim silently treats a new
category as "not in my set" — safe, because the host also filters, §5).

### 3.1 The variable is io-mon's channel, NOT the caller's — hence `--interest`

`childEnv` writes `REPRO_MONITOR_INTEREST` **after** it has applied both
`request.env` and the injected pairs, because io-mon's injection has to WIN: a
caller who could set `REPRO_MONITOR_SHIM_LIB` (or this) in the child's
environment could silently disarm monitoring. The consequence is easy to miss
and cost a live defect in reprobuild: **an out-of-process consumer cannot reach
the shim through the environment at all.** It may put
`REPRO_MONITOR_INTEREST` in the environment of `io-mon run` / `repro internal io
monitor` all it likes; that process's own request carries `{}` → `FullInterest`,
and `childEnv` writes that over the caller's value before the child ever starts.

So the CLI takes the request as an ARGUMENT, which io-mon does not overwrite:

```
io-mon run --interest file,proc,lib --depfile out.iomon -- <command>
```

Same vocabulary, same codec (`interestToTokens` / `parseInterestTokens`), so the
flag and the env variable are one wire format with one implementation. **An
absent flag, or an empty value, means all categories** — every existing caller
keeps the behaviour it has, and a consumer that wants a reduction has to ask for
it on each run. That asymmetry is deliberate: forgetting costs capture work,
never a missed dependency. A value that names at least one known token and also
an unknown one is accepted with the unknown token ignored (§3's forward-compat
rule, which now also covers a NEWER consumer talking to an OLDER io-mon); a
value that names **no** known token is refused as an operator typo rather than
silently widened to "all", because silently widening is the same discard the
flag exists to end.

## 4. Where the work is skipped (two levels)

1. **Recording (always).** The shim reads `REPRO_MONITOR_INTEREST` at init into a
   global `set[EventCategory]`. The emit funnels — `recordObservedNonFile` and the
   file/process/library emitters — return early when the record's category is
   disabled, *before* constructing the record and publishing it to the gset. This
   removes the expensive part (record build + shm insert + dedup) for unwanted
   categories. The hook still fires but does almost nothing.
2. **Hook installation (where cheap to gate).** Where a whole hook exists ONLY to
   feed one gate-able category (e.g. the `getenv`/`time`/`sysctl` non-determinism
   hooks), installation itself is skipped when that category is disabled, so the
   interposed function is not even wrapped. File/process/library hooks are always
   installed (they serve always-plausible categories and share machinery).

## 5. Host-side filter (belt-and-suspenders)

`collectMonitorEvidence` drops any record whose category is present-and-disabled
before it reaches the depfile, so:
- an older shim that does not honour the env still yields a correctly-filtered
  result (the host is the source of truth), and
- the invariant "the depfile contains only categories the consumer asked for"
  holds regardless of shim version.
`mrEventLoss`/meta are never dropped.

## 5.1 The depfile SAYS which categories were requested (DA-1j)

The merge stamps the host's normalized interest onto the backend-profile record
(`interest=file,proc,lib`), so a capture's scope travels with it. Read it through
the accessor, **never** through the raw field:

```nim
let dep = readMonitorDepFile(path)
if not observedInterestCovers(dep, {ecFileDeps, ecIpc}):
  discard  # this evidence answers a narrower question than we asked
```

`observedInterest` on its own is ambiguous and resolving it with
`normalizeInterest` is the trap this accessor exists to remove. `{}` arises three
ways and they do not mean the same thing:

| file | `observedInterestStated` | `effectiveObservedInterest` | full-scope consumer |
|---|---|---|---|
| no stamp (written before DA-1j, or a caller that stated no scope) | `false` | `FullInterest` | ACCEPT — unchanged from before the field existed |
| stamp naming categories this build knows | `true` | those categories | ACCEPT iff they cover the requirement |
| stamp naming **only** categories this build cannot name (`interest=gpu`, from a newer io-mon) | `true` | `{}` | **REJECT** — the file states a scope this build cannot evaluate |
| stamp whose VALUE is empty (`interest=`) | `true` | `{}` | **REJECT** — same reason, and it needs its own answer: `parseInterestTokens` widens `""` to `FullInterest`, which is right for the env channel (an unset `REPRO_MONITOR_INTEREST` means "capture everything") and a false ACCEPT here |

The last two rows are the ones that matter for a wire format: each is a NARROWED capture,
and reading it as full scope would republish the false complete this stamp exists
to end, pointing forward in time. `observedInterestTokens` keeps the raw stamp so
the unevaluable scope can be named in a diagnostic rather than merely detected.

The stamp is **not** a completeness input and **not** a cache-key component:
full-scope evidence is strictly stronger than narrowed evidence, so a narrow-scope
consumer must still be able to accept a full capture.

## 5.2 A DIFFERENT axis: evidence scope (DA-1i)

`--evidence=reads-only` narrows a capture too, and it is **not** expressible
here. It drops the lookups that found NOTHING, which is a predicate on a
record's RESULT; every category in §1 gates on its KIND, and success is not a
kind. Measured on one `nim c`: dropping every failed lookup leaves 23,049
records, while gating a probes *category* leaves 41,736 — discarding 2,066
successful probes and keeping 20,753 failed opens.

The two axes are **composed, never conflated**, and each is stamped separately
so a consumer can evaluate one without the other. See
[evidence-scope.md](evidence-scope.md).

## 6. Completeness semantics

> **This rule has a measured exception. Read §7's caveat before relying on it:
> `ecIpc` and `ecNonDeterminism` are completeness-BEARING, and disabling either
> turns an `mcIncomplete` edge into an `mcComplete` one.**

Disabling a category is a **consumer choice, not data loss** — so it does **not**
downgrade `mcComplete`. `mcIncomplete` still means "something we were asked to
capture was lost". A consumer that disables `ecNonDeterminism` and then a
non-deterministic read happens is `mcComplete` (it asked not to see it); a
consumer that keeps a category and loses an event is `mcIncomplete` as today.

## 7. Non-goals

- No per-*path* or per-*kind* filtering (categories only — keep it coarse).
- No dynamic re-configuration mid-run (interest is fixed at spawn).
- reprobuild wiring is a separate change in reprobuild's monitored-action
  launch; this doc specifies io-mon's surface only. Recorded here because it
  bears on how coarse these categories can afford to be: reprobuild's engine
  now asks for **every** category, having found that `ecNonDeterminism` carries
  `mrEnvRead` (which reaches its action-cache key) and `mrNonDeterministic`
  (which gates cache publication).
- **A caveat on §6, and it is a correctness one.** Two gate-able kinds are
  *completeness-bearing*: `mrIpcConnect` (`ecIpc`) and `mrExternalContent`
  (`ecNonDeterminism`). `mergeFragments` turns each out-of-tree IPC peer
  (`unmonitoredSubtreeLossDetails`) and each unpaired external content channel
  (`externalContentLossCount`) into a synthetic `mrEventLoss`, which is what
  forces `mcIncomplete`. The shim's gate drops those records at `emitRecord`,
  BEFORE `mergeFragments` runs, so disabling either category does not merely
  hide records the consumer did not want — it turns an `mcIncomplete` edge into
  an `mcComplete` one. §6's "disabling a category is a consumer choice, not
  data loss" holds for the other kinds and does not hold for these two: the
  loss markers are never gated, but they are also never generated. A consumer
  that wants a safe reduction needs either finer categories than these five, or
  these two kinds made ungate-able alongside `mrEventLoss`.

  **MEASURED for `ecIpc`, on Linux, with the built shim and CLI.** One
  `socat UNIX-LISTEN` peer started OUTSIDE the monitored tree, and the same
  monitored command (`socat -u - UNIX-CONNECT:<sock>`) run twice:

  | run | completeness | eventLoss | records |
  |---|---|---|---|
  | `io-mon run` (all categories) | `mcIncomplete` | 1 | 32 |
  | `io-mon run --interest file,proc,lib` | **`mcComplete`** | 0 | 23 |

  The loss record the full run carries is `unmonitored subtree/peer … IPC
  connect to an out-of-tree breakaway daemon`. Reducing the interest did not
  hide a record the consumer had declined to see; it published a **false
  clean** for an edge whose real inputs came from a daemon io-mon never
  watched — the cardinal sin, reached by asking the monitor not to look. The
  `mrExternalContent` half of the caveat is established by source reading
  only: this Linux build advertises `external-content` as a non-required
  capability gap, so the fixture that would exercise it emits no record here.

## 8. Test plan

- Portable: `categoryOf` totality (every `MonitorRecordKind` maps or is
  explicitly meta); interest codec round-trip; `{}` normalises to `FullInterest`;
  unknown token ignored.
  (`tests/portable/test_io_mon_event_interest.nim`.)
- Portable, §3.1: the CLI flag parses in both spellings and on both grammars,
  and the value it parses REACHES `childEnv`'s `REPRO_MONITOR_INTEREST` — the
  whole chain, not just the parsed field, since the parsed field was always
  honoured on the in-process path and the chain is where the request was being
  dropped. Absent flag ⇒ all; a caller's `request.env` entry loses to the flag;
  an all-unknown value is refused.
  (`tests/portable/test_io_mon_cli_interest_flag.nim`.)
- Host filter: a synthetic record set with mixed categories + a disabled category
  yields a depfile without that category and with meta/loss intact and
  `mcComplete` preserved.
- §5.1, read side: a stamp round-trips through the real envelope; an unknown
  token beside known ones does not poison it; a stamp naming ONLY unknown
  categories is `stated` and reads as `{}`, so a full-scope consumer rejects it,
  and so does a stamp whose VALUE is empty; while an ABSENT stamp still reads as
  `FullInterest` and is accepted.
  (`tests/portable/test_io_mon_observation_identity_fold.nim`.)
- §5.1, write side, LIVE: the real CLI runs twice on one command, once at full
  interest and once narrowed, and the two depfiles it wrote state the two scopes
  that were asked for — the only case that grades the stamp end to end. Deleting
  the stamp write, or the `!= {}` guard on it, reddens it.
  (`tests/posix/test_io_mon_cli_interest_stamp.nim`.)
- Linux (gated): a real monitored run with `ecNonDeterminism` disabled produces a
  depfile with zero `mrEnvRead`/`mrTimeRead`/`mrSysctlRead`/`mrNonDeterministic`/
  `mrExternalContent` records, file/proc/lib deps intact, `mcComplete`.
