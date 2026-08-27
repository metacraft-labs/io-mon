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

## 6. Completeness semantics

Disabling a category is a **consumer choice, not data loss** — so it does **not**
downgrade `mcComplete`. `mcIncomplete` still means "something we were asked to
capture was lost". A consumer that disables `ecNonDeterminism` and then a
non-deterministic read happens is `mcComplete` (it asked not to see it); a
consumer that keeps a category and loses an event is `mcIncomplete` as today.

## 7. Non-goals

- No per-*path* or per-*kind* filtering (categories only — keep it coarse).
- No dynamic re-configuration mid-run (interest is fixed at spawn).
- reprobuild wiring (opting out of `ecNonDeterminism`) is a separate change in
  reprobuild's monitored-action launch; this doc specifies io-mon's surface only.

## 8. Test plan

- Portable: `categoryOf` totality (every `MonitorRecordKind` maps or is
  explicitly meta); interest codec round-trip; `{}` normalises to `FullInterest`;
  unknown token ignored.
- Host filter: a synthetic record set with mixed categories + a disabled category
  yields a depfile without that category and with meta/loss intact and
  `mcComplete` preserved.
- Linux (gated): a real monitored run with `ecNonDeterminism` disabled produces a
  depfile with zero `mrEnvRead`/`mrTimeRead`/`mrSysctlRead`/`mrNonDeterministic`/
  `mrExternalContent` records, file/proc/lib deps intact, `mcComplete`.
