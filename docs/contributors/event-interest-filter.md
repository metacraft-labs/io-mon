# io-mon Event-Interest Filter

**Status:** draft (for review). Categories split by consumer in **DA-5**.
**Motivation.** A consumer often does not care about every class of observation
io-mon can capture. reprobuild's build engine wants file, process-tree and
library-load dependencies; it does **not** care that a monitored tool read the
clock or a sysctl. io-mon installs the hooks for all of that and spends
resources detecting, constructing and publishing those records into the gset
regardless. This feature lets a consumer declare which **event categories** it
wants, so io-mon skips the work for the rest.

## 1. Categories

A single enum over `MonitorRecordKind`. **One category per CONSUMER, not per
syntactic family** — that is DA-5's rule and the reason the enum looks the way
it does:

```nim
type EventCategory* = enum
  ecFileReads      ## mrFileOpen, mrFileRead
  ecPathProbes     ## mrPathProbe, mrDirectoryEnumerate
  ecFileWrites     ## mrFileWrite, mrPathMutation
  ecProcessTree    ## mrProcessStart, mrProcessExec, mrProcessSpawn
  ecLibraryLoads   ## mrLibraryLoad
  ecEnvReads       ## mrEnvRead
  ecEntropy        ## mrNonDeterministic
  ecAmbientReads   ## mrTimeRead, mrSysctlRead
```

| category | token | the consumer it exists for |
|---|---|---|
| `ecFileReads` | `file-reads` | the INPUT CONTENT set (`PathSetEvidence.monitorReads`) — what the staleness detector re-hashes and the strong fingerprint is taken over |
| `ecPathProbes` | `path-probes` | the EXISTENCE / MEMBERSHIP set (`monitorProbes`, `monitorDirectoryEnumerations`) — invalidated by a path being *added*, which a content hash cannot see |
| `ecFileWrites` | `file-writes` | the OUTPUT set (`monitorWrites`) and output-tree state tracking |
| `ecProcessTree` | `proc` | process-tree attribution: pid→image, subtree/breakaway analysis, the executed binary as a content dependency |
| `ecLibraryLoads` | `lib` | the loaded-object closure of the tool |
| `ecEnvReads` | `env` | the ACTION CACHE KEY (`monitorEnvReads` → `cacheEnvInputs`) |
| `ecEntropy` | `entropy` | the CACHE-PUBLISH GATE (`entropyObservations` → `applyEntropyBlessingPolicy`) |
| `ecAmbientReads` | `ambient` | **nothing, today.** Clock and sysctl reads reach reprobuild's record fold and land on its `else: discard` arm. This is the one category a reprobuild edge can drop without losing anything a consumer reads |

### 1.1 What the split replaced, and why "coarse" was not the problem

The five pre-DA-5 categories were `ecFileDeps` / `ecProcessTree` /
`ecLibraryLoads` / `ecNonDeterminism` / `ecIpc`. They grouped record kinds that
*look* alike, and the result was a switch no consumer could use.
`ecNonDeterminism` alone carried `mrEnvRead` (cache key), `mrNonDeterministic`
(publish gate), `mrTimeRead` / `mrSysctlRead` (no consumer at all) and
`mrExternalContent` (completeness) — **four consumers behind one bit.** So no
non-empty proper subset of those categories was safe to request, reprobuild's
engine asked for every category unconditionally, and its `captureNonDeterminism`
/ `captureIpc` policy fields were documented as `INERT`.

The fix is not "more categories". It is that a category is now the unit a
*single* consumer reads, so a narrowing can be argued one consumer at a time.

### 1.2 Two classes of kind have NO category and are never gated

`categoryOf(kind: MonitorRecordKind): Option[EventCategory]` maps a record kind
to its category, and `none` means **no interest set may suppress this record**:

- **META** — `mrEventLoss` (LF-1: loss markers must always flow, or a dropped
  input becomes a false `mcComplete`), `mrBackendProfile`, `mrCapabilityGap`.
- **COMPLETENESS-BEARING** — `mrIpcConnect` and `mrExternalContent`.
  `mergeFragments` *derives* a synthetic `mrEventLoss` from each out-of-tree IPC
  peer (`unmonitoredSubtreeLossDetails`) and each unpaired external-content
  channel (`externalContentLossCount`), and the shim's gate runs at
  `emitRecord`, **before** that merge. Gating these kinds therefore does not
  hide a record the consumer declined to see — it deletes the input a loss
  marker would have been derived from, turning an `mcIncomplete` edge into an
  `mcComplete` one. No granularity makes that safe, so there is no category:
  DA-5 retired `ecIpc` rather than renaming it. (The `ipc` token still *reads*;
  see §3.2.)

Gating a loss marker is forbidden by construction: `categoryOf` answers `none`,
and the gate only ever suppresses kinds whose category is *present and
disabled*. `recordIsFailedExistenceLookup` asks the same `categoryOf`, so the
evidence axis inherits the identical protection from one definition.

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
REPRO_MONITOR_INTEREST = <category tokens>,legacy-padding,<pre-DA-5 tokens>
                         # e.g. "file-reads,proc,lib,legacy-padding,file,nondet,ipc"
```

Tokens: `file-reads` `path-probes` `file-writes` `proc` `lib` `env` `entropy`
`ambient`, then the back-compat padding §3.3 describes. Absent/empty ⇒ all
(back-compat). An unknown token is ignored — forward-compat: a shim silently
treats a category it has no name for as "not in my set".

**That ignore rule is safe in ONE direction only, and this paragraph used to
claim both.** It read "safe, because the host also filters, §5". That is true for
a shim which ignores the variable *entirely* and therefore over-captures: the
host filter removes what the consumer did not ask for and the result is correct.
It is **false** for a shim which honours the variable in an OLDER vocabulary.
Such a shim ignores the tokens it does not know, keeps the ones it does, and
emits a **narrower** set than asked for — and the host filter cannot repair that,
because it only ever REMOVES records (§5) and can never restore one the shim
never emitted. The result is a depfile that is short and says it is complete.

DA-5 made that reachable with no flag at all by renaming six of the eight tokens.
Measured on Linux, one out-of-tree `socat` peer, same command line, no
`--interest`, only the shim differing: current shim 20 records / `mcIncomplete`;
a shim built at `0c312f2` **14 records / `mcComplete` / no file records at all**,
over a depfile stating `interest=file-reads,…,ambient` and
`evidenceComplete=true`. §3.3 is what closes it, and the honest general statement
is: **the host filter makes over-capture safe and does nothing at all for
under-capture, so nothing may ever make a shim capture less than the host asked
for.**

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
io-mon run --interest file-reads,proc,lib --depfile out.iomon -- <command>
```

Same vocabulary, one decoder (`parseInterestTokens`), and — since §3.3 — two
encoders, because the depfile stamp and the env value have opposite safe
directions. The flag's value and the child's `REPRO_MONITOR_INTEREST` are
therefore not expected to be the same string. **An
absent flag, or an empty value in either spelling (`--interest ""` and
`--interest=` alike), means all categories** — every existing caller keeps the
behaviour it has, and a consumer that wants a reduction has to ask for it on
each run. The two spellings are one flag: `parseRun` dispatches on the argument's
PRESENCE (`arg.startsWith("--interest=")`), because a dispatch on the value's
length cannot tell `--interest=` from an argument that is not `--interest` at
all, and sending it to the catch-all told the operator the flag does not exist
when only its value was missing. That asymmetry is deliberate: forgetting costs capture work,
never a missed dependency. A value that names at least one known token and also
an unknown one is accepted with the unknown token ignored (§3's forward-compat
rule, which now also covers a NEWER consumer talking to an OLDER io-mon); a
value that names **no** known token is refused as an operator typo rather than
silently widened to "all", because silently widening is the same discard the
flag exists to end.

**Adding an `EventCategory` whose wire token cannot be read back is a compile
error.** `interestToken` is an exhaustive `case`, `interestToTokens` and
`parseInterestTokens` are both derived from it rather than from a table of
pairs, and a `static:` block asserts over the whole enum that every category has
a token which is non-empty, carries neither the value's `,` separator nor the
record-detail's `;`, and decodes back to exactly that category. The table of
pairs this replaced was policed by nothing: a category added without a row
compiled, and every `interest=` stamp thereafter silently omitted it.

The harm on this axis is **strictly lesser** than on the evidence axis, and the
difference is worth being precise about rather than glossing. A missing token can
only *shrink* what a stamp declares, and `observedInterestCovers` is a subset
test, so every consequence points at **rejection**: a capture that really did
observe the new category is read as one that did not, and a consumer needing it
recaptures for nothing. It cannot produce the opposite mistake, because a
category this build cannot spell is also one it cannot be asked for. On the
evidence axis the same omission produces a depfile every consumer refuses, or —
with a duplicated token — one a full-evidence consumer wrongly **accepts**. That
asymmetry is the reason this axis was closed second, not a reason to leave it
open. Graded by the compile-refusal cases in
`tests/portable/test_io_mon_evidence_scope.nim`, alongside the evidence axis's.
That change (DA-1j) was wire-neutral: the enum's declaration order was the order
the array had, and the encoding was measured identical over all 32 subsets in
both directions.

**DA-5's change is NOT wire-neutral, deliberately,** and §3.2 is where that is
paid for. Six of the eight tokens are new spellings, because a capture stamped
`file` covered reads, probes and writes together and reading it as any one of
them would widen a narrowed stamp. `proc` and `lib` keep their spellings because
those two categories did not split, so reuse states an exact equivalence rather
than a loose one. The codec round-trip is measured over all **256** subsets, and
both wire directions over real depfile bytes
(`tests/portable/test_io_mon_observation_identity_fold.nim`).

### 3.2 The pre-DA-5 tokens still READ, as aliases

`file` `proc` `lib` `nondet` `ipc` are still accepted, on the flag and on the
env channel, and they expand to today's categories:

| old token | expands to | note |
|---|---|---|
| `file` | `ecFileReads`, `ecPathProbes`, `ecFileWrites` | |
| `proc` | `ecProcessTree` | unsplit — this IS the current token |
| `lib` | `ecLibraryLoads` | unsplit — this IS the current token |
| `nondet` | `ecEnvReads`, `ecEntropy`, `ecAmbientReads` | `mrExternalContent` became ungate-able |
| `ipc` | *nothing* | `mrIpcConnect` became ungate-able |

**The expansions are DERIVED from `categoryOf`, never written down.** The
alternative is the one construction on this axis whose failure direction is
ACCEPT: give `file` an expansion containing `ecEnvReads` and every old
`--interest file,proc,lib` capture — which observed no environment read — reads
back as though it had. Computing the expansion from where the kinds *actually*
went makes that unwritable, and a `static:` block recomputes it at compile time
and refuses a mismatch. `legacyMemberKinds` is frozen history and must never be
"updated" to match a later `categoryOf`.

Why keep them at all: an old depfile stamped `interest=file,proc,lib,nondet,ipc`
observed **everything**, and a build that could not read those tokens would
grade it as stating a scope it cannot evaluate and re-run correct work.

**`interestToTokens` never emits them, and that is a property of the DEPFILE
STAMP specifically** — asserted over all 256 subsets. A stamp is a claim a
consumer compares against its own requirement, so the failure direction of an
over-stated stamp is ACCEPT; emitting `file` beside `file-reads` would make an
old consumer read "reads, probes and writes were all observed" off a capture that
may have observed only one of the three. Nothing this build writes into a depfile
is spelled in a vocabulary whose meaning it no longer controls.

The env channel is the mirror image, and §3.3 is why it needs its own encoder.

A value naming **only** retired categories (`--interest ipc`) is refused with
its own diagnostic rather than the typo one: the token is spelled correctly and
there is simply nothing this build can be asked to do with it.

**Adding a category whose token collides with a legacy alias is a compile
error**, and it needs the legacy half of the `static:` block to catch it. A new
category spelled `file` is caught by the canonical round-trip too, but one
spelled `ipc` is not — `parseInterestTokens("ipc")` really would be exactly that
new category — and only the derived-expansion assertion refuses it. Measured;
both arms are graded in `tests/portable/test_io_mon_evidence_scope.nim`.

**The token↔legacy-category PAIRING is pinned separately from the expansion**,
because none of the above can see it. Every assertion in the legacy half is
quantified over the legacy category and re-derives both sides from the same
table, so SWAPPING the `file` and `nondet` spellings satisfies all of them — and
every old `interest=file,proc,lib` depfile then reads as having observed
environment reads and entropy, which is exactly the false accept the derivation
was introduced to make unwritable. The derivation guarantees the *expansion*, not
the *pairing*.

The pairing is frozen history, so it cannot be derived from anything in today's
code. It is instead pinned to something no edit to the table can move: **the
names of the record kinds each legacy category gated.** Each shipped token is a
case-insensitive substring of at least one of its own members' identifiers
(`file`/`mrFileOpen`, `proc`/`mrProcessStart`, `lib`/`mrLibraryLoad`,
`nondet`/`mrNonDeterministic`, `ipc`/`mrIpcConnect`) and — the part that makes it
a proof rather than a coincidence — it is the **only** shipped token that is. The
witness relation is therefore a bijection, the shipped pairing is the unique one
satisfying it, and **any permutation of the five spellings fails to compile.**
Renaming a `MonitorRecordKind` out from under a legacy category fails it too,
which is correct: that is the other way this table can quietly stop describing
the bytes it claims to describe.

### 3.3 The env channel carries the pre-DA-5 spellings TOO — `interestToShimTokens`

The stamp and the env value are one vocabulary with **two encoders**, because the
two channels have opposite safe directions:

| channel | reader | harm | so the encoder |
|---|---|---|---|
| depfile `interest=` stamp | a consumer comparing scope against its requirement | over-stating ⇒ **false accept** | emits canonical spellings only (`interestToTokens`) |
| `REPRO_MONITOR_INTEREST` | a shim deciding what it may decline to observe | under-stating ⇒ **records that never exist** | emits canonical spellings **plus** the pre-DA-5 ones (`interestToShimTokens`) |

The rule is derived, not written down: a legacy token is emitted exactly when the
legacy category it names contains a record kind this interest wants —

```
emit legacyInterestToken(L)   iff   legacyMemberKinds(L) ∩ wanted ≠ {}
```

— where `wanted` is `recordWanted` over every kind, so the ungate-able kinds
(`mrIpcConnect`, `mrExternalContent`) count as wanted always and `ipc` and
`nondet` are therefore emitted for **every** interest set. That is deliberate:
those two kinds are what `mergeFragments` derives its synthetic event-loss markers
from, so an old shim that gates them away is precisely the false `mcComplete` this
axis exists to refuse.

**Why this direction is safe, in two lines.** Let `K` be the kinds the host wants
and `E` the kinds an old shim emits under this value. Take any `k ∈ K`. Either the
old vocabulary classed `k` as META, in which case no vocabulary ever gated it and
`k ∈ E`; or `k` lay in some legacy category `L`, and then
`legacyMemberKinds(L) ∩ K ∋ k` is non-empty, so `L`'s token is emitted and
`k ∈ E`. Hence **`E ⊇ K` for every interest set** — the old shim over-captures,
never under-captures, and the host filter (§5) narrows `E` back to exactly `K`.
Asserted over all 256 sets, with the canonical-only encoder as the negative
control: that encoder — what shipped before this fix — under-captures on **193**
of the 256, `FullInterest` among them.

**The weaker rule is not enough.** "Emit the token when ALL of a legacy category's
members are requested" is a strict subset of the rule above. It repairs the
default (`FullInterest` requests every member of every legacy category, so both
rules emit everything) and leaves the flagged case broken: under it
`--interest file-reads` sends `file-reads,ipc`, an old shim recognises only `ipc`,
and the capture returns with no file records under a stamp saying
`interest=file-reads`. DA-5's own safe subset (`FullInterest - {ecAmbientReads}`)
would likewise lose `mrEnvRead`, which keys the action cache.

**`legacy-padding` is the fence, and it is not a version number.** A CURRENT shim
shares the alias arm with the depfile decoder, so without a fence it would read
the padding as a widening and `--interest` would quietly stop narrowing anything.
`interestToShimTokens` therefore emits the canonical spellings, then
`LegacyPaddingToken`, then the padding; `parseInterestTokens` drops the alias arm
once it has seen the fence. A shim that predates the fence ignores it under the
same forward-compat rule that makes the padding necessary — which is the point,
because that rule is the only behaviour a binary already on disk can be relied on
to have. No historical value carries the fence (`interestToTokens` does not emit
it, no pre-DA-5 build knew it, and `--interest` refuses it), so every value that
ever existed decodes exactly as it always did.

**And the shim widens a value it cannot read at all.** `shimInterestFromEnv`
reads a non-empty value naming nothing this build knows as `FullInterest` rather
than as `{}`. That is the opposite of what `--interest` does with the same input,
deliberately: there an operator is present and refusal is available, here the
reader is inside a monitored process and its only choices are to observe or not.
It is **not** what fixed the defect above — that shim recognised `proc` and `lib`
and was confidently wrong — but it is the second line of defence for the next
vocabulary change, including one that retires `proc` or `lib`.

## 4. Where the work is skipped

**Recording, at the emit funnel.** The POSIX shims read `REPRO_MONITOR_INTEREST`
at init into a global `set[EventCategory]` and consult it at exactly ONE site
each — `emitRecord` in `shim/linux_preload.nim` and in `shim/macos_interpose.nim`
— returning early when the record's category is disabled, *before* constructing
the record and publishing it to the gset. That removes the expensive part
(record build + shm insert + dedup) for unwanted categories. The hook still
fires but does almost nothing.

Two things this section used to claim that are **not** true of the code, stated
here rather than left for the next reader to discover:

- **There is no hook-INSTALL gating on any platform.** An earlier draft of this
  document described skipping installation for hooks that feed only one
  gate-able category (`getenv` / `time` / `sysctl`). Verified by sweep:
  `gInterest` has exactly one reader per shim and it is the emit funnel, so
  every hook is installed regardless of interest and the saving is the record
  build, not the interposition. Worth having; not yet built.
- **The Windows shim does not honour the variable at all.** `REPRO_MONITOR_INTEREST`
  appears nowhere in `shim/windows_interpose.nim`. A narrowed Windows capture is
  correct anyway — the shim over-captures and the host filter (§5) removes what
  was not asked for, which is the one direction that filter can fix — but it pays
  the full recording cost. Note that this is the *safe* half of the ignore rule:
  a Windows shim that started honouring the variable would join the class §3.3
  exists for.

## 5. Host-side filter (belt-and-suspenders)

`collectMonitorEvidence` drops any record whose category is present-and-disabled
before it reaches the depfile, so:
- an older shim that does not honour the env at all, or honours it and
  over-captures, still yields a correctly-filtered result, and
- the invariant "the depfile contains only categories the consumer asked for"
  holds regardless of shim version.

`mrEventLoss`/meta are never dropped.

**"THE HOST IS THE SOURCE OF TRUTH" IS TRUE OF WHAT THE DEPFILE CONTAINS AND
FALSE OF WHAT IT IS MISSING**, and the two used to be stated as one. This filter
runs after `mergeFragments` and its only operation is to **remove** records. So:

| the shim emits | the host filter | result |
|---|---|---|
| more than asked for | removes the excess | **correct** — the guarantee above |
| exactly what was asked for | removes nothing | correct |
| **less** than asked for | **cannot restore anything** | a short depfile that says it is complete |

The third row is not hypothetical and is not an adversary: it is what a shim
honouring `REPRO_MONITOR_INTEREST` in an older token vocabulary does. §3 has the
measurement — 14 records graded `mcComplete`, with no file records at all, from a
shim six commits behind its host — and §3.3 is the encoder that removes the row.

The rule to carry away: **this filter licenses over-capture and buys nothing
against under-capture.** Anything that makes a shim observe LESS than the host
asked for has to be correct on its own; there is no second line of defence
downstream.

## 5.1 The depfile SAYS which categories were requested (DA-1j)

The merge stamps the host's normalized interest onto the backend-profile record
(`interest=file-reads,proc,lib`), so a capture's scope travels with it. Read it through
the accessor, **never** through the raw field:

```nim
let dep = readMonitorDepFile(path)
if not observedInterestCovers(dep, {ecFileReads, ecEnvReads}):
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
| **pre-DA-5 stamp** naming only OLD tokens (`interest=file,proc,lib,nondet,ipc`) | `true` | the derived expansion — here `FullInterest` | ACCEPT iff it covers the requirement. §3.2; the expansion is computed from `categoryOf`, so it can never name a category the old capture did not observe |

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

DA-5 introduced `ecPathProbes`, which IS the probes category that table prices,
and that does not change the sentence above. The two axes are **composed, never
conflated**: a record is written iff its category is wanted AND its result is in
scope. Each is stamped separately so a consumer can evaluate one without the
other. See [evidence-scope.md](evidence-scope.md).

## 6. Completeness semantics

Disabling a category is a **consumer choice, not data loss** — so it does **not**
downgrade `mcComplete`. `mcIncomplete` still means "something we were asked to
capture was lost". A consumer that disables `ecEntropy` and then a
non-deterministic read happens is `mcComplete` (it asked not to see it); a
consumer that keeps a category and loses an event is `mcIncomplete` as today.

**This rule used to have a measured exception, and DA-5 removed the exception
rather than the rule.** Until the split, `ecIpc` and `ecNonDeterminism` were
completeness-BEARING and disabling either turned an `mcIncomplete` edge into an
`mcComplete` one. Those two kinds are now ungate-able (§1.2), so **no interest
set can move the grade**, and the rule above holds for every category without a
caveat. §7 keeps the measurement, because it is what the rule now rests on.

## 7. Non-goals

- No per-*path* or per-*kind* filtering (categories only — keep it coarse).
- No dynamic re-configuration mid-run (interest is fixed at spawn).
- reprobuild wiring is a separate change in reprobuild's monitored-action
  launch; this doc specifies io-mon's surface only. Recorded here because it
  bears on how coarse these categories can afford to be. Before DA-5,
  reprobuild's engine asked for **every** category, having found that
  `ecNonDeterminism` carried `mrEnvRead` (which reaches its action-cache key)
  and `mrNonDeterministic` (which gates cache publication) behind one bit.
  After DA-5 those are `ecEnvReads` and `ecEntropy`, separately requestable, and
  exactly one category — `ecAmbientReads` — has no consumer on that side. io-mon
  does not make reprobuild's decision for it; it now makes one expressible.
- **The §6 caveat that USED to live here, and what closed it.** Two gate-able
  kinds were *completeness-bearing*: `mrIpcConnect` (`ecIpc`) and
  `mrExternalContent` (`ecNonDeterminism`). `mergeFragments` turns each
  out-of-tree IPC peer (`unmonitoredSubtreeLossDetails`) and each unpaired
  external content channel (`externalContentLossCount`) into a synthetic
  `mrEventLoss`, which is what forces `mcIncomplete`. The shim's gate drops
  those records at `emitRecord`, BEFORE `mergeFragments` runs, so disabling
  either category did not merely hide records the consumer did not want — it
  turned an `mcIncomplete` edge into an `mcComplete` one.

  The caveat itself named the two possible fixes: "finer categories than these
  five, or these two kinds made ungate-able alongside `mrEventLoss`". DA-5 took
  **both**, and deliberately did not take only the first: finer categories alone
  would have left a smaller switch with the same failure mode, since the harm
  comes from the records not existing at merge time and not from how many other
  kinds share their bucket. `categoryOf` now answers `none` for both, so the
  measurement below is a record of what was fixed rather than a live hazard.

  **MEASURED for `ecIpc`, on Linux, with the built shim and CLI, BEFORE DA-5.**
  One
  `socat UNIX-LISTEN` peer started OUTSIDE the monitored tree, and the same
  monitored command (`socat -u - UNIX-CONNECT:<sock>`) run twice:

  | run | completeness | eventLoss | records |
  |---|---|---|---|
  | `io-mon run` (all categories) | `mcIncomplete` | 1 | 32 |
  | `io-mon run --interest file,proc,lib` (pre-DA-5 vocabulary) | **`mcComplete`** | 0 | 23 |

  **AND RE-MEASURED ON THE SAME SHAPE AFTER DA-5** (2026-09-25, Linux, this
  build's shim and CLI, one `socat UNIX-LISTEN` peer started outside the
  monitored tree, three sequential arms against one live listener):

  | run | completeness | eventLoss | records | `mrIpcConnect` |
  |---|---|---|---|---|
  | `io-mon run` (all categories) | `mcIncomplete` | 1 | 31 | 1 |
  | `--interest file-reads,path-probes,file-writes,proc,lib` | `mcIncomplete` | **1** | 26 | **1** |
  | `--interest file,proc,lib` (the alias) | `mcIncomplete` | **1** | 26 | **1** |

  The same command line that used to publish a false clean now keeps the
  `mrIpcConnect` record and the `mrEventLoss` derived from it, and grades
  `mcIncomplete`. What the narrowing drops is `mrEnvRead` / `mrSysctlRead` /
  `mrTimeRead` — five records — which is what a narrowing is supposed to drop.
  The alias arm is byte-for-byte the same capture as the explicit one and is
  stamped `interest=file-reads,path-probes,file-writes,proc,lib`.

  The loss record the full run carries is `unmonitored subtree/peer … IPC
  connect to an out-of-tree breakaway daemon`. Reducing the interest did not
  hide a record the consumer had declined to see; it published a **false
  clean** for an edge whose real inputs came from a daemon io-mon never
  watched — the cardinal sin, reached by asking the monitor not to look. The
  `mrExternalContent` half of the caveat is established by source reading
  only: this Linux build advertises `external-content` as a non-required
  capability gap, so the fixture that would exercise it emits no record here.
  Both kinds are covered by the same fix regardless, because the fix is at
  `categoryOf` and not at either kind's emission site.

## 8. Test plan

- Portable: `categoryOf` **exhaustiveness** — the expectation is itself an
  exhaustive `case` over `MonitorRecordKind` written out one kind per arm, so a
  kind added later cannot compile until it states its own answer; the
  ungate-able set asserted equal in both directions; every category reachable
  from some kind; LF-1 over **all 256 interest sets × the five ungate-able
  kinds**, with the gate-able complement checked so "never dropped" is not
  passing because nothing is; the codec round-tripping over all 256 subsets;
  every legacy alias expanding to the image of its frozen kind list under
  `categoryOf`; and the safe subset (`FullInterest - {ecAmbientReads}`) dropping
  exactly `mrTimeRead` / `mrSysctlRead`.
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
  the stamp write, or the `!= {}` guard on it, reddens it. Plus DA-5's live
  alias arm: the real binary run with the PRE-SPLIT spelling
  (`--interest file`) captures the same thing and stamps the depfile in TODAY's
  vocabulary, so the alias is proved to be read-side only across the whole
  argv → env → shim → merge → bytes chain.
  (`tests/posix/test_io_mon_cli_interest_stamp.nim`.)
- §3.2, both WIRE DIRECTIONS over real depfile bytes: every new token
  round-trips through the real envelope (with a negative control for an
  unrecognised one, which must read `stated`/`{}`/verbatim and be rejected);
  an old `interest=file,proc,lib,nondet,ipc` still reads as full scope; an old
  `interest=file,proc,lib` reads narrowed and is NOT widened onto `ecEnvReads` /
  `ecEntropy` / `ecAmbientReads`; and the new vocabulary read through the
  pre-DA-5 token table yields `{proc, lib}` — narrower, never wider.
  (`tests/portable/test_io_mon_observation_identity_fold.nim`.)
- Linux (gated): a real monitored run with `ecEnvReads`, `ecEntropy` and
  `ecAmbientReads` disabled produces a depfile with zero
  `mrEnvRead`/`mrTimeRead`/`mrSysctlRead`/`mrNonDeterministic` records,
  file/proc/lib deps intact, `mcComplete` — and with the `mrExternalContent` and
  `mrIpcConnect` records STILL PRESENT, because they are no longer gate-able.
- §3.3, the ENV channel's encoder, over **all 256 interest sets**: the padding
  rule is exactly "the legacy category holds a wanted kind"; a pre-DA-5 shim
  under-captures on **none** of the 256 (the canonical-only encoder, as a
  negative control, under-captures on **193**, `FullInterest` among them); every
  fully-requested legacy category is named, so the weaker "ALL members" rule is
  strictly contained; the value round-trips through this build's own decoder, so
  the fence keeps the padding away from a current shim; and no value that ever
  existed carries the fence. Plus `shimInterestFromEnv` widening an unreadable
  value to `FullInterest` while still honouring a real narrowing.
  (`tests/portable/test_io_mon_event_interest.nim`,
  `tests/portable/test_io_mon_cli_interest_flag.nim` — whose child-value cases
  assert those PROPERTIES rather than a literal, because a literal passed
  throughout the defect.)
- §3.2, the token↔legacy-category PAIRING, by compile refusal: swapping the
  `file` and `nondet` spellings is refused, naming `lecFileDeps`, and **not** by
  the expansion assertions — which that mutation satisfies. Alongside the two
  existing alias-theft refusals and their negative controls.
  (`tests/portable/test_io_mon_evidence_scope.nim`.)
