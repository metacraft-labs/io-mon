# io-mon Evidence Scope (`--evidence`)

**How much of what the monitor observes gets written down.** A different axis
from the [event-interest filter](event-interest-filter.md), and the difference
is structural rather than one of degree.

Read this before touching `recordIsFailedExistenceLookup`,
`recordInEvidenceScope`, `emitRecord`'s gate in `src/io_mon/shim/linux_preload.nim`,
or the host-side filter at the end of `collectMonitorEvidence`.

---

## 1. Why it cannot be an `EventCategory`

`--evidence=reads-only` means "record only the lookups that FOUND something".
The obvious implementation — split `ecFileDeps` and gate a *probes* category —
does not deliver it, and the gap was measured on one `nim c`:

| | records |
|---|---|
| total | 66,996 |
| drop every FAILED lookup — what `reads-only` MEANS | **23,049** |
| gate a probes *category* instead | 41,736 |

The category gate discards **2,066 successful probes** it should keep and leaves
**20,753 failed `mrFileOpen`s** it should drop.

> **`reads-only` is a predicate on the RESULT of a lookup. `EventCategory` gates
> on its KIND, and success is not a kind.**

So the two axes are **composed, never conflated**: a record is written iff
`recordWanted(interest, rec.kind)` **and** `recordInEvidenceScope(scope, rec)`.

## 2. The vocabulary

| token | `EvidenceScope` | meaning |
|---|---|---|
| `full` | `esFull` (the zero value) | every observation, including failed lookups |
| `reads-only` | `esReadsOnly` | drop failed **existence** lookups |
| *(none — not producible)* | `esUnrecognized` | READ SIDE ONLY: a depfile states a scope this build cannot name |

One vocabulary and one codec (`evidenceScopeToken` / `parseEvidenceScopeToken`)
for all three channels: the `--evidence` flag, the `REPRO_MONITOR_EVIDENCE`
environment variable, and the `evidence=` stamp in the depfile.

`esFull` is deliberately the **zero value**, so a zero-initialised
`FsSnoopRequest` and a depfile written before this existed both mean "full" with
no special case anywhere.

**Adding a member to `EvidenceScope` whose wire token cannot be read back is a
compile error, not a runtime surprise.** `evidenceScopeToken` is an exhaustive
`case` (so a forgotten member does not compile), `parseEvidenceScopeToken` is
derived from that one function rather than from a second table (so the two
directions of the codec cannot drift), and a `static:` block below the decoder
asserts, over the whole enum, that `esUnrecognized` is the *only* member whose
token is empty **and that every other member's token survives a round trip
through the wire**.

The reason is specific: the write side in `mergeFragments` stamps any scope that
is neither `esFull` nor `esUnrecognized`, so a member the codec cannot spell
ships a stamp no consumer can evaluate. Four shapes were measured on real
depfile bytes, and *only the first* is the one an emptiness check catches:

| token arm | compiles? | what reaches the depfile |
| --- | --- | --- |
| *(no arm)* | **no** — `case` is exhaustive | — |
| `""` | **no** — the emptiness assertion | bare `;evidence=`, read as *stated and unevaluable*, refused by every consumer including one asking for exactly that scope, residual **unnameable** |
| `"writes;only"` | **no** — the wire-safety assertion | the stamp rides inside a `;`-joined record detail, so the decoder splits on `;` first: read as `esUnrecognized` with the residual **misnamed** `writes` |
| `"full"` (a duplicate) | **no** — the round-trip assertion | decodes to the *first* member holding the token, so the narrowed capture reads back as `esFull` and a full-evidence consumer **accepts** it |

`"writes;only"` is the instructive one: it is non-empty *and* round-trips in
memory, so it passed both the emptiness assertion and the runtime enum case, and
the whole suite stayed green while the depfile was unreadable. **Non-empty was
never the property; the round trip is.**

Making the write-side guard test the token instead of the value does not help
and was measured to be worse: the stamp is then omitted, the capture reads as
*not stated*, and a full-evidence consumer **accepts** a narrowed capture. With
the assertions above the two spellings are provably the same predicate, so
neither is load-bearing by itself. Graded by the compile-refusal cases in
`tests/portable/test_io_mon_evidence_scope.nim`, each with two negative controls
(the unmutated codec compiles; a member *with* a good token compiles).

The interest axis carries the identical construction — see
[event-interest-filter.md](event-interest-filter.md).

## 3. The predicate

`recordIsFailedExistenceLookup` is the single definition of what `reads-only`
removes, so the shim gate and the host filter cannot disagree about it.

**META and loss kinds are excluded BY CONSTRUCTION.** The first line asks
`categoryOf` — the one definition of what META is — before looking at anything
else, so an `mrEventLoss` can never answer `true` and no META kind added later
can start answering `true` by being forgotten. A narrowing that could drop a loss
marker would manufacture a false `mcComplete` out of a capture that lost data
(LF-1).

**Lookups that did not succeed.** Only the three EXISTENCE lookups qualify:

| kind | dropped when |
|---|---|
| `mrPathProbe` | `probeResult == prAbsent`, or `prUnknown` with a negative result (the Windows `NtCreateFile` / `NtQueryAttributesFile` arms) |
| `mrFileOpen` | `result < 0` |
| `mrDirectoryEnumerate` | `result < 0` |

**NOT "proven absences", and the difference is measurable.** An earlier draft of
this section, and of the predicate's own comment, said the gate drops *absences*
and keeps *errors*. The record shape cannot draw that line:

- `record.result` is the raw call return — **`-1` for every `open` failure**,
  whatever the reason;
- `probeFromResult` stamps **`prAbsent` on every non-zero `stat` return**;
- **no errno reaches `MonitorRecord`.** There is no field for it.

So `result < 0` and `prAbsent` mean *the call failed*, never *the path is
absent*. Four shapes where the path **exists** are dropped, measured: `EACCES` (a
mode-000 `open`), `EISDIR`, `EACCES` on a `stat` through a no-exec directory, and
`ELOOP`. Magnitude on a real `nim c`: **5 of 2,104** dropped records name an
existing path (all `/dev/tty`, `ENXIO`).

That is a deliberate narrowing, not a defect to be papered over — `reads-only`
keeps the lookups that found something *usable*, which is what a
compiler-emitted depfile carries — but it costs a staleness blind spot, and that
blind spot is **row 4 of the hazard table in §8**.

**Why the distinguishing fact is not carried, so that it is a choice.** The
option is errno, or at minimum an ENOENT/ENOTDIR-vs-everything-else bit. The
**wire would not object to a version bump**: the `.iomon` envelope carries only
records (`depFileFromOwnedRecords` reconstructs the rest), so **no version bump
and no format break** would be needed. Two costs decided it, and both are stated
more narrowly than they were, because the first version of each was checkable
and wrong:

1. **Three backends — and the cost is not where this used to put it.** This
   bullet used to say macOS "must capture errno before any intervening libc call
   clobbers it". The capture is **already there**, on every backend, at exactly
   the required position, put there for an unrelated reason (preserving the
   tracee's errno across the hook): `linux_preload` takes `c_get_errno()`,
   `macos_interpose` `getErrno()` and `windows_interpose` `GetLastError()` on
   the line *after* the real call and *before* anything that could clobber it —
   one Windows probe site's comment already reads "`ERROR_FILE_NOT_FOUND` on
   absent path". What would actually have to be built is two other things:

   - **Plumbing, not capture.** The saved value is a *local in the hook*, while
     the record is built a frame or two down in helpers (`recordOpen`,
     `recordPathProbe`, `probeFromResult`, `recordFailedOpenCanonical`, …) that
     receive the *call result* and not the errno. Counted over the procs that
     build a droppable record without the saved value in scope: **~16 on macOS,
     ~5 on Linux, ~4 on Windows** — each a signature change on a hot path.
   - **Three error vocabularies**, and Windows has two of its own: a negative
     NTSTATUS on the `Nt*` arms, a positive Win32 code on the `GetLastError`
     arms. "Which values mean absent" must be answered three-and-a-half times.

   Until it is, the fail-toward-keeping rule below makes `reads-only` stop
   reducing anything on the backends that have not — a far larger behaviour
   change than the 0.24% blind spot it closes. **That consequence is the
   load-bearing half of this cost.**
2. **There is no spare field that is also free.** "Carrying errno moves the
   measurement" is true of one carrier and false of the other, and `full` is the
   baseline DA-1i exists to measure the per-record cost against, so which
   carrier is meant decides the argument. Measured on the real encoder over a
   real failed-open record: a `detail` suffix of `errno=2` costs **+7 bytes on a
   126-byte record, +5.2%** on the fixture's `full` arm — real, and it does move
   the measurement. `result` would cost **nothing** (a fixed-width `int64`: -1,
   -2 and -13 all encode in the same 126 bytes, and `result < 0` still selects
   every failure) — but it is **not available**, and that is an availability
   objection rather than a cost one: `result` is defined as the raw call return,
   and Windows already spends its sign on NTSTATUS, so `-errno` and a genuine
   negative status could not be told apart. The cheap carrier is the one the
   wire cannot spare; the one it can spare moves the measurement.

**A failed read is never dropped — but not for the reason previously given
here.** The old text called it "an error a consumer must still see", presented
as a live case. It is not live on Linux. Counted: `linux_preload.nim` builds an
`mrFileRead` at **six** sites and not one can emit a negative result — four
guard on the byte count (`recordFdRead`, `repro_hook_fread` and the `sendfile`
arm on `> 0`, `recordRawSplice` on `> 0`, `recordRawRead` returning early on a
negative result) and two hard-code `result = 0` (`recordPathRead`, and the
inherited-fd reclassification in `classifyEmptyFdRead`). What **is** live and is
kept: **short reads**
(`0 < n < requested`) and zero-length reads at EOF, with their real byte count,
plus the synthetic `result = 0` reads (`recordPathRead`, the inherited-fd
reclassification). None of those is an existence lookup. The arm is a guard —
like `mrDirectoryEnumerate`'s — against a future backend that records failed
reads and against anyone widening `mrFileOpen`'s `result < 0` test to everything
that touches a file.

**The predicate fails toward KEEPING.** Anything it cannot prove was an
unsuccessful lookup survives. A failed `fopen` records its NULL `FILE*` as `0`,
which is also a legal fd, so it is kept: over-keeping costs records,
under-keeping costs correctness.

## 4. Where the work is skipped (two levels)

1. **The shim (Linux), in `emitRecord`** — right beside the interest gate, so the
   expensive part (gset insert + dedup, or the fragment write) never happens.
   This is not an optimisation of the mode; it *is* the mode. A gate that
   published the record and filtered it at the merge would save nothing, and
   `--evidence` exists to measure what records cost.
2. **The host, in `collectMonitorEvidence`** — belt-and-suspenders, and the
   declared **source of truth** for what the depfile contains. An older shim that
   ignores `REPRO_MONITOR_EVIDENCE` (today: the macOS and Windows shims) still
   yields a correctly narrowed result.

Because the host is the source of truth for the RESULT, the **stamp describes the
host's scope**, never the shim's.

## 5. The depfile SAYS which scope it was captured under (DA-1i)

The merge stamps `evidence=reads-only` onto the backend-profile record. It rides
on a RECORD, not on the envelope, because the `.iomon` envelope carries only
records — `depFileFromOwnedRecords` reconstructs `profile`, `capabilityGaps`,
`requiredFeatures`, `completeness` and `summary` from them — which is why this
needed no version bump.

Read it through the accessor, **never** through the raw field:

```nim
let dep = readMonitorDepFile(path)
if not observedEvidenceScopeCovers(dep, esFull):
  discard  # this evidence answers a narrower question than we asked
```

Three fields, not one, and the middle row is why:

| file | `observedEvidenceScopeStated` | `effectiveObservedEvidenceScope` | full-evidence consumer |
|---|---|---|---|
| no stamp (written before DA-1i, or a full capture) | `false` | `esFull` | ACCEPT — unchanged from before the field existed |
| `evidence=reads-only` | `true` | `esReadsOnly` | **REJECT** |
| `evidence=writes-only` — a scope a NEWER io-mon narrowed to | `true` | `esUnrecognized` | **REJECT** — the file states a scope this build cannot evaluate |
| `evidence=` (empty VALUE) | `true` | `esUnrecognized` | **REJECT** — same reason, and it needs its own answer: `parseEvidenceScopeToken` widens `""` to `esFull`, which is right for the env channel (an unset `REPRO_MONITOR_EVIDENCE` means "write everything down") and a false ACCEPT here |

The last two rows are what matter for a wire format: each is a NARROWED capture,
and reading it as full scope would publish narrowed evidence as complete
evidence. DA-1j found exactly that defect live on the interest axis;
`observedEvidenceScopeToken` keeps the raw stamp so the unevaluable scope can be
**named** in a diagnostic rather than merely detected.

Only a **narrowing** is stamped. `esFull` is left unstamped because "not stated"
has always meant exactly `esFull`, so stamping it would say nothing new while
changing the profile-detail bytes of every capture that exists — and the depfile
is byte-reproducible on purpose.

## 6. Completeness semantics

A narrowing is the **operator asking a narrower question**, not the monitor
failing to observe something, and only the latter is what `mcIncomplete` means.
DA-1i's first draft forced `mcIncomplete` under the flag and was withdrawn for
exactly this reason: it would make a deliberate, honest narrowing
indistinguishable from a monitor failure and corrupt the one signal the whole
campaign exists to make trustworthy.

Nor could it move the grade even if it were recomputed: no completeness-bearing
record is an existence lookup, and META/loss kinds are undroppable by
construction (§3). So the grade is **invariant** under the narrowing — unlike the
interest axis, where gating `ecIpc` removes the records a synthetic loss is
derived from.

## 7. Not a cache-key component

Trust here is a **partial order, not a partition**. Full evidence is strictly
stronger than reads-only evidence, so:

- a `reads-only` consumer must accept a full capture, and
- a full-evidence consumer must reject a `reads-only` one.

Keying the action cache on the scope would make the two disjoint and block the
useful direction — the careful teammate publishes at full scope and the fast
teammate cannot consume it. `evidenceScopeCovers` states the order in one place.

## 8. The hazard, and where it is written down

`reads-only` reproduces the evidence model of a compiler-emitted depfile
(`gcc -MD` lists headers opened, never headers searched for) — and with it
ninja's precise unsoundness:

| change to the tree | detected under `reads-only`? |
|---|---|
| a recorded file is **modified** | yes |
| a recorded file is **deleted** | yes |
| a file is **added** that shadows one earlier in a search path | **no** |
| a file that **exists but could not be opened** becomes openable (a `chmod`, a directory replaced by a file) | **no** |

Rows 3 and 4 are one rule with two faces: **only successful lookups are
recorded, so any later change that makes an unsuccessful lookup succeed is
invisible.** Row 1 does **not** cover row 4 — it reads as though it should, and
that is exactly why the row is owed: the file **is not recorded at all**, so
"a recorded file" never names it. Row 4 follows from §3: the record cannot tell
`ENOENT` from `EACCES`, so an inaccessible-but-present path is dropped as if it
were absent.

The table is normative and must appear in the same shape everywhere it appears:
here, in [`docs/usage.md`](../usage.md) where an operator meets the flag, and in
reprobuild's `CLI/build.md` §"Dependency Evidence Scope". The framing that must
survive editing: this degrades *"is this build up to date?"*, **not** *"are
these bytes usable?"*.

## 9. Tests

| file | grades |
|---|---|
| `tests/portable/test_io_mon_evidence_scope.nim` | the predicate (exhaustive over `MonitorRecordKind`), that it answers on the RESULT and cannot see WHY a call failed, the grade not moving, the three-field stamp read and written, and `evidenceScopeCovers` over all nine pairs (including `esUnrecognized` not covering itself) |
| `tests/linux/test_io_mon_evidence_scope_shim_gate.nim` | the SHIM gate, with the host filter provably out of the call path, and the byte saving bounded against the fixture's own guaranteed paths rather than a loose ratio |
| `tests/linux/test_io_mon_evidence_scope_older_shim.nim` | the HOST filter, against a stand-in shim built from this repo minus the gate — and the stand-in proved not to gate by running it shim-only at `reads-only` with the host out of the call path |
| `tests/posix/test_io_mon_cli_evidence_scope.nim` | the real CLI run twice on one command: counts, stamps, that every successful lookup survives, and that an unknown OR EMPTY `--evidence` value is refused in the scope vocabulary |
