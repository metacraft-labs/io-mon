# io-mon Event Transport & Loss-Freedom

This document specifies **how observed events travel from a monitored process to
the consumer, and why that channel must lose nothing.** It complements
[architecture.md](architecture.md) (which defines the *observation* mechanisms
and the `mcComplete` / `mcIncomplete` correctness contract) by defining the
*transport* underneath that contract.

Read this before touching `src/io_mon/writer.nim`, `src/io_mon/shm/dep_queue.nim`,
`src/io_mon/fs_snoop.nim`, or the `nim-shm-queue` ring.

---

## 1. The requirement: capture every event

io-mon's whole value is an **honest, complete** dependency set. A consumer
(reprobuild's engine, CodeTracer's incremental test runner) uses the captured
read/write/probe set to decide what to cache or skip. A single missed input
that is still reported under `mcComplete` is the **cardinal sin**: a false cache
hit / false skip (architecture.md §2).

Therefore the transport has exactly one hard invariant:

> **LF-1 (loss-freedom).** Every record a monitored process emits either
> (a) reaches the consumer, or (b) is accounted for by an explicit event-loss
> marker that downgrades the edge to `mcIncomplete`. There is no third outcome.
> In particular, **there is no silent drop and no write-only spill that no one
> reads.**

Everything below exists to uphold LF-1 while staying fast enough to sit in the
hot path of `fork`-heavy `configure`/`cmake`/`cargo`/`nim` probe storms.

### 1.1 "Dropping events is fine" is wrong for io-mon — and why we ever thought otherwise

For io-mon's dependency channel, **dropping a record is data loss, and data loss
is the cardinal sin.** There is no reprobuild use case in which silently dropping
a discovered input is acceptable: the whole point of the channel is completeness.

The historical design (milestone `io-mon-DEP-SHM`, see
`reprobuild-specs/io-mon-Dependency-Shm-Queue.md`) nonetheless shipped a
**bounded, drop-on-full** ring. That was only self-consistent because it was
paired with a **file fallback**: `dep_queue.tryPushRecord` returns `dpsDropped`
on a full ring, and the caller was *required* to re-emit the dropped record to a
per-thread `.rmdf-frag` file (`writer.nim`). Under that two-channel design a ring
drop was **not** a loss event — the file caught it — so the ring's drop-on-full
looked "signalled, never silent, never lossy."

That reasoning inherited a premise we now reject: **that the file fallback should
exist at all.** Once the fallback is removed (§4), a ring drop becomes real,
unrecoverable data loss, and drop-on-full is simply incorrect for this channel.
The same fallback is also what produced the production incident that motivated
this work (§4.1). So the corrected model is: **the ring is the single channel,
and the ring must be lossless.**

Note the contrast that makes this subtle: the *same ring shape* is reused by
reprobuild's **action-cache submission ring**, where drop-on-full **is** correct
— a dropped cache submission is a missed optimization (a later build recomputes),
never a correctness violation. Two consumers, two truths. If the shm ring is kept
as the transport, §3 Candidate A resolves this with a compile-time policy so each
gets optimal, correct code; the other candidates sidestep it entirely (io-mon
gets its own structure, the action cache keeps its ring).

---

## 2. Topology and the shape of the data

```
   monitored process tree (many producers: processes × threads)
        │  each observed op → one MonitorRecord
        ▼
   ┌───────────────────────────────────────────────┐
   │  shared IPC structure  (TRANSPORT — see §3)    │  ← consumer-owned memory,
   │  many producers, one consumer                  │    outlives every producer
   └───────────────────────────────────────────────┘
        │  single consumer reads/drains
        ▼
   io-mon run driver / reprobuild engine  →  canonical RMDF depfile + completeness
```

- **Producers** are the shim instances injected into every process/thread of the
  monitored tree (`src/io_mon/shim/*`). They only ever *emit*.
- **Consumer** is the single process that launched the monitor and owns the
  shared structure. It sets `REPRO_MONITOR_DEP_SHM` to the segment path
  immediately before spawning the tree (`fs_snoop.nim`) and writes the canonical
  depfile itself.
- The structure lives in **consumer-owned memory that outlives every producer**,
  so a producer that is `SIGKILL`ed *after publishing a record* loses nothing —
  the record is already in the consumer's memory. With `MAP_SHARED` a store lands
  directly in the pages the consumer maps: no flush, no `fsync`, no page-cache
  window. This is **strictly more crash-safe than a buffered file** — the file
  fallback needed a flush protocol precisely because its writes were *not*
  synchronous to consumer-visible state.

**No shim buffering (retires read-tail netting).** Because a store is instantly
consumer-visible, the shim does **not batch**. It publishes each input observation
**before returning the observed data to the monitored process** (record the
read/stat/mmap dependency, then hand back the syscall result). So the process can
never act on data whose dependency is not already in consumer-owned memory — the
"acted-on-unrecorded-read" cardinal-sin window is closed *structurally*, and the
whole file-era batch apparatus (64 KiB/100 ms buffer, `read-tail-pending`/
`read-tail-committed` markers, `.io-mon-reading` sentinel, sig-safe committed
frame, `mergeFragments` netting — the `io-mon-Dependency-Flush-Robustness` protocol)
is deleted, not ported. It existed *only* to compensate for the buffer. A producer
killed mid-insert (before the publishing release-store) loses only a slot the
consumer skips (torn-writer skip) — and that is not a loss, because the process had
not yet received the data. Idempotency, not batching, is the throughput mechanism.

**The data is a set, not a stream.** The high-volume traffic is file
reads/writes/probes; the deliverable is the *distinct* input set (reduction — a
path read *and* written — is derived at the single-threaded final merge, §3
Candidate C). `configure`/`cmake` probes read the same handful of files thousands
of times, so *events* ≫ *distinct dependencies*. A lower-volume second class
(process-tree edges `exec`/`fork`/`childOsPid`; IPC peers; event-loss markers) is
also set-shaped under its own keys. This set-accumulation shape drives the
transport decision in §3.

---

## 3. Transport (open design decision)

> **Status: decided by benchmark.** Three candidate transports are on the table.
> They all satisfy the loss-freedom requirements (§1); they differ in how, and in
> how much mechanism the "capture everything without dropping" property costs. The
> decision is that **both principal models are implemented and benchmarked
> head-to-head under a real probe storm** before one is chosen — Candidate A (the
> `nim-shm-queue` ring + backpressure) and Candidate C (a **new
> `nim-shm-gset` library**), with the small ordered side channel (§2) built
> on Candidate B. See the corrective campaign
> `reprobuild-specs/io-mon-Lossless-Event-Capture.milestones.org` (M1 spike). This
> section records the candidates and their trade-offs so the decision is made in
> the open.

### Candidate A — SHM ring + compile-time backpressure policy

Reuse the `nim-shm-queue` Layer 1 `ShmRing` (already shared with the action
cache) with **two behaviors selected at compile time**, so each instantiation is
monomorphized to optimal branch-free code — no runtime policy check on the hot
path.

```nim
type
  OverflowPolicy* = enum
    opDropSignalled   ## bounded: on full, bump the atomic `dropped` counter and
                      ## return prDropped. Correct where loss = missed
                      ## optimization (action-cache submission ring).
    opBlockProducer   ## lossless: on full, the producer WAITS for the consumer
                      ## to free a slot (bounded spin → futex), then publishes.
                      ## Correct where loss = missed dependency (io-mon deps).

  ShmRing*[policy: static OverflowPolicy] = object
    seg: ShmSegment
    ...
```

The push path branches with `when`, so only the selected policy's code is
emitted:

```nim
proc tryPush*[p: static OverflowPolicy](r: var ShmRing[p];
                                        blob: openArray[byte]): PushResult =
  when p == opDropSignalled:
    # existing behavior: CAS a ticket iff not full; else bump `dropped`, prDropped
    ...
  elif p == opBlockProducer:
    # reserve a ticket; if full, wait for `head` to advance (see §3.1), re-try;
    # never return prDropped — only prPushed, prOversize, or prConsumerGone
    ...
```

- **Action cache** instantiates `ShmRing[opDropSignalled]` — unchanged semantics.
- **io-mon dep queue** instantiates `ShmRing[opBlockProducer]` — lossless.

`prOversize` and the drain path are identical for both policies (§3.2, §3.3).
The consumer side is policy-agnostic: a single-consumer `head`-advance drain.

### 3.1 Backpressure without hanging the tracee

`opBlockProducer` means the producer waits for a slot. Waiting must never wedge a
monitored process against a **dead or absent** consumer, so the wait is bounded
and liveness-gated:

1. **Bounded spin.** Spin `N` times attempting the CAS reservation. The common
   case (consumer keeps up) resolves here with no syscall.
2. **Futex wait.** If still full, `futex_wait` on the ring's `head` word with a
   timeout. The consumer, after advancing `head`, issues a `futex_wake` gated by
   a `waiters` atomic so the uncontended fast path costs nothing.
3. **Liveness re-check on every wake.** Re-check (a) a slot freed → publish;
   (b) the **consumer-liveness token** in the segment header (consumer pid +
   boot-guarded heartbeat/epoch). If the consumer is gone, stop: return
   `prConsumerGone`. The producer must **not** spin forever and must **not**
   spill to a file (§4).

**Contract:** consumer alive ⇒ the producer waits and every record is captured;
consumer dead ⇒ the producer fails fast (`prConsumerGone`) and the tree keeps
doing its real work. A dead consumer means nobody will ever read the data, so
producing it is pointless — this is the deliberate replacement for the old
"spill to a file no one drains" behavior.

### 3.2 Oversize records must not be lost either

LF-1 forbids losing an oversize record just because it exceeds a slot. Two
mechanisms, in order of preference:

- **Size the slot for the worst case.** `DepSlotRecCap` must bound any real
  `MonitorRecord` (path ≤ `PATH_MAX`, plus detail/run-token suffix). If the slot
  always fits, `prOversize` is unreachable in practice.
- **Jumbo framing (fallback within the ring, never a file).** For a genuinely
  oversize record, publish it as a length-prefixed run of consecutive slots that
  the consumer reassembles. This keeps loss-freedom inside the ring.

An `prOversize` that is *not* handled by one of the above MUST become an
event-loss marker → `mcIncomplete`, never a silent drop.

### 3.3 Torn / crashed producers

The ticket-CAS protocol already tolerates a producer that dies mid-write: the
slot's `ready` word is published via a release-store only after the blob is
fully written, so the consumer skips an unpublished/torn slot (`drEmpty`) rather
than reading garbage. A producer killed *before* the release-store loses only
that one in-flight record — which becomes an `mcIncomplete` downgrade if it was
material, per the flush-robustness invariant
(`reprobuild-specs/io-mon-Dependency-Flush-Robustness.md`).

**Known weakness of Candidate A.** Loss-freedom on a lock-free ring means bolting
a *blocking* discipline onto a structure designed to be *non-blocking*. The
result is busy-waiting on both sides: the producer bounded-spins then futex-waits
(§3.1); the consumer must drain continuously (today a 2 ms poll in `fs_snoop`) or
the ring backs up and stalls every producer. Backpressure is not the ring's
native mode — it is grafted on. Candidates B and C avoid this.

### Candidate B — OS-primitive MPSC queue (kernel-backed backpressure)

Use a traditional kernel IPC queue — a POSIX message queue (`mq_open`/`mq_send`/
`mq_receive`), or a Unix-domain socket / pipe drained via `epoll` — as the
transport. The kernel provides **correct blocking backpressure for free**:
`mq_send` blocks (or `EAGAIN`s) when the queue is full, `mq_receive` blocks when
empty. No hand-rolled spin loop, no consumer poll, no busy-wait on either side —
the kernel does the waiting.

- **Pro:** backpressure and blocking are the primitive's native semantics, not a
  graft. Liveness is also native — if the consumer dies its endpoint closes and
  producers get `EPIPE`/`ECONNRESET` (a clean `prConsumerGone` equivalent),
  killing the orphan class (LF-2) without a heartbeat protocol.
- **Con:** **a syscall per event.** Under a fork/probe storm that is millions of
  `mq_send`s — precisely the per-record syscall churn `io-mon-DEP-SHM` introduced
  the shm ring to *avoid* (the file path's syscall-per-record cost was a named
  motivation). Also: `mq` depth/size caps are sysctl-bounded; datagram sockets
  need framing; `SCM_RIGHTS` is not needed but message-boundary handling is.
- This con is only fatal **at event volume.** If the set-accumulation channel
  dedups at the source (Candidate C), the surviving volume is distinct-deps, not
  events, and a syscall-per-*distinct-dep* is cheap. B is most attractive for the
  *small ordered* channel (§2), where volume is low and native ordering + native
  backpressure are exactly what is wanted.

### Candidate C — new `nim-shm-gset`: an append-only shared-memory set

Model the channel as what the data actually is (§2): a **set**. Formally a
**grow-only set (G-Set)** — a state-based CRDT whose state is a bounded
join-semilattice and whose merge is **union**: insert is idempotent, nothing is
ever deleted, merge is order-independent. That algebra is what makes the sharded
design below correct regardless of write order, writer, or duplication. It is a
**new standalone library, `nim-shm-gset`** (`metacraft-labs/nim-shm-gset`, sibling
to `nim-shm-queue`).

**Pure membership (chosen).** The element is the full observation tuple
(`path`, `obsKind`, `flags`, `result`); the only shared-memory operation is an
**idempotent slot-claim** (CAS an empty slot to the element hash; identical element
already there ⇒ done). There is **no per-element mutable value and no atomic value
read-modify-write**, so the lost-update race class simply does not exist. Any
reduction (deriving that a path was read *and* written from two membership
elements) is done in the single-threaded final merge, where there is no
concurrency. (There is no read-tail pending/committed netting to do — LF-7 removes
buffering, so the markers are never emitted.) (The
G-Map alternative — key by `path`, carry a joinable value — dedups harder but
reintroduces the concurrent value RMW; not worth it unless the element count
proves a problem.)

- **Idempotent inserts eliminate the backpressure problem at the source.**
  Re-observing a key is a no-op — the set is bounded by *distinct* dependencies
  (thousands), not *events* (millions). The thousandth `stat` of the same header
  is one CAS that finds the key present and returns; the probe storm collapses.
- **No consumer drain loop.** The consumer does not race the producers; it
  snapshots at edge end (or reads live for progress). No poll, no busy-wait on
  either side — the cleanest answer to the two-sided busy-wait critique.
- **Append-only ⇒ tractable lock-free design.** No deletion ⇒ no tombstones: CAS
  an empty slot empty→key (linear probe on collision), or join the value on a key
  match. That is the only concurrent operation.

**Growth by sharding, not migration.** "Full" must never mean drop (LF-1). Instead
of the concurrent-resize hazard (lost value-joins during the copy, per-slot
sealing, robust-mutex recovery), the set **shards**: when the newest shard crosses
a load threshold (~0.5), a producer atomically links a **new, larger shard**
(growth factor 4–8) onto a chain and inserts continue there. Producers that have
not noticed keep writing older shards — harmless, because there is no migration to
race and the reader unions all shards. This *defers* the merge work to a single
place instead of doing it eagerly under contention, and keeps pure append-only
lock-freedom.

- **Loose shards, tight tally.** Shards run at low load factor (short probes; and
  the sum of shard capacities exceeds the true distinct-key count, so the final
  table is guaranteed room). The parent's final merge is **single-threaded** —
  no CAS, no atomics — so it packs at a **high load factor (~0.9)** and only needs
  to be ≥ distinct keys (grow it trivially if short). All concurrency slack lives
  in the shards; the source-of-truth table sheds it.
- **Control block in the first shard.** No separate anchor segment: the first
  shard is the well-known `REPRO_MONITOR_DEP_SHM` name, is never migrated/replaced
  (only appended past), and its header is the stable anchor — chain head,
  generation/shard count, consumer-liveness token, reaper metadata. Producers
  resolve the live shard through it; the parent walks the chain.
- **Publish-before-write.** Link a new shard into the chain (release-ordered)
  *before* any insert lands in it, so a producer that dies right after allocating
  cannot strand data the reader can't discover.

**Cross-OS lifetime — file-backed on all three OSes.** Named shared-memory
lifetime is *not* uniform: POSIX `shm_open`/file-backed mmap persists until
`shm_unlink`/delete independent of mapping count, but a **Windows page-file-backed
section** (`CreateFileMapping(INVALID_HANDLE_VALUE,…)`) is **handle-refcounted** —
the last handle closing destroys it, so all producers dying would lose the data
before the parent maps it. The set is therefore **file-backed** (one file per
shard in a parent-owned dir; POSIX `mmap(MAP_SHARED)`; Windows `CreateFileMapping`
over a real `CreateFile` handle). Then "persists" == "the file exists" everywhere,
decoupled from mapping count, surviving producer death and `exec`; it also dodges
macOS's 31-char `shm_open` name limit and Windows' namespace privileges, and
matches io-mon's existing treatment of `REPRO_MONITOR_DEP_SHM` as a *path*. Notes:
prefer a **tmpfs** dir on Linux (`/dev/shm`) to avoid writeback;
`FILE_ATTRIBUTE_TEMPORARY` on Windows; open with `FILE_SHARE_DELETE` so the reaper
can unlink a mapped file.

**Reaper (cross-restart GC).** LF-2 stops a *live* orphan; the reaper cleans up
after the *consumer* (the reprobuild daemon) crashing and leaving shard files
behind. `reapStaleSegments(dir, appId)` — called by the daemon on startup and
periodically — reaps a run's shards (named `{appId}~{runId}.{creatorBootId}.{ownerPid}.shardN`)
when `creatorBootId != currentBootId` (survived a reboot) or the owner pid is dead
on the current boot; live-owner runs are left alone; an `flock` guards a starting
run. The reaper is SCOPED to its `appId`: segments tagged with any other appId
are ignored entirely (never reaped, never even liveness-checked), so one
application cannot reap another's segments when they share a directory and
cross-app pid reuse can no longer misfire. This is the existing boot-guarded
staleness lifted to directory scope, then narrowed to per-app scope.

**Open questions for M1:** (1) **variable-length keys** — a shared append-only
**intern arena** (buckets store an offset) vs fixed `PATH_MAX` buckets;
(2) **membership sufficiency** — confirm every record class is derivable from set
membership at the single-threaded final merge, needing no arrival order.
Process-tree edges and IPC peers are plainly sets under their own keys. The
file-era read-tail **pending/committed netting** does **not** carry over: LF-7
removes shim buffering, so there is no un-flushed read tail and the markers are
never emitted — nothing to net. That leaves no record class needing arrival order,
so the Candidate-B side channel (§1.1) is not built; the current analysis confirms
it.

**Concurrency verification.** This is a lock-free, **multi-process**, weak-memory,
crash-exposed structure; functional tests pass for months while a missing fence
waits to fault on ARM64. The plan (design spec **§4.5**, the authoritative list)
requires: a **TLA+** protocol model + **stateless model checking**
(GenMC/CDSChecker) of the *shipped* C11 atomics core on a tiny forced-collision
table + **litmus tests** (herd7) for every release→acquire pair;
**position-independence** (map at different bases in producer vs consumer, offsets
only — no absolute pointer may live in shared memory); structure-specific
adversarial interleavings (slot-claim race, torn key, the intern arena as its own
lock-free structure, sharding double-grow with **no leaked shard file**, reaper
races) via deterministic schedule hooks *and* stress; **real multi-process
(fork+exec)** SIGKILL fault injection at every publish point; the **LF-7
publish-before-return** shim test; a `final == union(intended)` oracle + a
multi-hour `rr`-chaos **soak**; a **real-build completeness oracle** (ninja-cmake /
cargo validated against the toolchain's own dep data + `strace` — the under-capture
/ cardinal-sin gate, §4.5(h)); TSAN (thread harness only — it does not cross
processes) + ASan/UBSan + DRD. **Mandatory on x86 AND ARM64.**

### Comparison and leaning

| | A: SHM ring + backpressure | B: OS-primitive MPSC queue | C: `nim-shm-gset` (sharded append-only set) |
|---|---|---|---|
| Backpressure | hand-rolled, busy-wait both sides | native (kernel blocks) | moot (idempotent inserts) |
| Cost per event | zero-syscall push | **one syscall per event** | one CAS; dup = one CAS, no growth |
| Volume handled | every event | every event | **distinct deps only** |
| Ordering | preserved | preserved | irrelevant (set; final merge canonicalizes) |
| Consumer | continuous drain (poll) | blocking `recv` | snapshot + merge at end (no loop) |
| Growth / full | must not drop (block) | kernel-bounded | shard + link (never drop) |
| Liveness / orphan | heartbeat + `prConsumerGone` | native (`EPIPE`) | consumer-owned; reaper for cross-restart |
| Complexity | ring + grafted blocking | lowest | set + shards + intern arena |

**Decision:** implement **both** principal models — Candidate **A** (the
`nim-shm-queue` ring with the `opBlockProducer` policy) and Candidate **C** (the
new sharded `nim-shm-gset`, plus a **size-once baseline**) — behind a common
producer/consumer interface, and **benchmark them head-to-head** under a real
fork/probe storm including a many-producer `cargo` build (M1). The prior is that
C wins the file-dependency **set** because dedup-at-source dissolves the
backpressure and volume problems; the Candidate-B ordered side channel is built
**only if** M1 finds a folded field that is not a semilattice join. A is the
reference the benchmark must beat and the fallback if a single uniform transport
is required. Whichever wins, the loss-freedom requirements (§1) and the no-file /
no-orphan-spill rules (§4) are invariant, and the interface (§6) makes the choice
swappable.

---

## 4. No fallback file

**The `.rmdf-frag` per-process file spill is removed as a producer path.** Its
two historical jobs are both subsumed:

- *Durability across producer death* → provided by consumer-owned ring memory
  (§2).
- *Overflow capture* → provided by lossless backpressure (§3.1) and jumbo
  framing (§3.2).

What remains on disk is only the **canonical final depfile** the consumer writes
after draining — that is output, not a per-producer spill.

An **unattached ring** (`dpsUnavailable` / `REPRO_MONITOR_DEP_SHM` unset) is
treated as a **hard error, not a reason to write a file**:

> **LF-2 (no orphan spill).** If a producer finds no ring to attach, it was not
> launched under a real io-mon consumer. There is therefore no one to read
> anything it produces. It MUST NOT create a spill file; it fails fast (and, if
> monitoring was required for the edge, the edge is `mcIncomplete` / the action
> fails per `Sandbox-And-Monitoring.md`).

### 4.1 The incident this closes

A long-lived `repro-full daemon serve --dev` was left as an **orphaned monitored
descendant**: its monitor's root command had exited, the grace period lapsed, and
`fs_snoop` removed the fragment directory — but the descendant kept running and
kept appending to its now-*unlinked* `.rmdf-frag` fd. With no consumer draining
it, that single fragment grew to **~61 GiB** and filled the root tmpfs. This is
exactly the `dpsUnavailable`/orphan class: a producer on the file fallback with
no consumer. LF-2 makes it structurally impossible — there is no file to grow.

The interim `FragmentMaxBytesDefault` byte-cap leak-guard added to `writer.nim`
(cap the fragment, write a `fragment-byte-cap-reached` loss marker, close the fd)
is a **stopgap for platforms still on the file path** (§5). On Linux it is
deleted together with the file producer.

---

## 5. Per-OS producer arms

Loss-freedom is delivered per platform; the file path is only retired on a
platform once that platform's ring producer exists.

| Platform | Producer mechanism | Ring producer status | File fallback |
|----------|--------------------|----------------------|---------------|
| **Linux**   | `LD_PRELOAD` shim + raw-syscall substrate | present (`dep_queue` attaches via `REPRO_MONITOR_DEP_SHM`) | **removed** once `opBlockProducer` lands |
| **macOS**   | interpose + `mach_vm_remap` body-patch / EndpointSecurity | `depQueueSupported` compiles, **producer arm is future work** | retained until the macOS ring producer lands |
| **Windows** | injected hooks (`CreateRemoteThread` + `LoadLibraryW`) | not yet | retained until the Windows ring producer lands |

`depQueueSupported = defined(linux) or defined(macosx)`; on any other platform the
ring is a no-op and the producer must degrade to an explicit `mcIncomplete`
(never a silent capture). The corrective milestones campaign
(`reprobuild-specs/io-mon-Lossless-Event-Capture.milestones.org`) tracks one
milestone per OS.

---

## 6. The parent-host library (don't re-implement the protocol)

A parent that wants io-mon's guarantees must not hand-roll the ring lifecycle
(create segment → set `REPRO_MONITOR_DEP_SHM` → spawn → drain → finalize). A
hand-rolled host that forgets a step is exactly how a producer ends up with no
consumer (LF-2). io-mon therefore exposes the host orchestration as a **public
library API**, not only a CLI:

- **Producer side** is already a drop-in: the shim is built `--app:lib` and the
  parent reimplements nothing; it sets env and launches.
- **Protocol/ring** is already one shared library (`nim-shm-queue`, reused by the
  action cache) — the wire format is not duplicated per repo.
- **Consumer/host side** is now exported (**M6 part A landed**, Linux x86-64).
  The batch host API is public in `fs_snoop.nim` and re-exported from `io_mon`:

  ```nim
  proc runMonitored*(req: FsSnoopRequest): MonitorResult   ## owns set lifecycle
  type MonitorResult* = object
    exitCode*: int
    depFilePath*: string
    depFile*: MonitorDepFile     ## .records, .completeness, …
  ```

  `runMonitored` owns the entire lifecycle — on Linux it **creates** the
  consumer-owned `nim-shm-gset` (via `transport.startHost`, appId defaulting to
  `"io-mon"` or `REPRO_MONITOR_APP_ID`), **exports** `REPRO_MONITOR_DEP_SHM` +
  `REPRO_MONITOR_APP_ID`, **spawns** the tree, **snapshots** the deduped set,
  **writes** the canonical depfile (with the spawned root pid as the R1
  root-guard), and on **finish** calls `markConsumerGone` + detach. The CLI
  `runFsSnoopCli` is now a thin wrapper over it (`runMonitored(req).exitCode`) —
  no duplicated lifecycle. Because the consumer structure is created, named, and
  torn down inside this proc, **LF-2** (no orphan spill: a producer never runs
  without a consumer) and **LF-4** (consumer liveness) hold *by construction*
  for any well-formed parent: "the set was never set up" is structurally
  impossible. See `io-mon/docs/usage.md` → *The public host API* for the caller
  contract, and `tests/linux/test_io_mon_public_host_api.nim` for the end-to-end
  proof (public-surface-only: `mcComplete`, inputs captured, no `.rmdf-frag`
  spill).

  `FsSnoopRequest` also carries a per-call `env` and `cwd`
  (IoMon-Decomposed-Host-API DH-1). On **all three** arms the injection
  variables travel through the spawn and `runMonitored` mutates nothing
  process-global, so N monitors can run concurrently in one host process without
  clobbering each other's `LD_PRELOAD` / `REPRO_MONITOR_*`. Windows was the last
  arm to get there: `stackable_hooks.runWithMonitorShim` now takes an `env`
  (a non-nil table being the child's *complete* environment, encoded into an
  explicit `CreateProcessW` environment block), so its four injection variables
  no longer need a scope-restored `putEnv`. One `childEnv` helper composes the
  child environment for every arm, so there is a single layering rule (host env,
  then `request.env`, then io-mon's injection, injection winning) rather than
  three that can drift.

  The **decomposed** form has landed (DH-2): `startMonitor` → `pollMonitor` →
  `finishMonitor`, so a caller can own the wait and interleave N monitors in one
  poll loop — the shape the build engine's scheduler needs. `runMonitored` is
  now literally `finishMonitor(startMonitor(req))`, so there is still exactly
  one implementation of the lifecycle.

  Moving ownership of the wait out is precisely what makes an LF-2 orphan
  reachable again, so the guarantee moved into the TYPE rather than into a rule
  callers are asked to follow. `MonitorHandle` cannot be copied (`=copy` is
  `{.error.}`, propagating through `seq`s, arrays and wrapping objects, so "the
  other copy will finish it" is not an argument that can be made), and dropping
  one runs `=destroy`, which **reaps the monitored root before releasing the
  consumer** — on every path out of the owning scope, including an unwinding
  exception. The ordering that produced §4.1's incident (release the consumer
  and delete the fragment directory while a producer is still publishing into
  it) is therefore not reachable by forgetting anything: a dropped handle costs
  the caller the wait and the evidence, never an orphan. The wait/release
  ordering has ONE implementation (`endMonitor`), shared by `finishMonitor` and
  the destructor, so the two cannot drift.

  Pinned by `tests/linux/test_io_mon_decomposed_host_api.nim` (a handle dropped
  over a demonstrably-live producer, three monitors interleaved in one poll
  loop, and `runMonitored`'s delegation asserted both at runtime and at source
  level) and `tests/portable/test_io_mon_monitor_handle_exclusivity.nim` (the
  real compiler refusing every copy of a handle, with positive controls).
  Making the §4.1 descendant guard unskippable for a host that owns its OWN
  spawn is DH-3, still open.

---

## 7. Invariants checklist (for reviewers)

- **LF-1** every event reaches the consumer or becomes an `mcIncomplete` marker;
  no silent drop, no write-only spill.
- **LF-2** unattached ring ⇒ hard fail, never a spill file.
- **Transport** chosen per §3 (open decision); whichever wins, §1/§4 hold.
- **Policy split (Candidate A only)** `opDropSignalled` (action cache) vs
  `opBlockProducer` (io-mon deps) chosen at compile time via
  `static OverflowPolicy` + `when`.
- **Liveness** a blocked/waiting producer waits only while the consumer is alive;
  dead consumer ⇒ `prConsumerGone` (or native `EPIPE`), never a hang.
- **Oversize** handled by worst-case slot sizing or jumbo framing, else
  `mcIncomplete` — never a silent drop.
- **No file producer on a platform whose ring producer exists** (Linux first;
  macOS/Windows tracked per-OS).
