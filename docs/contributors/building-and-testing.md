# Building & Testing io-mon

This guide details how to build and test the `io-mon` monitor, shim libraries, and CLI.

---

## 1. Prerequisites & Sibling Layouts

`io-mon` compiles against `nim-stackable-hooks`. In typical workspace development:

- `nim-stackable-hooks` must be checked out as a sibling directory at `../nim-stackable-hooks/`.
- Paths are resolved automatically by the `Justfile` and `io_mon.nimble` targets.

---

## 2. Compilation Targets

You can build the components using `just` or the `repro` command-line tool.

### Build the Interpose Shim Shared Library

The shim library intercepts system calls in monitored programs. It compiles to `build/lib/librepro_monitor_shim.{dylib,so,dll}`.

```sh
just build-shim
# OR
repro build io-mon:shim
# OR (fallback)
scripts/build_shim.sh
```

### Build the Standalone CLI Snoop tool

The `io-mon` binary runs commands under the shim and writes dependency depfiles. It compiles to `build/bin/io-mon`.

```sh
just build-snoop
# OR
repro build io-mon
# OR (fallback)
nimble buildSnoop
```

---

## 3. Running the Test Suite

Tests are organized into directories based on their target compatibility:

| Directory         | Runs on      | Focus / Scope                                                                                         |
| ----------------- | ------------ | ----------------------------------------------------------------------------------------------------- |
| `tests/portable/` | All OSes     | Pure logic tests (depfile formats, encoders, completeness algorithm checks). Runs without live shims. |
| `tests/posix/`    | POSIX OSes   | Shared POSIX hooks and platform wrapper validations.                                                  |
| `tests/macos/`    | macOS only   | Live macOS interpose + body-patch testing.                                                            |
| `tests/linux/`    | Linux only   | Live Linux `LD_PRELOAD` testing.                                                                      |
| `tests/windows/`  | Windows only | Live Windows hook injection testing.                                                                  |

The inline `exit_group` assembly fixture requires Linux x86_64, matching
`linuxRawSyscallSupported()` and the INT3 backend. It reports an explicit skip
on other architectures. Linux ARM64 still runs the portable, POSIX and Linux
file-capture tests; this skip does not claim an ARM64 raw-syscall backend.

### Run the full suite (Automatic Selection)

Runs the portable tests plus whatever directories match the host operating system:

```sh
just test
# OR
repro test
```

`just test` invokes Nim directly through `scripts/run_tests.nims`. Its sorted
catalog is shared with the compatibility Nimble tasks. Use Just or Reprobuild
for test verdicts: the Windows Nimble bundled with Nim 2.2.10 can return zero
after a task exception.

### Verify isolated programs execute again

`repro build .#test-monitor-isolation --write-report=build/monitor-isolation-repeat.json`
reruns the programs whose fixture must own its monitor environment. Their
compilation stays monitored and their execution stays uncached. CI requires
all selected programs to launch and succeed on the repeat: 45 on macOS, nine
on Linux and eight on Windows. Update that explicit inventory when adding an
isolated program; keep the complete report among failure artifacts.

At `40a0adc` plus the workflow inventory repair, the macOS repeat passes all
137 actions and launches all 45 isolated programs. The previous expectation
of 42 rejects that complete successful report; the corrected count accepts it.

### Run only portable tests

```sh
just test-portable
```

### Run only host-platform specific tests

```sh
just test-platform
```

---

## 4. Memory safety: the sanitizer arm

```sh
scripts/run_sanitizer_tests.sh              # tests/portable (the default)
scripts/run_sanitizer_tests.sh tests/portable tests/posix
```

This compiles and runs a tier a second time under **AddressSanitizer and
UndefinedBehaviorSanitizer**. CI runs it on every push and pull request to
`main`/`dev`/`stable`, in the merge queue, and on demand
(`.github/workflows/sanitizers.yml`, job _Memory safety_). It is a separate
arm rather than a flag on `just test` because the instrumented builds are
slower, and because it grades a class of defect the ordinary suite
structurally cannot.

**What it is for.** `src/io_mon/codec.nim` moves string bodies and
fixed-width header fields with `copyMem`. A wrong _size_ on one of those
copies still writes correct bytes into the buffer and then keeps going, so
the round-trip checks, the byte-for-byte `.iomon` goldens and the field
digests all agree with themselves and see nothing.

**The gating result first.** On an unmutated tree at `53994c0` the arm is
**rc=0, 25 files, 0 failed**, with no ASan report and no UBSan `runtime error:`
anywhere in the sweep. Everything below was measured on a deliberately broken
tree, and none of it would mean anything without this line — an arm that is red
on everything grades nothing.

**What it actually adds is not uniform across defects, and the honest table
matters more than the slogan.** Three mutations of `codec.nim` were applied in
throwaway trees at `53994c0`, each anchor asserted to occur exactly once:

| mutation                                          | ordinary portable tier                                                                                                                                                                       | this arm                                                                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `writeString` copy length `+ 1`                   | **green, 25/25 files**                                                                                                                                                                       | **red** — ASan `heap-buffer-overflow WRITE … 0 bytes after` the region, in `writeString`, called from `encodeFrame` |
| `readString` bounds check removed                 | red, but only by dying: SIGBUS, exit 135, **no verdict printed**                                                                                                                             | red — ASan `heap-buffer-overflow READ of size 65540` naming `readString`                                            |
| `readString` bound off by one (`> bytes.len + 1`) | **red by verdict** already: `test_io_mon_wire_negative_oracle` reports `[FAILED] t_every_negative_case_is_refused_with_the_pinned_verdict` on its `detaillen_one_byte_past_the_payload` case | red                                                                                                                 |

The first row deliberately does **not** quote a byte count, and that is worth a
paragraph because quoting one is the natural mistake. The write size and the
region size are _data-dependent_ — they are whatever string that particular test
happened to encode. Across the 11 files the mutant reddens, five distinct pairs
occur:

```
WRITE of size 18  0 bytes after a  97-byte region   (6 files)
WRITE of size 20  0 bytes after a 118-byte region   test_io_mon_wire_negative_oracle
WRITE of size 33  0 bytes after a 144-byte region   test_io_mon_wire_informative_fixture
WRITE of size 41  0 bytes after a 120-byte region   test_io_mon_t0_completeness
WRITE of size 551 0 bytes after a 653-byte region   (2 files)
```

So a specific pair lifted out of one log reads as a signature of the defect and
is not one. The stable part of the signature is the access kind, the _zero_
offset past the region, and the frame — `writeString` called from `encodeFrame`.
All 11 findings are `heap-buffer-overflow` in `codec::writeString`; none is a
UBSan finding.

**The sharpest form of the contrast** is that `test_io_mon_wire_negative_oracle`
and `test_io_mon_wire_informative_fixture` — the two files whose entire job is to
check the wire format, one of them byte-for-byte against a golden — are **green**
on the ordinary tier under this mutant and **red** under the arm. The files best
placed to catch a wire-format defect cannot see this one, because there is no
wire-format difference to see.

Read that as three different statements:

- The **first** mutation is the entire justification for this job. Nothing
  else in the tree grades it, and nothing else can: the byte written past the
  region is the string's NUL terminator, so the logical contents are
  unchanged and there is no wrong output for any oracle to compare.
- The **second** is an upgrade in _diagnosis_, not in detection. The suite
  already went red — it just went red as an unexplained process death. The
  arm names the function and the size.
- The **third** the arm **does not improve on at all**. The negative oracle
  already separates the correct bound from a slack one by verdict. Do not
  count it as something the sanitizers bought.

**UBSan catches none of those three, and is kept anyway — on measured grounds,
not asserted ones.** Every finding above is AddressSanitizer's, and UBSan
reports nothing at all on a clean tree (zero `runtime error:` lines across the
whole sweep). A sanitizer that has never fired can only be justified by what it
_would_ catch, so that was measured. Two probes at `53994c0`, each a one-line
change to `codec.nim` run under this arm:

| probe                                                                                                  | UBSan verdict                                                                 | ASan   |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- | ------ |
| `readU32Le`'s shift amount widened                                                                     | `runtime error: shift exponent 64 is too large for 64-bit type`               | silent |
| `loadU32Le`'s `copyMem` replaced by a reinterpreting pointer cast — the obvious "faster" rewrite of it | `runtime error: load of misaligned address … which requires 4 byte alignment` | silent |

Both are one edit away from the code as written, and ASan sees neither. That is
what earns UBSan its place, together with a marginal cost near zero: same
compile, same run, and ASan dominates both. Read its silence as "no such defect
today", never as coverage of the copy sizes. Those are ASan's.

Two things this rationale deliberately does **not** claim, because both were
checked and are false:

- Not _"signed overflow in the big-endian shift arms"_. Those arms sit in a
  `when cpuEndian == littleEndian: … else:` inside the fixed-offset accessors
  and are not compiled at all on this arm's only platform, so nothing here
  grades them.
- Not _"out-of-range enum conversions"_. Those conversions live in
  `encode.nim` and `shm/dep_queue.nim`, not `codec.nim`, and
  `decodeRecordPayload` explicitly range-checks `kindOrd`, `obsOrd` and
  `probeOrd` before converting each one — so there is no unguarded conversion
  for UBSan to reach, and Nim's own range check would fire first if there were.

**`-d:useMalloc` is mandatory, and the script passes it on the command
line.** Nim's default allocator carves per-thread regions out of `mmap`, so
every Nim object lives inside one large mapping that ASan does not know the
shape of — a write one byte past a `seq` lands inside the same mapping and is
reported as nothing at all. `-d:useMalloc` gives each object its own `malloc`
block with redzones, which is the only configuration in which this arm grades
anything.

**That is measured, not asserted, and it is the most falsifiable claim on this
page.** The `writeString` mutant was swept a second time with the script
unchanged except for the removal of that one flag:

|                     | verdict                   | ASan reports across the 25 logs |
| ------------------- | ------------------------- | ------------------------------- |
| with `-d:useMalloc` | rc=1, **11 of 25 failed** | 11                              |
| without it          | rc=0, **0 of 25 failed**  | **0**                           |

The second row is not a build that lost its sanitizer. Those binaries link
`libasan` and carry 31 `__asan` and 16 `__ubsan` symbols each — ASan is fully
present, and simply cannot see an overflow that never leaves Nim's one big
mapping. Drop the flag and this job still runs, still reports itself as
instrumented, and grades nothing. That is why it lives on the command line where
a reader of the script can see it.

The flag is _not_ added to `config.nims`, and that is deliberate: the three
shim entry modules (`src/io_mon/shim/*`) carry a `when appType == "lib" and
not defined(useMalloc): {.error.}` guard because the shim is loaded into
processes whose threads it does not own (see
[shim-build-policy.md](shim-build-policy.md)). The guard stays. What it
punishes is _assuming the flag travels_: a `nim c` that a test spawns for
itself is a fresh compiler invocation and inherits nothing, so each such
compile passes its own `-d:useMalloc`. Putting the flag in `config.nims` to
avoid that would change the allocator for every build in the checkout, which
is a product change in a CI change's clothing.

**What the arm does not cover — a green tick is a statement about the portable
tier only.** It sweeps `tests/portable/` and nothing else:

- **`tests/posix`, `tests/linux`, `tests/macos`, `tests/windows` are not
  swept.** Grading them would mean injecting an instrumented shim into
  arbitrary host processes, which is a different problem from grading the
  codec and has its own open question
  (`issues/2026-09-30-linux-shim-runtime-settings-diverge-from-policy.md`).
- **The shim shared library is not built by this arm at all.**
- **Children are not instrumented, and this is the largest of the four gaps.**
  **8 of the 25** portable tests drive a `nim` of their own —
  `test_io_mon_child_env_layering`, `test_io_mon_cli_interest_flag`,
  `test_io_mon_evidence_scope`, `test_io_mon_monitor_handle_exclusivity`,
  `test_io_mon_snoop_cli_smoke`, `test_io_mon_windows_child_env_block`,
  `test_nimcache_is_worktree_local`, `test_shim_signal_handler_policy` — and
  none of those child compiles carries `-d:useMalloc` or `-fsanitize`, because a
  spawned `nim c` is a fresh compiler invocation that inherits nothing from this
  script's command line. So the arm _pays_ for those child builds (they are why
  `test_io_mon_evidence_scope` is the most expensive file in the sweep) without
  _grading_ them. Worth knowing before reading a green tick as covering a third
  of the tier's compiler work.
- **Leak detection is off** (`detect_leaks=0`). The Nim runtime keeps
  process-global state alive to exit by design, so leak checking would report
  the runtime's architecture on every file and make the arm red on a clean
  tree. This arm grades memory _safety_, not retention.

Within the tier it sweeps, nothing is sampled: every `test_*.nim` is compiled
and run, and there is no skip list. The two tests that cannot be run
unattended — `test_io_mon_allocator_clock_reentrancy`, which needs `rustc`,
and `test_io_mon_shim_fd_path_concurrency`, which hangs before any case
reports — are both in `tests/linux/` and so are outside this arm by
construction rather than by exclusion; no file in `tests/portable/` requires
`rustc`. A caller who points the script at `tests/linux` inherits both
problems and must deal with them deliberately.

Every run prints the tier and the file list it swept, so the gate's coverage
is readable from its log. Each file gets its own log and its own exit-code
file under `build/sanitizers/logs/`, and one red file does not stop the
sweep.

**Runtime, measured on a real runner — and the workstation figure that looked
alarming was wrong by 16x.** The number that matters is the _Memory safety_ job's
own wall time, and on a dedicated GitHub-hosted `ubuntu-24.04` runner the sweep of
all 25 files takes **320–435 s** across the two runs measured, inside a whole job
— Nix setup, checkout, sweep, log upload — of **8m47s and 10m29s**. Two runs is a
small sample and runner variance is clearly a third of the figure, so treat this
as "under fifteen minutes", not as a constant. That makes it the _slowest of the fast jobs_ and nowhere near
the repo's long poles — for comparison, on the same commit: Lint 3m25s, Build
(linux) 3m37s, Windows complete suite 4m21s, Build (macOS) 5m40s, and the
`CI (reprobuild)` legs 26m / 49m / 81m / 84m.

The same sweep on a 32-core developer workstation took **5104 s** against 2211 s
for the tier uninstrumented. Do not quote either of those, or the 2.3x ratio
between them: they were taken with four such sweeps running concurrently at load
average 108–293, and the CI figure shows that contention inflated them by more
than an order of magnitude. A contended multiplier is not an instrumentation
multiplier. This is recorded because the original version of this section quoted
the workstation numbers as though they predicted CI cost, which is how a 5-minute
job gets argued about as though it were an hour.

Per-file costs come out of the `.rc` files the sweep already writes — one per
file, written the moment that file's compile-and-run returns — so they are
readable from the uploaded artifact without the script measuring anything extra.
Both hosts agree on the _shape_, which is the part worth knowing:

|                               | CI (dedicated)      | workstation (contended) |
| ----------------------------- | ------------------- | ----------------------- |
| `test_io_mon_t0_completeness` | **58 s** (heaviest) | **1348 s** (heaviest)   |
| `test_io_mon_evidence_scope`  | 46 s                | 673 s                   |
| median file                   | ~9 s                | 116 s                   |
| whole sweep                   | 320 s / 435 s       | 5104 s                  |

`test_io_mon_evidence_scope` is the most expensive file _uninstrumented_, because
most of its time is child `nim` builds that this arm does not instrument.
`test_io_mon_t0_completeness` spawns no child compiler at all, so its cost is its
own translation unit, and instrumentation is what makes it the hot-spot. The arm's
expense falls on the file whose own code it actually grades — the right shape for
this cost to have.

Nothing is sampled to keep the time down. If this arm ever does need trimming,
the scope must change visibly in the workflow, because a gate that quietly skips
most of a tier reads as coverage it does not have.
