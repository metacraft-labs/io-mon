## test_io_mon_evidence_identical_across_launch_paths — IoMon-Decomposed-Host-API
## DH-4, the acceptance milestone.
##
## THE CLAIM: an external host driving `startMonitor` → `pollMonitor` →
## `finishMonitor` and `runMonitored` produce **byte-identical evidence** for the
## same action — the same path set, the same completeness, the same loss records,
## the same diagnostics. This is what retires In-Process-Monitor-Hosting HM-4's
## blocker: a build engine may take ownership of the wait without its evidence
## drifting from the CLI's.
##
## NO MOCKS. The tree is real, the detached descendant is a real double-forked
## `setsid`'d daemon compiled here by the host toolchain, the `/proc` scan is
## real, and both renderings are decoded from the canonical depfiles io-mon
## actually wrote. The property under test is what two launch paths report about
## the same fixture; a fake on either side would be a comparison of the fake with
## itself.
##
## ── WHAT "BYTE-IDENTICAL" EXCLUDES, AND WHY ────────────────────────────────
##
## Two runs of one action are two different process trees at two different
## moments, so a handful of KERNEL-ALLOCATED IDENTIFIERS cannot be equal. They
## are normalised; nothing else is. The list is closed, was derived by MEASURING
## a real pair of runs rather than guessed, and every entry is a bijection (a
## renaming) rather than a redaction (a blanking):
##
##   1. **OS pids** — the `osPid`, `parentOsPid`, `threadId` and `childOsPid`
##      fields. Replaced by `P0`, `P1`, … assigned by FIRST APPEARANCE over the
##      canonical record sequence. Because it is a bijection it preserves how
##      many distinct pids appear, which records share one, and the order in
##      which they first appear. `0` stays `0`: 0 means "no pid", and conflating
##      it with a real pid would hide a record that lost its parent.
##   2. **An `mrProcessSpawn`'s `result`**, which for that record kind IS the
##      forked child's pid (measured: it equals the record's own `childOsPid`).
##      Same bijection as (1). `result` on EVERY OTHER record kind — byte counts,
##      `-1` probe failures — is compared verbatim.
##   3. **The `run=` detail token.** The launcher stamps the invocation's run id
##      into a record's `detail` as a whitespace-separated `key=value` token
##      (writer.nim's own convention, `detailToken`). The run id is per-call
##      unique BY CONSTRUCTION since DH-1 — that is what stops two concurrent
##      monitors fabricating each other's losses — so two runs can never agree on
##      it. The VALUE becomes `<RUN>`; the token, and everything around it, stay.
##   4. **The `pids=` detail token**, which is how the §4.1 marker names the
##      descendants it found. Each entry goes through the SAME bijection as (1),
##      so the COUNT and the identity-sharing survive.
##   5. **The kernel object id in a `localfd:<dev>:<ino>` pseudo-path** — the
##      pipe the fixture creates gets a fresh inode every run. Only the third
##      component is tokenised, through its own bijection; `dev` and the scheme
##      are compared verbatim, and a path that is not a `localfd:` pseudo-path is
##      not touched at all.
##
## REAL FILESYSTEM PATHS ARE NOT NORMALISED. They are made equal BY CONSTRUCTION
## instead: the two runs execute the same command in the SAME directory, one
## after the other (the directory is torn down and rebuilt between them), so
## every path string either matches exactly or is a real difference. That is
## deliberately stronger than placeholdering the paths, because a placeholder is
## exactly the sort of normalisation that passes vacuously.
##
## Everything else is compared VERBATIM: `kind`, `observationKind`, `seq`,
## `flags`, `probeResult`, `path`, every part of `detail` outside those two
## tokens, and every non-record field of `MonitorDepFile` — `version`,
## `producerVersion`, `backendFamily`, `requiredFeatures`, `completeness`,
## `profile` (including its `diagnostics`), `capabilityGaps`, and all four
## `summary` counts.
##
## The renderer walks `fieldPairs`, so a field ADDED to `MonitorRecord` or
## `MonitorDepFile` later is compared automatically; EXCLUDING it would take a
## deliberate edit to the name list in `renderRecord`.
##
## ── WHY THE COMPARISON CANNOT PASS VACUOUSLY ───────────────────────────────
##
## `t_the_normalisation_cannot_mask_a_real_difference` takes the REAL evidence
## this suite just produced and perturbs it, demanding that the NORMALISED
## rendering CHANGE for every perturbation a regression could produce — a dropped
## record, a duplicated one, a flipped completeness, a deleted loss marker, a
## one-character path change, a changed observation kind / result / flags, a
## wrong summary count, two distinct pids COLLAPSED into one, an extra pid in the
## `pids=` list, a spawn whose `result` stops agreeing with its `childOsPid`, two
## channel records given DIFFERENT inodes, a changed `localfd` device, EVERY
## `localfd` device changed consistently, and a changed non-token word inside a
## loss `detail`. It then asserts the two things the normalisation is supposed to
## erase — a different run id, and a wholesale consistent RENAMING of every pid —
## and nothing else, so the exclusion is bounded from both sides.
##
## One rule is pinned DIRECTLY rather than through a perturbation, because no
## perturbation of this fixture reaches it: the pid map reserves `0` for "no
## pid". Mapping `0` like any other value was measured to redden nothing here,
## and it is a real masking channel — the two runs are normalised by independent
## `Norm`s, so a record that lost its parent could land on the same token index
## as a record whose parent is another process. A three-line assertion on
## `pidTok` is both cheaper and stronger than a contrived perturbation.
##
## ── THE THREE WAYS THE PATHS CAN DIVERGE, AND HOW EACH IS HANDLED ──────────
##
## DH-3's verification enumerated them; this file addresses all three.
##
##   1. **The one code-level seam** is `waitForMonitorRoot`'s `if h.exited:
##      return`. The paths differ ONLY in `h.exited` at `finishMonitor` entry, so
##      any state a change puts after that early return runs on the batch path
##      and is skipped on the polled one. The headline case is what catches such
##      a change, exactly as DH-3's M5 was caught.
##   2. **A TIMING seam that needs no bug at all.** The §4.1 grace window opens
##      when `collectMonitorEvidence` runs: immediately after `waitForExit` on
##      the batch path, but at a HOST-CHOSEN later moment on the polled one. A
##      descendant that dies inside that extra interval is graded `mcComplete` by
##      one path and `mcIncomplete` by the other ON IDENTICAL INPUTS, with no bug
##      present. This file does not merely avoid that window — it ATTACKS it: the
##      polled host sleeps `HostDelayMs` (three grace windows) between the root's
##      exit and `finishMonitor`, and the descendant is held alive across BOTH
##      windows by a sentinel file the harness drops only after `finishMonitor`
##      has returned. The descendant's lifetime is therefore a SUPERSET of every
##      grace window either path can open, whatever the host's scheduler does, so
##      the agreement is deterministic rather than timing-lucky. The control arm
##      is gated from the other side: its descendant has provably EXITED (the
##      root drains an inherited pipe to EOF) before the root exits, so it is
##      dead before either window opens.
##   3. **`h.exitCode`'s two writers.** DH-4 closes this one in the source rather
##      than testing around it: `recordRootExit` is now the single writer of
##      `h.exitCode` and `h.exited`, and
##      `t_the_root_exit_status_has_a_single_writer` pins that structurally AND
##      demands the two paths agree on a NON-ZERO status, which is where a
##      divergence would actually show.

import std/[os, osproc, sequtils, streams, strutils, tables, unittest]

import io_mon                            # the PUBLIC host API
import shm_gset                          # shmGSetSupported

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fsSnoopPath = repoRoot / "src" / "io_mon" / "fs_snoop.nim"

  ## The §4.1 grace window, set in THIS process because the guard is a
  ## LAUNCHER-side step and for a decomposed host the launcher IS this process.
  GraceMs = 300
  PollMs = 10

  ## How long the polled host deliberately dawdles between the root's exit and
  ## `finishMonitor`, which is when its §4.1 grace window opens. Three grace
  ## windows: long enough that a descendant merely SLEEPING would have died in
  ## the gap and the two paths would legitimately disagree. The sentinel is what
  ## makes them agree anyway.
  HostDelayMs = 3 * GraceMs

  LocalFdPrefix = "localfd:"

# --------------------------------------------------------------------------
# Helpers.
#
# Every helper that ASSERTS is a `template`: a `check` inside a plain `proc`
# prints "Check failed" and still leaves the case labelled `[OK]`. Helpers that
# merely DO something are procs and signal failure by RAISING, which unittest
# reports as a genuine `[FAILED]`.
# --------------------------------------------------------------------------

proc run(cmd: string; args: seq[string]): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildC(work, name, source: string): string =
  ## Compile `source` to `work/name` with the host toolchain. RAISES on failure —
  ## a helper must not swallow a broken fixture into a green test.
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result])
  if built.code != 0 or not fileExists(result):
    raise newException(IOError,
      "failed to compile fixture " & name & " (exit " & $built.code & "): " &
        built.output)

proc ensureShim(): string =
  ## Build the shim the way the rest of the Linux suite does and resolve it with
  ## the same discovery `startMonitor` uses.
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  if buildShim.code != 0:
    raise newException(IOError, "build_shim.sh failed: " & buildShim.output)
  result = findShimLibrary()
  if result.len == 0:
    raise newException(IOError, "findShimLibrary() resolved nothing after build")

proc awaitFile(path: string; timeoutMs: int) =
  ## Block until `path` appears. RAISES on timeout rather than carrying on, so a
  ## descendant that never acknowledged its release cannot be mistaken for one
  ## that exited.
  var waited = 0
  while not fileExists(path):
    if waited >= timeoutMs:
      raise newException(IOError,
        "timed out after " & $timeoutMs & "ms waiting for " & path)
    sleep(10)
    waited += 10

# --------------------------------------------------------------------------
# The evidence renderer and its normalisation. The header states the contract;
# this is the whole of it.
# --------------------------------------------------------------------------

type
  Norm = object
    ## BIJECTIONS from this run's kernel-allocated identifiers to stable tokens,
    ## assigned by first appearance. Not redactions: two distinct values can
    ## never share a token and one value always gets the same token, so "how many
    ## processes" and "which records belong to the same process / the same
    ## channel" both survive normalisation.
    pids: Table[uint64, string]
    nextPid: int
    inodes: Table[string, string]
    nextInode: int

proc newNorm(): Norm =
  Norm(pids: initTable[uint64, string](), nextPid: 0,
       inodes: initTable[string, string](), nextInode: 0)

proc pidTok(n: var Norm; v: uint64): string =
  if v == 0:
    # 0 is "no pid", not a pid. Mapping it would conflate a record that has no
    # parent (or no child) with one whose counterpart is simply another process.
    return "0"
  if n.pids.hasKey(v):
    return n.pids[v]
  result = "P" & $n.nextPid
  n.pids[v] = result
  inc n.nextPid

proc inodeTok(n: var Norm; v: string): string =
  if n.inodes.hasKey(v):
    return n.inodes[v]
  result = "I" & $n.nextInode
  n.inodes[v] = result
  inc n.nextInode

proc isAllDigits(s: string): bool =
  if s.len == 0:
    return false
  for c in s:
    if c notin {'0' .. '9'}:
      return false
  true

proc normalisePath(path: string; n: var Norm): string =
  ## Only the `localfd:<dev>:<ino>` pseudo-path is touched, and only its third
  ## component. Everything else — every real filesystem path, every
  ## `sysconf:<n>`, every capability-gap slug — is returned unchanged.
  ##
  ## RAISES on a `localfd:` path it cannot decompose: a normaliser that shrugs at
  ## input it does not understand is how a comparison starts agreeing about text
  ## neither side read.
  if not path.startsWith(LocalFdPrefix):
    return path
  let rest = path[LocalFdPrefix.len .. ^1]
  let colon = rest.find(':')
  if colon < 0:
    raise newException(ValueError,
      "malformed `localfd:` pseudo-path (expected localfd:<dev>:<ino>): " & path)
  let dev = rest[0 ..< colon]
  let ino = rest[colon + 1 .. ^1]
  if not isAllDigits(ino):
    raise newException(ValueError,
      "`localfd:` pseudo-path carries a non-numeric inode: " & path)
  LocalFdPrefix & dev & ":" & inodeTok(n, ino)

proc normaliseDetail(detail: string; n: var Norm): string =
  ## A record's `detail` is a sequence of whitespace-separated words, some of
  ## which are `key=value` tokens whose values contain no whitespace — that is
  ## `writer.nim`'s own convention (`detailToken` / `detailTokens`), not a rule
  ## invented here. Exactly two keys are rewritten:
  ##
  ##   `run=<id>`      → `run=<RUN>`
  ##   `pids=<a>,<b>…` → the same list with each pid mapped through `n`
  ##
  ## Every other word, including every other `key=value` token, is returned
  ## byte-for-byte. Splitting and rejoining on `' '` round-trips exactly, runs of
  ## spaces included.
  ##
  ## RAISES on a second `run=` or `pids=` token, and on a `pids=` entry that is
  ## not a number. Answering short here is how a normalisation quietly grows.
  var parts = detail.split(' ')
  var runSeen = 0
  var pidsSeen = 0
  for i in 0 ..< parts.len:
    if parts[i].startsWith("run="):
      inc runSeen
      parts[i] = "run=<RUN>"
    elif parts[i].startsWith("pids="):
      inc pidsSeen
      var toks: seq[string] = @[]
      for item in parts[i][len("pids=") .. ^1].split(','):
        if item.len == 0:
          continue
        if not isAllDigits(item):
          raise newException(ValueError,
            "`pids=` entry `" & item & "` is not a number, in detail `" &
              detail & "`")
        toks.add pidTok(n, uint64(parseBiggestInt(item)))
      parts[i] = "pids=" & toks.join(",")
  if runSeen > 1 or pidsSeen > 1:
    raise newException(ValueError,
      "detail carries more than one `run=`/`pids=` token, which this " &
        "normaliser refuses to guess about: " & detail)
  parts.join(" ")

proc renderRecord(r: MonitorRecord; n: var Norm; norm: bool): string =
  ## EVERY field of `MonitorRecord`, via `fieldPairs` — so a field added later is
  ## compared without anyone remembering to add it here.
  var parts: seq[string] = @[]
  for name, value in fieldPairs(r):
    when name == "osPid" or name == "parentOsPid" or name == "threadId" or
         name == "childOsPid":
      parts.add name & "=" & (if norm: pidTok(n, value) else: $value)
    elif name == "result":
      # For `mrProcessSpawn` — and ONLY for it — `result` is the forked child's
      # pid (measured: it equals the record's own `childOsPid`). On every other
      # kind it is a byte count or an errno-ish status and is compared verbatim.
      parts.add name & "=" &
        (if norm and r.kind == mrProcessSpawn: pidTok(n, uint64(value))
         else: $value)
    elif name == "path":
      parts.add name & "=" & (if norm: normalisePath(value, n) else: value)
    elif name == "detail":
      parts.add name & "=" & (if norm: normaliseDetail(value, n) else: value)
    else:
      parts.add name & "=" & $value
  parts.join(" ")

proc renderEvidence(dep: MonitorDepFile; norm: bool): string =
  ## EVERY field of `MonitorDepFile`, records included, one line each. The result
  ## is compared with `==`, i.e. byte for byte.
  var n = newNorm()
  var lines: seq[string] = @[]
  for name, value in fieldPairs(dep):
    when name == "records":
      lines.add "records.len=" & $value.len
      for i, r in value:
        lines.add "  record[" & $i & "] " & renderRecord(r, n, norm)
    else:
      lines.add name & "=" & $value
  lines.join("\n")

proc firstDifference(a, b: string): string =
  ## Where two renderings first disagree, as a diagnostic. Never asserts.
  let al = a.splitLines()
  let bl = b.splitLines()
  for i in 0 ..< max(al.len, bl.len):
    let x = if i < al.len: al[i] else: "<absent>"
    let y = if i < bl.len: bl[i] else: "<absent>"
    if x != y:
      return "line " & $(i + 1) & ":\n    A: " & x & "\n    B: " & y
  "<no difference>"

proc lossDetails(dep: MonitorDepFile): seq[string] =
  ## Every §4.1 launcher-side loss marker in an edge's evidence. Both spellings
  ## the guard can produce count: the grace-window timeout, and the `/proc` scan
  ## having failed outright (which is also an honest "I could not tell").
  result = @[]
  for rec in dep.records:
    if rec.kind == mrEventLoss and
        ("linux injected descendants still live" in rec.detail or
         "linux injected-descendant /proc scan failed" in rec.detail):
      result.add rec.detail

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

# --------------------------------------------------------------------------
# Fixtures.
# --------------------------------------------------------------------------

## The detached-descendant fixture, adapted from DH-3's
## `tests/linux/test_io_mon_external_host_descendant_guard.nim`. TWO changes,
## both forced by DH-4 comparing two runs' evidence rather than grading one run.
##
## 1. **In gated mode the descendant writes `<release>.ack`** after it sees its
##    release sentinel and immediately before it `_exit`s. DH-4 runs the two
##    launch paths in the SAME directory so their path strings are identical,
##    which means the directory must be torn down between them — and tearing it
##    down under a descendant still polling `stat(release)` would leave that
##    descendant spinning forever. The ack is what lets the harness know the
##    descendant is past its last file operation.
##
## 2. **ONE fork, not two.** DH-3's fixture double-forks (`fork`, `setsid`,
##    `fork`, intermediate `_exit`s), which is the textbook daemonisation. It is
##    also NONDETERMINISTIC in a way DH-3 never had to care about: the shim emits
##    the grandchild's `mrProcessStart` at fork time, and whether the
##    intermediate parent has exited by that instant is a race, so the record's
##    `parentOsPid` is the intermediate on some runs and `1` (init) on others.
##    MEASURED, not theorised: with the double fork this file's quiesced case
##    failed on exactly that field — `parentOsPid=P2` against `parentOsPid=P4`
##    for the same record — while everything else matched. That is a real
##    difference in the evidence, so normalising it away would be precisely the
##    over-normalisation this file exists to avoid; the fixture is what has to
##    change. A single `fork` + `setsid` gives a descendant that is equally
##    detached (a new session, re-parented to init the moment the root exits, and
##    never waited on) whose recorded parent is deterministically THE ROOT,
##    because the root is provably still alive — blocked on the pipe — when the
##    fork happens. The second fork only ever protected against re-acquiring a
##    controlling terminal, which nothing here does.
##
##   argv[1] — the marker file the descendant reads (so the run has a real
##             dependency the DESCENDANT, not the root, discovered)
##   argv[2] — the proof file it writes once it has read the marker
##   argv[3] — ms to sleep before reading
##   argv[4] — ms to sleep before exiting (quiesce mode only)
##   argv[5] — release sentinel path, or "-" for quiesce mode
##
## QUIESCE ("-", the control): the root drains an inherited pipe to EOF, so the
## descendant has provably EXITED before the root does and therefore before
## either path's grace window can open. Expected verdict `mcComplete` on BOTH.
##
## GATED (a path, the headline): the descendant signals the root once it is
## alive, visible in `/proc` and past its I/O; the root then exits and the
## descendant BLOCKS until the sentinel appears. The harness drops the sentinel
## only after `finishMonitor` has returned, so the descendant is alive across the
## WHOLE of whichever grace window each path opens, however late the host opens
## it. Expected verdict `mcIncomplete` on BOTH.
##
## The gated arm closes every fd but the pipe: the shim dups its own channels
## onto inherited descriptors, and a blocking daemon holding them can keep a
## parent's stream from reaching EOF.
const detachedDescendantSrc = """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void msleep_arg(const char *s) {
  long ms = strtol(s, NULL, 10);
  if (ms > 0) usleep((useconds_t)ms * 1000);
}

int main(int argc, char **argv) {
  if (argc != 6) return 2;
  const char *release = argv[5];
  int gated = strcmp(release, "-") != 0;

  int rp[2];
  if (pipe(rp) != 0) return 8;

  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid > 0) {
    /* THE ROOT. */
    close(rp[1]);
    char b;
    if (gated) {
      /* Wait until the descendant is alive, visible in /proc and past its
         I/O — then exit, so the grace window opens over a LIVE descendant. */
      while (read(rp[0], &b, 1) < 0) { /* retry on EINTR */ }
    } else {
      /* Wait until the descendant has fully EXITED (pipe EOF), so the grace
         window opens over a provably quiesced tree. */
      while (read(rp[0], &b, 1) > 0) { /* drain until EOF */ }
    }
    close(rp[0]);
    return 0;
  }
  /* THE DESCENDANT. ONE fork and a setsid, deliberately — see the Nim comment
     above. `setsid` detaches the session; the root exiting re-parents this
     process to init; nothing ever waits on it. Its recorded parent is the root,
     deterministically, because the root is blocked on the pipe above and cannot
     have exited when this process started. */
  close(rp[0]);
  if (setsid() < 0) _exit(4);

  if (gated) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
    for (int fd = 0; fd < maxfd; fd++) {
      if (fd != rp[1]) close(fd);
    }
    int dn = open("/dev/null", O_RDWR);
    if (dn == 0) { dup2(dn, 1); dup2(dn, 2); }
  }

  msleep_arg(argv[3]);
  int in = open(argv[1], O_RDONLY);
  if (in < 0) _exit(6);
  char buf[64];
  ssize_t n = read(in, buf, sizeof(buf));
  close(in);
  int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out >= 0) {
    if (n > 0) { if (write(out, "read\n", 5) < 0) {} }
    else { if (write(out, "empty\n", 6) < 0) {} }
    close(out);
  }
  if (gated) {
    char rb = 1;
    if (write(rp[1], &rb, 1) < 0) {}
    close(rp[1]);
    struct stat st;
    while (stat(release, &st) != 0) usleep(2000);
    char ack[4096];
    snprintf(ack, sizeof(ack), "%s.ack", release);
    int af = open(ack, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (af >= 0) { if (write(af, "gone\n", 5) < 0) {} close(af); }
    _exit(n > 0 ? 0 : 7);
  }
  msleep_arg(argv[4]);
  _exit(n > 0 ? 0 : 7);
}
"""

## Reads a marker (so the edge carries real evidence to compare) and exits with
## the status named in argv[2]. A NON-ZERO status is the point: two paths
## agreeing that a run exited 0 says nothing about `h.exitCode`'s writers,
## because 0 is also what a `finishMonitor` that never learned the status would
## report.
const exitWithSrc = """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 3;
  char b[64];
  if (read(fd, b, sizeof(b)) < 0) {}
  close(fd);
  return atoi(argv[2]);
}
"""

# --------------------------------------------------------------------------
# Source-level reading of `fs_snoop.nim`, for the single-writer case.
#
# Deliberately the dumbest parser that can answer the question asked of it, and
# every lookup RAISES when it cannot find what it was told to find — answering
# SHORT is how a count assertion passes with three producers present while it
# asserts two (DH-3, M9b).
# --------------------------------------------------------------------------

type
  ProcSpan = object
    name: string
    first: int
    last: int

proc isTopLevelBoundary(line: string): bool =
  for prefix in ["proc ", "func ", "template ", "iterator ", "type", "var ",
                 "const ", "# ---"]:
    if line.startsWith(prefix):
      return true
  false

proc fsSnoopLines(): seq[string] =
  readFile(fsSnoopPath).splitLines()

proc spanOf(lines: seq[string]; name: string): ProcSpan =
  var first = -1
  for i, line in lines:
    if line.startsWith("proc " & name & "(") or
        line.startsWith("proc " & name & "*("):
      if first >= 0:
        raise newException(ValueError,
          "src/io_mon/fs_snoop.nim declares `" & name & "` more than once — " &
            "this parser assumes one definition per name")
      first = i
  if first < 0:
    raise newException(ValueError,
      "could not find `proc " & name & "(` in src/io_mon/fs_snoop.nim")
  var last = lines.high
  for i in first + 1 .. lines.high:
    if isTopLevelBoundary(lines[i]):
      last = i - 1
      break
  ProcSpan(name: name, first: first, last: last)

iterator codeLineIndices(lines: seq[string]): int =
  ## Indices of CODE lines — no comments, no doc comments, no blanks. Comments
  ## are excluded on purpose: a claim that survives only because a comment
  ## mentions the call is exactly the documented-only guarantee this campaign
  ## exists to replace.
  for i, line in lines:
    let stripped = line.strip()
    if stripped.len > 0 and not stripped.startsWith("#"):
      yield i

proc assignmentsTo(lines: seq[string]; field: string): seq[int] =
  ## Every CODE line that ASSIGNS to `<something>.<field>`, where the something
  ## is not `result`. Written as an assignment test rather than a mention test so
  ## that `result.exitCode = h.exitCode` (a READ of the handle's field, into the
  ## `MonitorResult`) is not counted, and `h.injection.exitCode` (no `=`) is not
  ## either.
  ##
  ## **WHITESPACE- AND OPERATOR-TOLERANT, and that is not fussiness.** The first
  ## draft matched the literal needle `.<field> = `. MEASURED during verification:
  ## a second writer spelled `handle.exitCode=code` — the same statement with two
  ## spaces removed — slipped straight past it while `exitCodeWrites.len == 1`
  ## went on passing, so the single-writer claim held only for writers spelled the
  ## way the author happened to spell them. That is DH-3's lesson one milestone
  ## later ("a parser that answers SHORT is worse than one that raises"), and the
  ## remedy is the same: recognise the SHAPE, not one spelling of it. The
  ## positive control is a mutation that adds the spaced spelling; the negative
  ## control is the same mutation without them. Both redden now.
  ##
  ## RAISES when it finds nothing: "there are no writers" must never be an answer
  ## this parser can give quietly.
  result = @[]
  let needle = "." & field
  for i in codeLineIndices(lines):
    let stripped = lines[i].strip()
    var at = 0
    while true:
      let hit = stripped.find(needle, at)
      if hit < 0:
        break
      at = hit + needle.len
      # The field name must END here, so `.exitCode` does not match inside a
      # longer identifier such as `.exitCodeSeen`.
      if at < stripped.len and stripped[at] in IdentChars:
        continue
      var j = at
      while j < stripped.len and stripped[j] in {' ', '\t'}:
        inc j
      if j >= stripped.len:
        continue
      # `=` (but not the comparison `==`), or a compound assignment `+=` etc.
      let isPlain = stripped[j] == '=' and
        (j + 1 >= stripped.len or stripped[j + 1] != '=')
      let isCompound = stripped[j] in {'+', '-', '*', '/'} and
        j + 1 < stripped.len and stripped[j + 1] == '='
      if not (isPlain or isCompound):
        continue
      let target = stripped[0 ..< hit]
      if target.len == 0 or target.startsWith("result"):
        continue
      result.add i
      break
  if result.len == 0:
    raise newException(ValueError,
      "could not find any assignment to `." & field & "` in " &
        "src/io_mon/fs_snoop.nim — this parser must never answer short")

proc callSitesOf(lines: seq[string]; name: string): seq[int] =
  ## Every CODE line calling `name(`, excluding its own definition. RAISES when
  ## there are none.
  result = @[]
  for i in codeLineIndices(lines):
    let stripped = lines[i].strip()
    if stripped.startsWith("proc " & name & "("):
      continue
    if (name & "(") in stripped:
      result.add i
  if result.len == 0:
    raise newException(ValueError,
      "could not find any call to `" & name & "(` in " &
        "src/io_mon/fs_snoop.nim — this parser must never answer short")

# --------------------------------------------------------------------------
putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", $GraceMs)
putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", $PollMs)

type
  LaunchPath = enum
    lpBatch      ## `runMonitored` — the reference, and what the CLI uses
    lpPolledHost ## `startMonitor` → `pollMonitor` → `finishMonitor`, with a delay

var
  workRoot = ""
  descendantProbe = ""
  exitWithProbe = ""

proc setUpFixtures() =
  ## Build the fixtures ONCE, OUTSIDE the run directory, so their paths are the
  ## same string for every run.
  if workRoot.len > 0:
    return
  workRoot = getTempDir() / ("io-mon-dh4-" & $getCurrentProcessId())
  removeDir(workRoot)
  createDir(workRoot)
  let binDir = workRoot / "bin"
  createDir(binDir)
  descendantProbe = buildC(binDir, "dh4_detached_descendant",
    detachedDescendantSrc)
  exitWithProbe = buildC(binDir, "dh4_exit_with", exitWithSrc)

proc runOneAction(path: LaunchPath; command: proc (runDir: string): seq[string];
    gatedRelease: bool): MonitorResult =
  ## Run ONE action, in a freshly rebuilt `runDir`, by the named launch path.
  ##
  ## Both launch paths use the SAME directory, one after the other, which is what
  ## makes their path strings identical and lets the comparison leave real paths
  ## alone entirely.
  ##
  ## The polled arm deliberately dawdles `HostDelayMs` between the root's exit
  ## and `finishMonitor` — the moment its §4.1 grace window opens. That is DH-3's
  ## timing seam, driven on purpose rather than avoided.
  let runDir = workRoot / "run"
  removeDir(runDir)
  createDir(runDir)
  writeFile(runDir / "marker.txt", "dh4 marker\n")

  var req: FsSnoopRequest
  req.command = command(runDir)
  req.depFilePath = runDir / "evidence.iomon"
  req.streamMode = fsoNone

  case path
  of lpBatch:
    result = runMonitored(req)
  of lpPolledHost:
    var h = startMonitor(req)
    while not pollMonitor(h):
      sleep(5)
    sleep(HostDelayMs)
    result = finishMonitor(move(h))

  if gatedRelease:
    # Release the descendant IMMEDIATELY — before any assertion, so it is let go
    # (and reaped by init) even if a later assertion fails — then wait for its
    # ack, because the NEXT run reuses this very directory.
    let release = runDir / "release"
    writeFile(release, "release\n")
    awaitFile(release & ".ack", 20_000)
    sleep(100)

suite "io-mon evidence is identical across launch paths (DH-4)":

  test "t_evidence_is_identical_across_launch_paths_for_a_detached_descendant":
    ## THE ACCEPTANCE CASE. The same action, run by both launch paths, with a
    ## descendant that outlives every grace window either path can open. Not the
    ## happy path: agreeing on `mcComplete` is easy and proves little, and DH-3
    ## MEASURED that these two paths can diverge.
    check shmGSetSupported
    check ensureShim().len > 0
    setUpFixtures()

    let gatedCommand = proc (runDir: string): seq[string] =
      @[descendantProbe, runDir / "marker.txt", runDir / "proof", "0", "0",
        runDir / "release"]

    let batch = runOneAction(lpBatch, gatedCommand, gatedRelease = true)
    let host = runOneAction(lpPolledHost, gatedCommand, gatedRelease = true)

    let batchRaw = renderEvidence(batch.depFile, norm = false)
    let hostRaw = renderEvidence(host.depFile, norm = false)
    let batchNorm = renderEvidence(batch.depFile, norm = true)
    let hostNorm = renderEvidence(host.depFile, norm = true)

    checkpoint("batch (runMonitored) : completeness=" & $batch.completeness &
      " exit=" & $batch.exitCode & " records=" & $batch.depFile.records.len &
      " losses=" & $lossDetails(batch.depFile))
    checkpoint("polled external host : completeness=" & $host.completeness &
      " exit=" & $host.exitCode & " records=" & $host.depFile.records.len &
      " losses=" & $lossDetails(host.depFile))

    # (1) Both paths report the honest downgrade. Without this the identity in
    #     (3) could hold over two equally WRONG answers.
    check batch.completeness == mcIncomplete
    check host.completeness == mcIncomplete
    check lossDetails(batch.depFile).len > 0
    check lossDetails(host.depFile).len > 0

    # (2) The monitored ROOT still succeeded on both. The downgrade is a
    #     statement about the EVIDENCE, not about the action.
    check batch.exitCode == 0
    check host.exitCode == 0

    # (3) THE MILESTONE: byte-identical evidence. Path sets, completeness, loss
    #     records, diagnostics — the whole `MonitorDepFile`, field by field.
    checkpoint("first difference (normalised): " &
      firstDifference(batchNorm, hostNorm))
    check batchNorm == hostNorm

    # (4) …and the normalisation was not a blanket that made (3) trivial. The two
    #     runs really were two different process trees: their UNNORMALISED
    #     renderings differ.
    checkpoint("first difference (raw): " & firstDifference(batchRaw, hostRaw))
    check batchRaw != hostRaw

    # (5) Counts called out separately, so a failure reads as what it is rather
    #     than as a wall of rendered text.
    check batch.depFile.records.len == host.depFile.records.len
    check lossDetails(batch.depFile).len == lossDetails(host.depFile).len
    check batch.depFile.summary == host.depFile.summary

  test "t_evidence_is_identical_across_launch_paths_for_a_quiesced_run":
    ## The CONTROL, and it is not decoration: it is what stops the headline
    ## passing because io-mon grades this fixture `mcIncomplete` for some reason
    ## that has nothing to do with a descendant outliving a window. Same probe,
    ## same directory, same two paths — but the descendant has provably EXITED
    ## before the root does, so both paths must say `mcComplete` and must still
    ## agree byte for byte.
    check shmGSetSupported
    check ensureShim().len > 0
    setUpFixtures()

    let quietCommand = proc (runDir: string): seq[string] =
      @[descendantProbe, runDir / "marker.txt", runDir / "proof", "10", "0", "-"]

    let batch = runOneAction(lpBatch, quietCommand, gatedRelease = false)
    let host = runOneAction(lpPolledHost, quietCommand, gatedRelease = false)

    checkpoint("batch (runMonitored) : completeness=" & $batch.completeness &
      " records=" & $batch.depFile.records.len & " losses=" &
      $lossDetails(batch.depFile))
    checkpoint("polled external host : completeness=" & $host.completeness &
      " records=" & $host.depFile.records.len & " losses=" &
      $lossDetails(host.depFile))

    check batch.completeness == mcComplete
    check host.completeness == mcComplete
    check lossDetails(batch.depFile).len == 0
    check lossDetails(host.depFile).len == 0

    # The dependency at stake is REAL and was discovered by the DESCENDANT, not
    # by the root — which is what makes the headline's downgrade meaningful.
    check hasFileRead(batch.depFile, "marker.txt")
    check hasFileRead(host.depFile, "marker.txt")

    let batchNorm = renderEvidence(batch.depFile, norm = true)
    let hostNorm = renderEvidence(host.depFile, norm = true)
    checkpoint("first difference (normalised): " &
      firstDifference(batchNorm, hostNorm))
    check batchNorm == hostNorm
    check renderEvidence(batch.depFile, norm = false) !=
          renderEvidence(host.depFile, norm = false)

  test "t_the_root_exit_status_has_a_single_writer":
    ## DH-3's THIRD divergence seam, closed in the SOURCE rather than tested
    ## around. `h.exitCode` used to have two writers — `pollMonitor` on the
    ## polled path and `waitForMonitorRoot` on the batch path. They agreed, and
    ## nothing pinned that they must. Since the two paths differ ONLY in which of
    ## those runs, a change to either is a change to one path's evidence and not
    ## the other's — the same shape as the `h.settled` divergence DH-3 measured,
    ## one field over.
    let lines = fsSnoopLines()

    # (A) Exactly ONE writer of each of the two fields that say "the root has
    #     been reaped", and it is `recordRootExit`.
    let reaper = spanOf(lines, "recordRootExit")
    let exitCodeWrites = assignmentsTo(lines, "exitCode")
    let exitedWrites = assignmentsTo(lines, "exited")
    checkpoint("`.exitCode =` writers at lines " &
      $exitCodeWrites.mapIt(it + 1) & "; `.exited =` writers at lines " &
      $exitedWrites.mapIt(it + 1) & "; recordRootExit spans " &
      $(reaper.first + 1) & ".." & $(reaper.last + 1))
    check exitCodeWrites.len == 1
    check exitedWrites.len == 1
    for idx in exitCodeWrites & exitedWrites:
      check idx >= reaper.first and idx <= reaper.last

    # (B) …and BOTH launch paths go through it, so the single writer is genuinely
    #     shared rather than one path's private helper.
    let calls = callSitesOf(lines, "recordRootExit")
    let poll = spanOf(lines, "pollMonitor")
    let waitRoot = spanOf(lines, "waitForMonitorRoot")
    checkpoint("recordRootExit called at lines " & $calls.mapIt(it + 1) &
      "; pollMonitor spans " & $(poll.first + 1) & ".." & $(poll.last + 1) &
      "; waitForMonitorRoot spans " & $(waitRoot.first + 1) & ".." &
      $(waitRoot.last + 1))
    for idx in calls:
      check (idx >= poll.first and idx <= poll.last) or
            (idx >= waitRoot.first and idx <= waitRoot.last)
    check calls.anyIt(it >= poll.first and it <= poll.last)
    check calls.anyIt(it >= waitRoot.first and it <= waitRoot.last)

    # (C) RUNTIME: the two paths agree on a NON-ZERO status, which the polled
    #     path learns from `peekExitCode` and the batch path from `waitForExit`.
    check shmGSetSupported
    check ensureShim().len > 0
    setUpFixtures()

    let failingCommand = proc (runDir: string): seq[string] =
      @[exitWithProbe, runDir / "marker.txt", "7"]

    let batch = runOneAction(lpBatch, failingCommand, gatedRelease = false)
    let host = runOneAction(lpPolledHost, failingCommand, gatedRelease = false)
    checkpoint("exit codes: batch=" & $batch.exitCode & " polled=" &
      $host.exitCode)
    check batch.exitCode == 7
    check host.exitCode == 7
    check batch.exitCode == host.exitCode

    # …and the evidence is identical for a FAILING action too, which is the case
    # a build engine actually has to grade.
    let batchNorm = renderEvidence(batch.depFile, norm = true)
    let hostNorm = renderEvidence(host.depFile, norm = true)
    checkpoint("first difference (normalised): " &
      firstDifference(batchNorm, hostNorm))
    check batchNorm == hostNorm

  test "t_the_normalisation_cannot_mask_a_real_difference":
    ## The comparison above is worth exactly as much as its normalisation is
    ## narrow. This case takes REAL evidence — produced here, by the real
    ## monitor, not hand-built — and perturbs it, demanding that the normalised
    ## rendering CHANGE for every perturbation a regression could produce and NOT
    ## change for the two things the normalisation exists to erase.
    check shmGSetSupported
    check ensureShim().len > 0
    setUpFixtures()

    let gatedCommand = proc (runDir: string): seq[string] =
      @[descendantProbe, runDir / "marker.txt", runDir / "proof", "0", "0",
        runDir / "release"]
    let real = runOneAction(lpBatch, gatedCommand, gatedRelease = true).depFile
    let baseline = renderEvidence(real, norm = true)
    checkpoint("baseline: " & $real.records.len & " records, completeness=" &
      $real.completeness & ", loss markers=" & $lossDetails(real).len)
    check real.records.len > 3
    check real.completeness == mcIncomplete

    # Determinism first: the same evidence renders the same way twice. Without
    # this, every "differs" below could be noise.
    check renderEvidence(real, norm = true) == baseline

    # The pid map's RESERVED VALUE, asserted at the normaliser itself rather than
    # through a perturbation. `0` is not a pid, it is "no pid", and giving it a
    # token would let a record that LOST ITS PARENT render exactly like one whose
    # parent is simply another process — the two runs are normalised by
    # independent `Norm`s, so nothing stops the same token index landing on `0`
    # in one and on a real pid in the other.
    #
    # MEASURED during verification: mutating `pidTok` to map `0` like any other
    # value reddened NONE of the perturbations below. A rule this file states in
    # its own header, and `docs/usage.md` alongside it, was resting on no
    # assertion at all — so it is measured directly, which is also the cheaper
    # and more honest way to pin a property of a two-line pure function.
    block:
      var n = newNorm()
      check pidTok(n, 0'u64) == "0"
      check pidTok(n, 4321'u64) == "P0"     # `0` consumed no token
      check pidTok(n, 0'u64) == "0"         # …and still does not
      check pidTok(n, 4321'u64) == "P0"     # a real pid is stable
      check pidTok(n, 8765'u64) == "P1"     # and distinct values stay distinct

    template checkDiffers(label: string; mutated: MonitorDepFile) =
      ## A `template`, not a `proc`: a `check` inside a plain `proc` prints
      ## "Check failed" and leaves the case labelled `[OK]`.
      let rendered = renderEvidence(mutated, norm = true)
      checkpoint("perturbation `" & label & "` -> " &
        (if rendered == baseline: "MASKED, rendering unchanged"
         else: firstDifference(baseline, rendered)))
      check rendered != baseline

    template checkSame(label: string; mutated: MonitorDepFile) =
      let rendered = renderEvidence(mutated, norm = true)
      checkpoint("declared exclusion `" & label & "` -> " &
        (if rendered == baseline: "erased, as intended"
         else: firstDifference(baseline, rendered)))
      check rendered == baseline

    # The indices the perturbations target. Each lookup RAISES rather than
    # settling for -1, so a perturbation can never silently hit nothing.
    var lossIdx = -1
    var spawnIdx = -1
    var localFdIdxs: seq[int] = @[]
    var posResultIdx = -1
    var negResultIdx = -1
    for i, rec in real.records:
      if rec.kind == mrEventLoss and
          "linux injected descendants still live" in rec.detail:
        if lossIdx >= 0:
          raise newException(ValueError,
            "expected exactly one §4.1 loss record, found at least two")
        lossIdx = i
      if rec.kind == mrProcessSpawn and rec.childOsPid != 0 and spawnIdx < 0:
        spawnIdx = i
      if rec.path.startsWith(LocalFdPrefix):
        localFdIdxs.add i
      if rec.kind != mrProcessSpawn and rec.result > 0 and posResultIdx < 0:
        posResultIdx = i
      if rec.kind != mrProcessSpawn and rec.result < 0 and negResultIdx < 0:
        negResultIdx = i
    if lossIdx < 0:
      raise newException(ValueError,
        "expected a §4.1 loss record in the gated run's evidence, found none")
    if spawnIdx < 0:
      raise newException(ValueError,
        "expected an mrProcessSpawn carrying a childOsPid, found none")
    if localFdIdxs.len < 2:
      raise newException(ValueError,
        "expected at least two `localfd:` channel records (the fixture's pipe), " &
          "found " & $localFdIdxs.len)
    if posResultIdx < 0:
      raise newException(ValueError,
        "expected a NON-spawn record with a POSITIVE `result` (a byte count), " &
          "found none")
    if negResultIdx < 0:
      raise newException(ValueError,
        "expected a NON-spawn record with a NEGATIVE `result` (a failed " &
          "probe), found none")
    checkpoint("targets: loss=" & $lossIdx & " spawn=" & $spawnIdx &
      " localfd=" & $localFdIdxs & " posResult=" & $posResultIdx &
      " negResult=" & $negResultIdx)

    # ---- (1) a record disappears ------------------------------------------
    block:
      var m = real
      m.records.delete(m.records.high)
      checkDiffers("drop the last record", m)

    # ---- (2) a record appears twice ---------------------------------------
    block:
      var m = real
      m.records.add m.records[0]
      checkDiffers("duplicate a record", m)

    # ---- (3) the verdict flips — the cardinal sin, in one field -----------
    block:
      var m = real
      m.completeness = mcComplete
      checkDiffers("completeness mcIncomplete -> mcComplete", m)

    # ---- (4) the loss marker is deleted -----------------------------------
    block:
      var m = real
      m.records.delete(lossIdx)
      checkDiffers("delete the §4.1 loss record", m)

    # ---- (5) a REAL path changes by ONE character -------------------------
    block:
      var m = real
      var i = -1
      for k, rec in m.records:
        if rec.path.len > 0 and not rec.path.startsWith(LocalFdPrefix):
          i = k
          break
      if i < 0:
        raise newException(ValueError, "no record carries a real path to perturb")
      m.records[i].path = m.records[i].path & "x"
      checkDiffers("append one character to a real path", m)

    # ---- (6) an observation kind changes ----------------------------------
    block:
      var m = real
      m.records[0].observationKind =
        if m.records[0].observationKind == moFileRead: moFileWrite
        else: moFileRead
      checkDiffers("change an observationKind", m)

    # ---- (7) a NON-spawn record's `result` changes ------------------------
    #      `result` is only normalised for `mrProcessSpawn`; everywhere else it
    #      is a byte count or a failed-probe status and must compare verbatim.
    #
    #      BOTH SIGNS, and the reason is measured rather than tidy. A first draft
    #      of this control picked "the first non-spawn record with a non-zero
    #      `result`", which on this fixture is a `prAbsent` probe carrying `-1`,
    #      and mutated it to `-1 + 1 = 0`. Against a mutation that normalised
    #      `result` on EVERY kind, that control still reddened — but only by
    #      accident, because 0 is the pid map's reserved "no pid" value, so the
    #      perturbation crossed a special case rather than testing the rule. The
    #      mutation was inert against everything else and the gap was invisible.
    #      Two perturbations that stay within one sign close it: a byte count
    #      5 → 6 and a failed probe -1 → -2 both map to a FRESH token under that
    #      mutation and would therefore render identically, so the control now
    #      catches it.
    block:
      var m = real
      m.records[posResultIdx].result = m.records[posResultIdx].result + 1
      checkDiffers("change a non-spawn record's positive result", m)
    block:
      var m = real
      m.records[negResultIdx].result = m.records[negResultIdx].result - 1
      checkDiffers("change a non-spawn record's negative result", m)

    # ---- (8) open flags change --------------------------------------------
    block:
      var m = real
      m.records[0].flags = m.records[0].flags xor 1'u32
      checkDiffers("change a record's flags", m)

    # ---- (9) the summary disagrees with the records -----------------------
    block:
      var m = real
      m.summary.recordCount = m.summary.recordCount + 1
      checkDiffers("change summary.recordCount", m)

    # ---- (10) TWO DISTINCT PIDS COLLAPSE INTO ONE -------------------------
    #      The control that matters most: it proves the pid map is a BIJECTION
    #      and not a redaction. If it merely blanked pids out, this would be
    #      invisible — and "two processes' reads were attributed to one" is
    #      exactly the regression a build engine must not inherit.
    block:
      var m = real
      var firstPid = 0'u64
      var otherIdx = -1
      for k, rec in m.records:
        if rec.osPid == 0: continue
        if firstPid == 0'u64:
          firstPid = rec.osPid
        elif rec.osPid != firstPid:
          otherIdx = k
          break
      if otherIdx < 0:
        raise newException(ValueError,
          "the fixture produced only one distinct osPid — the collapse control " &
            "cannot run, and passing it silently would be worse than failing")
      m.records[otherIdx].osPid = firstPid
      checkDiffers("collapse two distinct osPids into one", m)

    # ---- (11) an extra pid joins the `pids=` list -------------------------
    #      Proves the list normalisation preserves CARDINALITY: a guard that
    #      found two descendants must not render like one that found one.
    block:
      var m = real
      m.records[lossIdx].detail =
        m.records[lossIdx].detail.replace("pids=", "pids=999999,")
      checkDiffers("add a pid to the `pids=` list", m)

    # ---- (12) a spawn's `result` stops agreeing with its `childOsPid` -----
    #      The boundary of exclusion (2): normalising the spawn `result` erases
    #      WHICH pid it is, never the fact that it is the record's own child.
    block:
      var m = real
      m.records[spawnIdx].result = int64(m.records[spawnIdx].childOsPid) + 1
      checkDiffers("a spawn's result no longer equals its childOsPid", m)

    # ---- (13) two channel records get DIFFERENT inodes --------------------
    #      Proves the inode map is a bijection too: "both records describe the
    #      same pipe" is evidence, and must not survive being made false.
    block:
      var m = real
      let p = m.records[localFdIdxs[1]].path
      m.records[localFdIdxs[1]].path = p & "9"
      checkDiffers("give two channel records different inodes", m)

    # ---- (14) the `localfd` DEVICE changes --------------------------------
    #      Only the third component is normalised; the scheme and the device are
    #      compared verbatim.
    block:
      var m = real
      let p = m.records[localFdIdxs[0]].path
      let rest = p[LocalFdPrefix.len .. ^1]
      let colon = rest.find(':')
      m.records[localFdIdxs[0]].path =
        LocalFdPrefix & "99" & rest[colon .. ^1]
      checkDiffers("change a `localfd:` device", m)

    # ---- (14b) EVERY `localfd` device changes, CONSISTENTLY ---------------
    #      (14) alone does not say what it looks like it says. It changes ONE
    #      record's device, which breaks the SHARING between the two channel
    #      records — so it still reddens under a renderer that tokenised the
    #      device through a bijection, and "the device is compared verbatim"
    #      would be false while the table row read like coverage. MEASURED: a
    #      mutation that sends the device through the inode map reddens nothing
    #      without this control. Changing every device consistently is a
    #      renaming, so only a VERBATIM comparison can see it.
    block:
      var m = real
      for k in localFdIdxs:
        let p = m.records[k].path
        let rest = p[LocalFdPrefix.len .. ^1]
        let colon = rest.find(':')
        m.records[k].path =
          LocalFdPrefix & $(parseBiggestInt(rest[0 ..< colon]) + 1) &
            rest[colon .. ^1]
      checkDiffers("change EVERY `localfd:` device consistently", m)

    # ---- (15) a NON-token word inside the loss detail changes -------------
    #      Proves the detail normalisation is lexically narrow: it rewrites the
    #      `run=` and `pids=` tokens and nothing else, so a changed diagnostic is
    #      still a difference.
    block:
      var m = real
      m.records[lossIdx].detail =
        m.records[lossIdx].detail.replace("still live", "still alive")
      checkDiffers("change a non-token word in the loss detail", m)

    # ---- (16) DECLARED EXCLUSION: the run id ------------------------------
    #      Changing ONLY the run stamp must render identically — that is what
    #      "the run id necessarily differs" means as an executable claim. Paired
    #      with (15), it bounds the exclusion from both directions.
    block:
      var m = real
      let d = m.records[lossIdx].detail
      let at = d.find(" run=")
      if at < 0:
        raise newException(ValueError,
          "the §4.1 loss detail carries no ` run=` stamp — the exclusion this " &
            "case is about does not exist as described")
      m.records[lossIdx].detail = d[0 ..< at] & " run=some-other-run-id"
      checkSame("replace the run id", m)

    # ---- (17) DECLARED EXCLUSION: a wholesale pid RENAMING ----------------
    #      Replacing every pid with a different one, structure preserved, is
    #      precisely the equivalence class the bijection defines, so it renders
    #      the same. Asserted so nobody mistakes it for a hole: it is the
    #      definition, and (10) is its boundary.
    block:
      var m = real
      const shift = 1_000_000'u64
      for k in 0 ..< m.records.len:
        if m.records[k].osPid != 0: m.records[k].osPid += shift
        if m.records[k].parentOsPid != 0: m.records[k].parentOsPid += shift
        if m.records[k].threadId != 0: m.records[k].threadId += shift
        if m.records[k].childOsPid != 0: m.records[k].childOsPid += shift
        if m.records[k].kind == mrProcessSpawn and m.records[k].result != 0:
          m.records[k].result += int64(shift)
      let d = m.records[lossIdx].detail
      let at = d.find("pids=")
      let start = at + len("pids=")
      var stop = start
      while stop < d.len and d[stop] != ' ': inc stop
      var toks: seq[string] = @[]
      for item in d[start ..< stop].split(','):
        toks.add $(uint64(parseBiggestInt(item)) + shift)
      m.records[lossIdx].detail =
        d[0 ..< start] & toks.join(",") & d[stop .. ^1]
      checkSame("rename every pid, structure preserved", m)

    removeDir(workRoot)
