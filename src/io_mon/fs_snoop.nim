import std/[atomics, os, osproc, strtabs, strutils, times]
from io_mon/paths import extendedPath

import io_mon/reader
import io_mon/render
import io_mon/types
import io_mon/writer
import io_mon/shm/dep_queue
# io-mon-Lossless-Event-Capture M3 (part 1) — the CONSUMER hosts a nim-shm-gset
# (the M1-winning SET transport) as the new primary Linux dependency channel; it
# decodes the merged set with dep_queue's `decodeDepRecord`. `shmGSetSupported`
# gates the Linux arm; `transport` is the §5 host lifecycle.
import shm_gset as shmset_core
import shm_gset/transport as shmset

when defined(linux):
  import std/[algorithm, monotimes, posix]

  const
    LinuxInjectedDescendantGraceMsDefault = 500
    LinuxInjectedDescendantPollMsDefault = 25
    ## `/proc/<pid>/stat` is one generated line: a 16-byte comm plus ~50 numeric
    ## fields, so 4 KiB holds it with room to spare. A pid whose line somehow did
    ## NOT fit still yields its run state (field 3, immediately after the comm)
    ## and is then treated as "start time unknown", which keeps it a CANDIDATE —
    ## the safe direction, and the same answer HEAD gave.
    ProcStatBufLen = 4096
    ## STARTING capacity for the `/proc/<pid>/environ` read, not a cap: the
    ## read loop doubles the buffer whenever it fills, so an environ larger than
    ## this is read WHOLE and a needle sitting past 64 KiB is still found. That
    ## matters — environs here reach 244 KiB, and a truncating read would be a
    ## missed descendant, i.e. a false `mcComplete`. Sized so the common case
    ## takes one allocation. With the prune armed only a handful of processes
    ## per sweep get this far; with it disabled (`rootStartTicks == 0`) every
    ## process whose environ is readable does.
    ##
    ## THE GROWTH IS NOT PINNED BY THE SUITE, and the reason is worth knowing
    ## before someone "simplifies" it away. Replacing the doubling with a
    ## `break` reddens NOTHING in the tree — not because the fixtures' environs
    ## are small (they are not; a fixture given 320 KiB through
    ## `FsSnoopRequest.env` really carries it) but because `childEnv` composes a
    ## `StringTable` and the two needles land at whatever byte offsets its
    ## iteration order gives them. Measured across padded runs, the SESSION
    ## needle lands late (110 KiB / 543 KiB / 1018 KiB for 360 KiB / 843 KiB /
    ## 1647 KiB environs) while the FRAGMENT_DIR needle lands at 123 B / 4 KiB /
    ## 12 KiB — so the OR of the two conjuncts finds the descendant through the
    ## early needle no matter how badly the read truncates. That is an accident
    ## of hashing over a caller-controlled key set, not a property anything
    ## guarantees, so the growth stays. It IS measured, by driving
    ## `liveInjectedDescendants` directly against a carrier whose ONLY needle
    ## sits at the end of a 400 KiB environ; that check fails without the
    ## doubling and passes with it.
    ProcEnvironChunkLen = 64 * 1024

  proc openat(dirfd: cint; path: cstring; flags: cint): cint
    {.importc, header: "<fcntl.h>", sideEffect.}
  let AT_FDCWD {.importc, header: "<fcntl.h>".}: cint
  proc dirfd(dirp: ptr DIR): cint
    {.importc, header: "<dirent.h>", sideEffect.}

  proc envInt(name: string; defaultValue, minValue: int): int =
    let raw = getEnv(name)
    if raw.len == 0:
      return defaultValue
    try:
      result = parseInt(raw)
      if result < minValue:
        result = minValue
    except ValueError:
      result = defaultValue

  proc readProcFileAt(dirfd: cint; relPath: cstring; buf: var openArray[char]):
      int =
    ## open+read+close one small `/proc` file into a caller-owned buffer.
    ## `-1` means "could not read it", which every caller treats exactly as the
    ## old `readFile` exception did: skip this pid.
    ##
    ## The point of doing this by hand rather than with `readFile` is that a
    ## `/proc` sweep performs 2-3 of these PER PROCESS ON THE MACHINE, and
    ## `readFile` on a procfs file (apparent size 0) allocates a string, grows
    ## it, and copies — measured at roughly 2x the raw syscall cost, on top of
    ## the GC traffic.
    let fd = openat(dirfd, relPath, O_RDONLY or O_CLOEXEC)
    if fd < 0:
      return -1
    let n = posix.read(fd, addr buf[0], buf.len)
    discard posix.close(fd)
    if n <= 0:
      return -1
    int(n)

  proc parseProcStat(buf: openArray[char]; n: int;
                     state: var char; startTicks: var uint64): bool =
    ## Pull field 3 (run state) and field 22 (start time, in USER_HZ ticks since
    ## boot) out of one `/proc/<pid>/stat` line. Both live after the ')' that
    ## closes the comm field, which is the only field that may itself contain
    ## spaces or parentheses — hence the scan from the END for ')'.
    ##
    ## The RESULT reports only whether the run state was recovered, because that
    ## is the conjunct HEAD's `linuxProcState` gated on and skipped the pid for.
    ## The start time is reported out-of-band: `startTicks = 0` means "could not
    ## tell", and every caller reads that as "do not prune this pid". So a stat
    ## line this parser cannot fully understand costs a wasted environ read, not
    ## a missed descendant.
    startTicks = 0
    var closeParen = -1
    for i in countdown(n - 1, 0):
      if buf[i] == ')':
        closeParen = i
        break
    if closeParen < 0 or closeParen + 2 >= n:
      return false
    state = buf[closeParen + 2]
    var idx = closeParen + 2
    var field = 3
    while idx < n and field < 22:
      while idx < n and buf[idx] != ' ': inc idx
      while idx < n and buf[idx] == ' ': inc idx
      inc field
    if field != 22 or idx >= n:
      return true
    var value = 0'u64
    var digits = 0
    while idx < n and buf[idx] in {'0' .. '9'}:
      value = value * 10 + uint64(ord(buf[idx]) - ord('0'))
      inc idx
      inc digits
    if digits > 0:
      startTicks = value
    true

  proc procStartTicks(pid: uint64): uint64 =
    ## Field 22 of `/proc/<pid>/stat`: when this process was created, in USER_HZ
    ## ticks since boot. `0` means "unknown" (the process is already gone, or
    ## `/proc` is not mounted), and every caller reads `0` as "do not filter" —
    ## i.e. the old exhaustive sweep, never a narrower one.
    ##
    ## PRIVATE on purpose, like `liveInjectedDescendants` itself: `io_mon`
    ## re-exports all of `fs_snoop`, so a `*` here would put a raw `/proc` reader
    ## on the package's public surface for no caller that needs it.
    var buf {.noinit.}: array[ProcStatBufLen, char]
    let path = "/proc/" & $pid & "/stat"
    let n = readProcFileAt(AT_FDCWD, path.cstring, buf)
    if n <= 0:
      return 0
    var state = '\0'
    var ticks = 0'u64
    if not parseProcStat(buf, n, state, ticks):
      return 0
    ticks

  proc environCarriesInvocation(buf: openArray[char]; n: int;
                                sessionNeedle, fragmentNeedle: string): bool =
    ## Does this `/proc/<pid>/environ` image contain either needle as a WHOLE
    ## NUL-delimited entry? Same predicate as the old
    ## `environ.split('\0')` + `==` loop, without materialising one Nim string
    ## per environment variable: environs on a dev box routinely run to 200 KiB,
    ## and the split alone measured ~76 ms across one machine's processes.
    var start = 0
    while start < n:
      var stop = start
      while stop < n and buf[stop] != '\0': inc stop
      let entryLen = stop - start
      if entryLen == sessionNeedle.len and
         equalMem(unsafeAddr buf[start], unsafeAddr sessionNeedle[0],
                  entryLen):
        return true
      if entryLen == fragmentNeedle.len and
         equalMem(unsafeAddr buf[start], unsafeAddr fragmentNeedle[0],
                  entryLen):
        return true
      start = stop + 1
    false

  proc liveInjectedDescendants(runId, fragmentDir: string; rootPid: uint64;
                               minStartTicks: uint64):
      tuple[pids: seq[int]; scanFailed: bool] =
    ## The §4.1 detector: which processes on this machine still carry THIS
    ## monitor's injection markers in their environment?
    ##
    ## ── THE PREDICATE (unchanged) ──────────────────────────────────────────
    ## A pid counts iff its `/proc/<pid>/stat` is readable, its run state is not
    ## `Z`, its `/proc/<pid>/environ` is readable, and that environ contains
    ## `REPRO_MONITOR_SESSION=<runId>` or `REPRO_MONITOR_FRAGMENT_DIR=<dir>` as
    ## a whole entry. Every one of those conjuncts is still evaluated here, and
    ## a pid failing any of them is skipped exactly as before. What changed is
    ## the ORDER and the START-TIME PRUNE below, not the answer.
    ##
    ## ── WHY THE ORDER CHANGED ──────────────────────────────────────────────
    ## This sweep is O(processes on the machine) and it runs on the critical
    ## path of every `finishMonitor`. The old shape cost ~105 ms per monitored
    ## action on a 900-process box and ~160 ms on the same box at ~1100
    ## processes — measured — because it read `/proc/<pid>/stat` AND the full
    ## `/proc/<pid>/environ` for every process, then split each environ into one
    ## Nim string per variable. Where that time went, measured at 900 processes
    ## by building each step on its own (medians of 25 sweeps):
    ##
    ##   ~105 ms   HEAD
    ##    ~43 ms   raw syscalls instead of `readFile`/`walkDir`/`split`, old
    ##             conjunct order  (so the allocation and copying were the
    ##             LARGEST single item, not the wasted opens)
    ##    ~29 ms   + conjuncts evaluated cheapest-first (below)
    ##   5-11 ms   + the start-time prune
    ##
    ## So the conjuncts are now evaluated cheapest-first:
    ##
    ##   1. `openat` the environ. Failure here is the same skip the old code
    ##      took when `readFile` raised, so this is the SAME test, moved
    ##      earlier: it costs one failed `open` (~10 us) instead of a stat read
    ##      plus a failed open, and on a shared machine it retires ~90% of pids.
    ##   2. read `/proc/<pid>/stat` (state AND start time, one read).
    ##   3. the START-TIME PRUNE (below).
    ##   4. only now, read the environ and scan it.
    ##
    ## ── WHY THE START-TIME PRUNE IS SOUND ──────────────────────────────────
    ## `minStartTicks` is the monitored ROOT's own start time, taken from field
    ## 22 of its `/proc/<pid>/stat` in `startMonitor`. Both needles are minted
    ## before the spawn and travel ONLY through the spawn's environment
    ## (DH-1: nothing outside `childEnv` writes either name into any
    ## environment), so a process can carry one only by having inherited it
    ## from the root — i.e. only by being a descendant of the root,
    ## and therefore only by having been created after the root was. A process
    ## whose start time is strictly less than the root's is not a descendant of
    ## the root; it is a fact about process creation, not a heuristic, and it
    ## does not depend on permissions, pid ordering, pid reuse, or the clock
    ## (both values are the same kernel counter, in the same units, read from
    ## the same file).
    ##
    ## `minStartTicks == 0` disables the prune entirely, which is what a handle
    ## carries when the root's start time could not be read. That degrades to
    ## the old full sweep — slower, never blinder.
    ##
    ## The prune's soundness is a CROSS-MILESTONE dependency, not a local one:
    ## it holds only because nothing outside `childEnv` ever writes either
    ## needle into any environment (DH-1). See the note on `childEnv`, which is
    ## where a future editor would break it.
    ##
    ## ── AN OPTIMISATION DELIBERATELY NOT TAKEN ─────────────────────────────
    ## A UID pre-filter — skip any pid whose `/proc/<pid>` is not owned by us,
    ## before doing anything else — was built and measured, and is REJECTED.
    ## It is not even faster once the start-time prune is in place: on a
    ## 900-process box, medians of 25 sweeps, 5.0-6.4 ms with the uid filter
    ## against 5.5-10.7 ms without it, which is inside the run-to-run spread.
    ## And it would not be worth taking if it were, because its premise is not
    ## a fact about process creation but a fact about ptrace permissions: "a
    ## descendant running as another user is one whose environ we could not
    ## have read anyway". That is true for an ordinary host and
    ## FALSE for a privileged one — a host holding `CAP_SYS_PTRACE` (or running
    ## as root) passes `ptrace_may_access` for any pid, so it CAN read the
    ## environ of a setuid or `sudo`-launched descendant that the uid filter
    ## would have skipped. The guard would then be narrowest on exactly the
    ## hosts that can see the most, and nothing here would say why. The
    ## start-time prune has no such dependency: a descendant cannot predate its
    ## own ancestor whatever the caller's capabilities are.
    var dir = opendir("/proc")
    if dir == nil:
      return (@[], true)
    defer: discard closedir(dir)
    let fd = dirfd(dir)
    if fd < 0:
      return (@[], true)
    let selfPid = getCurrentProcessId()
    let sessionNeedle = "REPRO_MONITOR_SESSION=" & runId
    let fragmentNeedle = "REPRO_MONITOR_FRAGMENT_DIR=" & fragmentDir
    var statBuf {.noinit.}: array[ProcStatBufLen, char]
    var envBuf = newSeq[char](ProcEnvironChunkLen)
    var relPath {.noinit.}: array[32, char]
    while true:
      # `readdir` answers `nil` both for "end of directory" and for a read
      # error, told apart only by `errno` — so zeroing it before every call is
      # load-bearing, not hygiene. A read error must become `scanFailed`, which
      # is what publishes an `mrEventLoss` instead of a silent "no descendants".
      #
      # This is STRICTER than HEAD rather than a translation of it. HEAD walked
      # `/proc` with `walkDir`, whose `checkDir` parameter defaults to FALSE: a
      # failed `opendir` yields nothing and raises nothing, and the read loop is
      # `if x == nil: break` with no `errno` check at all — so HEAD's `except
      # OSError` never fired for either fault, and both were reported as "no
      # descendants live", i.e. a silent `mcComplete`. Measured by fault
      # injection on this box (an `LD_PRELOAD` failing `opendir("/proc")` with
      # `EACCES`, and one returning `nil` + `EIO` from the 20th `readdir` on
      # that `DIR*`): HEAD grades `mcComplete` with no marker under both, this
      # shape grades `mcIncomplete` with `linux injected-descendant /proc scan
      # failed` under both, and both grade `mcComplete` with the injector loaded
      # but disarmed. NOT covered by any test in the suite — forcing a `readdir`
      # error needs an out-of-tree `LD_PRELOAD`, and the suite has no hook for
      # one.
      errno = 0.cint
      let entry = readdir(dir)
      if entry == nil:
        if errno != 0.cint:
          return (@[], true)
        break
      let name = cast[cstring](addr entry.d_name[0])
      if name[0] notin {'0' .. '9'}:
        continue
      # A real pid fits in 7 digits (`pid_max` maxes out at 2^22); the loop
      # bound below is 10, the point at which a name has stopped being plausibly
      # a pid at all. Either figure keeps `pid` far from overflow and `relPath`
      # far from its 32-byte capacity (10 digits + "/environ" + NUL = 19).
      var pid = 0
      var i = 0
      var numeric = true
      while name[i] != '\0':
        if name[i] notin {'0' .. '9'} or i >= 10:
          numeric = false
          break
        pid = pid * 10 + (ord(name[i]) - ord('0'))
        inc i
      if not numeric or i == 0:
        continue
      if pid == selfPid or uint64(pid) == rootPid:
        continue

      # (1) Can we read this process's environment at all? The old code found
      # this out by letting `readFile` raise after it had already read the stat
      # file; asking first is the same question, one syscall earlier.
      for k in 0 ..< i: relPath[k] = char(name[k])
      var w = i
      for c in "/environ": relPath[w] = c; inc w
      relPath[w] = '\0'
      let envFd = openat(fd, cast[cstring](addr relPath[0]),
                         O_RDONLY or O_CLOEXEC)
      if envFd < 0:
        continue

      # (2) run state + start time, from ONE read of `/proc/<pid>/stat`.
      w = i
      for c in "/stat": relPath[w] = c; inc w
      relPath[w] = '\0'
      let statLen = readProcFileAt(fd, cast[cstring](addr relPath[0]), statBuf)
      var state = '\0'
      var startTicks = 0'u64
      if statLen <= 0 or not parseProcStat(statBuf, statLen, state, startTicks):
        discard posix.close(envFd)
        continue
      if state == 'Z':
        discard posix.close(envFd)
        continue

      # (3) the start-time prune. `startTicks == 0` is "this stat line did not
      # tell us", and it keeps the pid as a CANDIDATE — an unparseable stat line
      # must never be the reason a live descendant goes unreported.
      if minStartTicks > 0 and startTicks > 0 and startTicks < minStartTicks:
        discard posix.close(envFd)
        continue

      # (4) only now is the environ worth reading.
      var total = 0
      while true:
        if total == envBuf.len:
          envBuf.setLen(envBuf.len * 2)
        let r = posix.read(envFd, addr envBuf[total], envBuf.len - total)
        if r <= 0:
          break
        total += int(r)
      discard posix.close(envFd)
      if total > 0 and
         environCarriesInvocation(envBuf, total, sessionNeedle, fragmentNeedle):
        result.pids.add pid

  proc emitLauncherLossToSet(path0: string; rec: MonitorRecord): bool =
    ## io-mon-Lossless-Event-Capture M7 (Linux slice) — insert a consumer-side
    ## launcher event-loss marker into the edge's consumer-owned `nim-shm-gset` (the
    ## same set the shim's producers publish into), so `runFsSnoop`'s finalize
    ## `snapshot` folds it into the depfile as an `mrEventLoss` → `mcIncomplete`,
    ## with NO `.rmdf-frag` file. Attaches a short-lived producer to the host's
    ## `path0` (the host is still alive here — `finish()` runs later, on proc exit),
    ## emits ONE idempotent element, and detaches. Returns true when the marker is
    ## durable in consumer-owned memory (LF-3). The element is run-stamped in
    ## `rec.detail`, so `mergeFragments`' run-scoping keeps it for this run.
    if path0.len == 0:
      return false
    var prod = shmset.attachProducer(path0)
    if not prod.available:
      prod.detach()
      return false
    var buf {.noinit.}: array[512, byte]
    let n = encodeDepRecordIdentity(rec, buf)
    result = false
    if n >= 0:
      case prod.emit(buf.toOpenArray(0, n - 1))
      of emInserted, emExists, emSaturated, emConsumerGone:
        result = true
      of emOversize, emUnavailable:
        result = false
    prod.detach()

  proc appendLauncherEventLoss*(fragmentDir, runId, detail: string;
      depSetPath0 = "") =
    ## Record a launcher-side event-loss for THIS run. On Linux the loss is
    ## published into the consumer-owned `nim-shm-gset` at `depSetPath0` (M7 Linux
    ## slice — file-free), so `writer.hostUsesFileFallback` is `false` and no
    ## `.rmdf-frag` is written. The `.rmdf-frag` writer is used ONLY as the fallback
    ## when the set is unavailable (the `REPRO_MONITOR_DEP_SHM_DISABLE` pure-file
    ## baseline) — matching the shared file producer that macOS/Windows still use.
    let rec = MonitorRecord(
      kind: mrEventLoss,
      observationKind: moEventLoss,
      osPid: uint64(getCurrentProcessId()),
      detail: detail & " run=" & runId)
    if not hostUsesFileFallback and emitLauncherLossToSet(depSetPath0, rec):
      return
    appendFragmentRecord(fragmentDir, rec)

  proc waitForLinuxInjectedDescendants(fragmentDir, runId: string;
      rootPid: uint64; minStartTicks: uint64; depSetPath0 = "") =
    let graceMs = envInt("IO_MON_LINUX_DESCENDANT_GRACE_MS",
      LinuxInjectedDescendantGraceMsDefault, 0)
    let pollMs = envInt("IO_MON_LINUX_DESCENDANT_POLL_MS",
      LinuxInjectedDescendantPollMsDefault, 1)
    let start = getMonoTime()
    while true:
      let live = liveInjectedDescendants(runId, fragmentDir, rootPid,
        minStartTicks)
      if live.scanFailed:
        appendLauncherEventLoss(fragmentDir, runId,
          "linux injected-descendant /proc scan failed", depSetPath0)
        return
      if live.pids.len == 0:
        return
      let elapsedMs = inMilliseconds(getMonoTime() - start)
      if elapsedMs >= graceMs:
        appendLauncherEventLoss(fragmentDir, runId,
          "linux injected descendants still live after root exit pids=" &
            live.pids.join(","), depSetPath0)
        return
      sleep(min(pollMs, graceMs - int(elapsedMs)))

# Windows: pull in the CreateRemoteThread+LoadLibraryW injector that
# substitutes for the macOS DYLD_INSERT_LIBRARIES env-var injection.
when defined(windows):
  import stackable_hooks/windows_injector

# macOS: prepare a sandbox-tools directory holding non-SIP drop-ins for the
# common system binaries that show up in monitored subprocess trees. The
# shim's spawn hook (see repro_monitor_hooks/macos_interpose_runtime.nim)
# rewrites SIP-protected exec paths to these drop-ins (``rewriteExecPathForSip``
# → ``rewriteSipPath``) so that DYLD_INSERT_LIBRARIES is not stripped on the way
# into /bin/sh, /bin/cat and friends — the path-rewriting bypass documented in
# codetracer-native-recorder/ct_interpose/src/ct_interpose/library_init.nim and
# in reprobuild-specs/Portable-Macos-Sandbox-Tools.milestones.org.
#
# WHY a drop-in and not a copy (SIP/AMFI rationale): on macOS 26 / Apple
# Silicon, System Integrity Protection strips DYLD_INSERT_LIBRARIES when a
# binary under /bin, /sbin, /usr/bin or /usr/sbin is exec'd, AND AMFI SIGKILLs
# a *copy* of a restricted platform binary on launch even when ad-hoc re-signed
# (measured). So the drop-in MUST be a NON-SIP binary we resolve elsewhere —
# typically the Nix-provided coreutils/bash in the dev shell, or a portable
# bundle built by scripts/build-sandbox-tools.sh. ``findNonSipAlternative``
# resolves it on PATH; ``populateReproSandboxTools`` symlinks each SIP path to
# that non-SIP instance.
#
# COVERAGE: a monitored test process tree shells out far past the four shells
# the original route-B populate covered — a bare ``system("cat X")`` or
# ``head``/``grep``/``sed`` in a Makefile recipe would otherwise exec the SIP
# binary, lose DYLD_INSERT_LIBRARIES, and go blind for that whole subtree. We
# therefore drop in the realistic POSIX/coreutils tool set at BOTH its /bin and
# /usr/bin SIP locations (macOS ships many tools at both, and a given test may
# invoke either path). The list is data-driven so it stays DRY and is easy to
# extend; each entry is verified to exist before being dropped in.
#
# FAIL-SAFE (preserved): a tool with no non-SIP alternative on PATH (and whose
# byte-copy fallback is AMFI-killed at launch) is simply NOT dropped in. Its
# exec then runs the SIP original, the shim falls silent for that subtree, and
# the monitored action re-runs — never a fabricated/false "captured nothing"
# skip. Coverage only ever makes MORE of the tree observable; it never makes a
# previously-correct capture wrong.
when defined(macosx):
  import stackable_hooks/propagation as ct_propagation

  const reproSandboxBinaries = [
    # Shells (the original route-B set — the most common SIP exec target via
    # ``osproc.execCmdEx`` / ``quoteShellCommand`` and ``system(3)``).
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/bin/csh",
    "/bin/tcsh",
    "/bin/ksh",
    # Core file utilities at their /bin SIP locations.
    "/bin/cat",
    "/bin/ls",
    "/bin/cp",
    "/bin/mv",
    "/bin/rm",
    "/bin/mkdir",
    "/bin/rmdir",
    "/bin/ln",
    "/bin/pwd",
    "/bin/echo",
    "/bin/date",
    "/bin/sleep",
    "/bin/df",
    "/bin/chmod",
    # POSIX/coreutils tools at their /usr/bin SIP locations. A Makefile recipe,
    # configure probe, or test harness commonly reaches for these via the shell.
    "/usr/bin/env",
    "/usr/bin/which",
    "/usr/bin/cat",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/wc",
    "/usr/bin/sort",
    "/usr/bin/uniq",
    "/usr/bin/cut",
    "/usr/bin/tr",
    "/usr/bin/basename",
    "/usr/bin/dirname",
    "/usr/bin/sed",
    "/usr/bin/grep",
    "/usr/bin/egrep",
    "/usr/bin/fgrep",
    "/usr/bin/awk",
    "/usr/bin/find",
    "/usr/bin/xargs",
    "/usr/bin/tar",
    "/usr/bin/gzip",
    "/usr/bin/gunzip",
    "/usr/bin/touch",
    "/usr/bin/true",
    "/usr/bin/false",
    "/usr/bin/test",
    "/usr/bin/printf",
    "/usr/bin/tee",
    "/usr/bin/expr",
    "/usr/bin/seq",
    "/usr/bin/comm",
    "/usr/bin/join",
    "/usr/bin/paste",
    "/usr/bin/od",
    "/usr/bin/cmp",
    "/usr/bin/diff",
    "/usr/bin/sleep",
    # Apple packaging/query tools. The reprobuild sandbox-tools bundle may
    # seed non-SIP drop-ins for these paths; when it does, honor them through
    # the same rewrite path as POSIX tools. When it does not, macOS fallback
    # copying is deliberately disabled below because AMFI can reject copied
    # platform binaries.
    "/usr/bin/iconutil",
    "/usr/bin/hdiutil",
    "/usr/bin/sw_vers",
    "/usr/bin/codesign"
  ]

  proc findNonSipAlternative(binaryName: string): string =
    ## Walk PATH looking for an instance of ``binaryName`` that lives
    ## outside the SIP-protected prefixes (``/bin``, ``/sbin``,
    ## ``/usr/bin``, ``/usr/sbin``). On macOS 26 / arm64e, byte-copies
    ## of system binaries refuse to execute (the kernel rejects them),
    ## so the sandbox-tools tree has to symlink to a non-SIP alternative
    ## — typically the Nix-provided shell on developer machines or the
    ## Homebrew copy on others. Returns an empty string if no candidate
    ## exists, in which case the caller falls back to a byte-copy.
    let pathEnv = getEnv("PATH")
    if pathEnv.len == 0:
      return ""
    for entry in pathEnv.split(PathSep):
      if entry.len == 0:
        continue
      let candidate = entry / binaryName
      if not fileExists(candidate):
        continue
      if ct_propagation.isSipProtected(candidate):
        continue
      return candidate
    ""

  proc populateReproSandboxTools(sandboxDir: string) =
    ## Drop in a non-SIP instance of every entry in ``reproSandboxBinaries``
    ## under ``sandboxDir``, mirroring the original SIP layout so
    ## ``rewriteSipPath`` resolves (``/bin/cat`` → ``<sandboxDir>/bin/cat``,
    ## ``/usr/bin/grep`` → ``<sandboxDir>/usr/bin/grep``). Each entry is a
    ## symlink to the non-SIP alternative found on PATH. Entries without a
    ## non-SIP source are left absent on macOS: a byte-copy of an Apple platform
    ## binary is not a valid monitorable drop-in on recent systems.
    ##
    ## Idempotent: an entry that already exists in ``sandboxDir`` (e.g. seeded
    ## by a pre-built portable bundle pointed at via CT_SANDBOX_TOOLS_DIR) is
    ## left untouched, so a distribution-grade bundle is never clobbered by the
    ## dev-shell PATH symlinks. Fail-safe: an entry with no resolvable non-SIP
    ## drop-in is simply skipped (its subtree stays unmonitored → re-run, never
    ## a false skip).
    if sandboxDir.len == 0:
      return
    # The per-entry ``createDir(destPath.parentDir)`` below makes both ``bin``
    # and ``usr/bin`` (and any future prefix) on demand; seed ``bin`` up front
    # so a sandboxDir that cannot be created at all fails fast and silently.
    try:
      createDir(extendedPath(sandboxDir / "bin"))
    except OSError, IOError:
      return
    for src in reproSandboxBinaries:
      if not fileExists(src):
        continue
      let destPath = sandboxDir / src.strip(leading = true, trailing = false,
                                            chars = {'/'})
      if fileExists(destPath) or symlinkExists(destPath):
        continue
      try:
        createDir(extendedPath(destPath.parentDir))
      except OSError, IOError:
        continue
      let basename = src.extractFilename
      let alternative = findNonSipAlternative(basename)
      if alternative.len > 0:
        try:
          createSymlink(alternative, destPath)
          continue
        except OSError, IOError:
          discard
      # No non-SIP alternative on PATH. On macOS, copying a protected Apple
      # platform binary is not a valid substitute: recent AMFI policy can
      # kill that copy at launch, and even where it runs it is still not the
      # portable drop-in promised by CT_SANDBOX_TOOLS_DIR. Leave the entry
      # absent so the spawn hook falls back transparently and completeness
      # accounting can make the action non-cacheable/incomplete as needed.
      when not defined(macosx):
        try:
          discard ct_propagation.prepareSandboxCopy(src, sandboxDir)
        except OSError, IOError:
          discard

  proc resolveExecutableInPath(name: string): string =
    ## Resolve ``name`` against PATH the way ``posix_spawnp`` would so we
    ## can read the file's shebang before the kernel does. Returns ``""``
    ## when no executable instance is found. Skips path components that
    ## look like absolute paths already so the caller can avoid double
    ## resolution.
    if name.len == 0:
      return ""
    if name.contains('/'):
      if fileExists(name):
        return name
      return ""
    let pathEnv = getEnv("PATH")
    if pathEnv.len == 0:
      return ""
    for entry in pathEnv.split(PathSep):
      if entry.len == 0:
        continue
      let candidate = entry / name
      if fileExists(candidate):
        return candidate
    ""

  proc readShebangInterpreter(scriptPath: string): tuple[interpreter: string;
      extraArg: string] =
    ## Read the ``#!`` line at the head of ``scriptPath``. Returns the
    ## interpreter path (first token) and an optional second token (e.g.
    ## ``/usr/bin/env python3`` → ("/usr/bin/env", "python3")). Returns
    ## empty strings if the file is not a script or cannot be read.
    var f: File
    if not open(f, scriptPath, fmRead):
      return ("", "")
    defer: close(f)
    var firstLine = ""
    try:
      if not f.readLine(firstLine):
        return ("", "")
    except IOError:
      return ("", "")
    if not firstLine.startsWith("#!"):
      return ("", "")
    let body = firstLine[2 .. ^1].strip()
    if body.len == 0:
      return ("", "")
    let parts = body.splitWhitespace()
    if parts.len == 0:
      return ("", "")
    if parts.len == 1:
      (parts[0], "")
    else:
      (parts[0], parts[1 .. ^1].join(" "))

  proc rewriteScriptCommandForSip(command: seq[string];
                                  sandboxDir: string): seq[string] =
    ## Detect whether ``command[0]`` (or, after PATH resolution) is a
    ## shell-style script whose shebang interpreter falls under a
    ## SIP-protected prefix. If so, rewrite the command to invoke the
    ## non-SIP sandbox copy of the interpreter directly. This sidesteps
    ## the kernel's shebang re-exec — which strips
    ## ``DYLD_INSERT_LIBRARIES`` because the interpreter lives at
    ## ``/bin/sh`` etc. — so the shim loads in the interpreter process
    ## and observes the child's reads/writes.
    ##
    ## Returns ``command`` unchanged when the rewrite cannot be applied
    ## (no script, interpreter is not SIP-protected, or no sandbox copy
    ## exists).
    if command.len == 0 or sandboxDir.len == 0:
      return command
    let resolved = resolveExecutableInPath(command[0])
    if resolved.len == 0:
      return command
    let (interpreter, extraArg) = readShebangInterpreter(resolved)
    if interpreter.len == 0:
      return command
    if not ct_propagation.isSipProtected(interpreter):
      return command
    let sandboxInterpreter = ct_propagation.rewriteSipPath(interpreter,
      sandboxDir)
    if sandboxInterpreter == interpreter or
        not fileExists(sandboxInterpreter):
      return command
    result = @[sandboxInterpreter]
    if extraArg.len > 0:
      result.add(extraArg)
    result.add(resolved)
    if command.len > 1:
      result.add(command[1 .. ^1])

type
  ParsedFsSnoopCommand = object
    inspectMode: bool
    inspectPath: string
    inspectFormat: string
    request: FsSnoopRequest
    depfileWasExplicit: bool

# DH-1 — ATOMIC, because `runMonitored` is now a concurrently-callable host API.
# Two monitors racing in one process must not be handed the same scratch name;
# the timestamp alone does not separate them (two calls can land in the same
# nanosecond bucket, and `getTime().nanosecond` resolution is not guaranteed).
var tempDirNonce: Atomic[uint64]
tempDirNonce.store(uint64(getCurrentProcessId()))

proc createLocalTempDir(prefix: string): string =
  let nonce = tempDirNonce.fetchAdd(1'u64) + 1'u64
  let now = getTime()
  result = getTempDir() / (prefix & "-" & $getCurrentProcessId() & "-" &
    $now.toUnix & "-" & $now.nanosecond & "-" & $nonce)
  createDir(extendedPath(result))

proc removeLocalTempDir(path: string) =
  ## Recursive deletion can race a recently-exited Windows producer or a file
  ## scanner that briefly holds a fragment without delete sharing. Cleanup must
  ## not replace the monitored command's result after evidence was finalized.
  when defined(windows):
    const
      CleanupRetryMs = 2_000
      CleanupPollMs = 20
      WindowsAccessDenied = 5'i32
      WindowsSharingViolation = 32'i32
      WindowsLockViolation = 33'i32
      WindowsDirNotEmpty = 145'i32
    var waitedMs = 0
    while true:
      try:
        removeDir(extendedPath(path))
        return
      except OSError as error:
        if not dirExists(extendedPath(path)):
          return
        if (error.errorCode != WindowsAccessDenied and
            error.errorCode != WindowsSharingViolation and
            error.errorCode != WindowsLockViolation and
            error.errorCode != WindowsDirNotEmpty) or
            waitedMs >= CleanupRetryMs:
          stderr.writeLine("io-mon: warning: could not remove temporary " &
            "directory " & path & ": " & error.msg)
          return
        let delayMs = min(CleanupPollMs, CleanupRetryMs - waitedMs)
        sleep(delayMs)
        inc(waitedMs, delayMs)
  else:
    removeDir(extendedPath(path))

proc parseOutputMode(value: string): FsSnoopOutputMode =
  case value
  of "none":
    fsoNone
  of "text":
    fsoText
  of "jsonl":
    fsoJsonl
  of "binary", "binary-stream":
    fsoBinaryStream
  else:
    raise newException(ValueError, "unsupported event mode: " & value)

proc requireValue(args: seq[string]; index: var int; flag: string): string =
  if index + 1 >= args.len:
    raise newException(ValueError, flag & " requires a value")
  inc index
  args[index]

proc splitFlagValue(arg, flag: string): string =
  let prefix = flag & "="
  if arg.startsWith(prefix):
    arg[prefix.len .. ^1]
  else:
    ""

proc parseInspect(args: seq[string]): ParsedFsSnoopCommand =
  if args.len < 2:
    raise newException(ValueError, "inspect requires an RMDF path")
  result.inspectMode = true
  result.inspectPath = args[1]
  result.inspectFormat = "text"
  var i = 2
  while i < args.len:
    let arg = args[i]
    case arg
    of "--format":
      result.inspectFormat = requireValue(args, i, "--format")
    of "--events":
      result.inspectFormat = requireValue(args, i, "--events")
    else:
      let formatValue = splitFlagValue(arg, "--format")
      if formatValue.len > 0:
        result.inspectFormat = formatValue
      else:
        raise newException(ValueError, "unsupported inspect argument: " & arg)
    inc i

proc parseRun(args: seq[string]): ParsedFsSnoopCommand =
  result.inspectMode = false
  result.request.streamMode = fsoNone
  result.request.passthroughChildStdout = true
  result.request.passthroughChildStderr = true

  var i = 0
  var commandStart = -1
  while i < args.len:
    let arg = args[i]
    if arg == "--":
      commandStart = i + 1
      break
    case arg
    of "--depfile":
      result.request.depFilePath = requireValue(args, i, "--depfile")
      result.depfileWasExplicit = true
    of "--events":
      result.request.streamMode = parseOutputMode(requireValue(args, i, "--events"))
    of "--format":
      result.request.streamMode = parseOutputMode(requireValue(args, i, "--format"))
    of "--event-stream":
      result.request.eventStreamPath = requireValue(args, i, "--event-stream")
    of "--capture-stdio":
      # Flag form (no value) — turn capture on; subsequent
      # ``--capture-stdio-path=…`` controls where the captured bytes
      # are written.
      result.request.captureChildStdio = true
    of "--capture-stdio-path":
      result.request.captureStdioPath = requireValue(args, i,
        "--capture-stdio-path")
      result.request.captureChildStdio = true
    else:
      let depValue = splitFlagValue(arg, "--depfile")
      let eventsValue = splitFlagValue(arg, "--events")
      let formatValue = splitFlagValue(arg, "--format")
      let streamValue = splitFlagValue(arg, "--event-stream")
      let stdioPathValue = splitFlagValue(arg, "--capture-stdio-path")
      if depValue.len > 0:
        result.request.depFilePath = depValue
        result.depfileWasExplicit = true
      elif eventsValue.len > 0:
        result.request.streamMode = parseOutputMode(eventsValue)
      elif formatValue.len > 0:
        result.request.streamMode = parseOutputMode(formatValue)
      elif streamValue.len > 0:
        result.request.eventStreamPath = streamValue
      elif stdioPathValue.len > 0:
        result.request.captureStdioPath = stdioPathValue
        result.request.captureChildStdio = true
      else:
        raise newException(ValueError, "unsupported fs-snoop argument: " & arg)
    inc i

  if commandStart < 0 or commandStart >= args.len:
    raise newException(ValueError, "missing command; use -- <command> [args...]")
  result.request.command = args[commandStart .. ^1]

proc parseFsSnoopCommand(args: seq[string]): ParsedFsSnoopCommand =
  if args.len > 0 and args[0] == "inspect":
    parseInspect(args)
  elif args.len > 0 and args[0] == "run":
    # Accept an explicit ``run`` subcommand so the snoop grammar reads
    # ``io-mon run --depfile <out> -- <command>`` (the verb form the
    # standalone CLI and the CodeTracer runner's live-capture call site use),
    # while still supporting the bare ``--depfile … -- <command>`` form for
    # backward compatibility with reprobuild's ``repro internal io monitor`` which
    # dispatched the verb itself before delegating. The ``run`` token is
    # stripped before the option parser sees it.
    parseRun(args[1 .. ^1])
  else:
    parseRun(args)

proc ensureParentDir(path: string) =
  let parent = parentDir(path)
  if parent.len > 0:
    createDir(extendedPath(parent))

const ShimLibOverrideEnv* = "REPRO_MONITOR_SHIM_LIB"
  ## Operator override for the shim shared-library path — see
  ## ``findShimLibrary``.

proc candidateShimLibraries(): seq[string] =
  ## The DISCOVERY candidates only. The ``REPRO_MONITOR_SHIM_LIB`` override is
  ## deliberately NOT in this list: an override is a pin, not a first guess, so
  ## it is handled separately in ``findShimLibrary`` where a miss can be made
  ## fatal instead of silently falling through to a different shim.
  let appDir = getAppDir()
  # Windows: the shim builds as a .dll instead of a .dylib; probe both so the
  # same lookup logic works on either platform without runtime branching at
  # every call site.
  when defined(windows):
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.dll",
      appDir / "librepro_monitor_shim.dll",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dll"
    ]
  elif defined(linux):
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.so",
      appDir / "librepro_monitor_shim.so",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.so"
    ]
  else:
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.dylib",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dylib"
    ]

proc findShimLibrary*(): string =
  ## **Public since M9.R.13c.2** — the build engine's ``monitoredAction``
  ## now seeds ``REPRO_MONITOR_SHIM_LIB`` on the action's env at wrap
  ## time, so the daemon-spawned ``repro internal fs-snoop`` subprocess
  ## resolves the shim without inheriting the user's shell environment.
  ##
  ## Lookup order:
  ##   1. ``$REPRO_MONITOR_SHIM_LIB`` env override (operator pin).
  ##   2. ``<appDir>/../lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (canonical build layout — what ``just build`` produces).
  ##   3. ``<appDir>/librepro_monitor_shim.{dll,so}`` (Windows-only
  ##      side-by-side install layout).
  ##   4. ``<cwd>/build/lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (running from the repo root with a freshly built tree).
  ##
  ## Returns the absolute path of the first existing discovery candidate, or the
  ## empty string when no candidate exists.
  ##
  ## **The override is honoured or the call FAILS — it is never ignored.** A set
  ## ``REPRO_MONITOR_SHIM_LIB`` that does not name an existing file raises
  ## ``IOError`` instead of falling through to a discovered shim. Falling
  ## through would silently capture a run with a DIFFERENT shim than the
  ## operator pinned — a stale pin or a typo'd path would produce a capture
  ## whose provenance is not the one that was asked for, with no diagnostic and
  ## a cheerful ``mcComplete``. The override exists precisely so a specific shim
  ## build is used; "honoured first" has to mean honoured, not preferred.
  let override = getEnv(ShimLibOverrideEnv)
  if override.len > 0:
    if not fileExists(extendedPath(override)):
      raise newException(IOError,
        ShimLibOverrideEnv & " is set to \"" & override &
          "\" but no such file exists; refusing to fall back to a discovered " &
          "shim because the capture would then come from a shim the operator " &
          "did not pin (unset " & ShimLibOverrideEnv & " to use discovery)")
    return absolutePath(override)
  for candidate in candidateShimLibraries():
    if candidate.len > 0 and fileExists(extendedPath(candidate)):
      return absolutePath(candidate)
  ""

# ---------------------------------------------------------------------------
# IoMon-Decomposed-Host-API DH-1 — per-call injection environment.
#
# The injection variables used to be published by mutating the HOSTING process's
# environment (`putEnv`) for the duration of the run and restoring it afterwards.
# That made `runMonitored` un-runnable concurrently: two monitors in one process
# overwrite each other's `LD_PRELOAD` / `REPRO_MONITOR_*`, so one tree attaches
# the other's dependency set and both edges report a set that is not theirs. The
# restore-on-exit `defer` made the damage invisible AFTER the fact but did
# nothing DURING it, and a host that never opted out could not avoid it.
#
# The variables are therefore computed into a child-only environment table and
# handed to the spawn. `runMonitored` performs NO `putEnv` on ANY arm: the two
# POSIX arms pass the table to `osproc.startProcess(env = …)`, and the Windows
# arm passes it to `runWithMonitorShim(env = …)`, which encodes it into an
# explicit `CreateProcessW` environment block. Windows was the last holdout —
# its injector took no `env` at all until nim-stackable-hooks 6a53408 — and
# `childEnv` below is the single composition all three share.
# ---------------------------------------------------------------------------

proc requestEnvValue(request: FsSnoopRequest; name: string): string =
  ## The value `name` would have in the child BEFORE io-mon's own injection: the
  ## request's override when it supplies one (last wins), else the hosting
  ## process's value, which the child inherits. Reads only — never mutates.
  for i in countdown(request.env.high, 0):
    if request.env[i][0] == name:
      return request.env[i][1]
  getEnv(name)

proc windowsHiddenEnvEntry(value: string): tuple[name, value: string] =
  ## Undo `envPairs`' index-0 split of a Windows HIDDEN environment variable.
  ##
  ## Windows keeps variables whose NAME BEGINS WITH `=`: the per-drive current
  ## directories (`=C:=C:\some\dir`), `cmd.exe`'s `=ExitCode=00000000`, and
  ## `=::=::\`. `std/envvars.envPairsImpl` reads `GetEnvironmentStringsW` and
  ## splits every entry on the FIRST `=` (`substr(kv, 0, p-1)` /
  ## `substr(kv, p+1)`); for these p is 0, so it yields an EMPTY name with the
  ## real name folded into the front of the value. This proc takes that value
  ## and returns the pair the entry actually encoded.
  ##
  ## It is load-bearing rather than cosmetic. `encodeWindowsEnvironmentBlock`
  ## REFUSES an empty name — it would frame as a leading `=VALUE` entry — and
  ## `runWithMonitorShim` turns that `ValueError` into an `OSError`. So without
  ## this repair a host launched from `cmd.exe`, where these entries are normal
  ## and inherited, could not spawn a monitored child AT ALL: `childEnv` would
  ## carry the empty name straight into the block encoder. Both directions are
  ## pinned, EXECUTABLY on a POSIX host, by
  ## `tests/portable/test_io_mon_windows_child_env_block.nim`.
  ##
  ## An entry with no `=` anywhere is dropped (`("", "")`), not guessed: it is
  ## not a well-formed Win32 entry, and emitting a name of `=` with the whole
  ## text as its value would invent a variable the parent never had.
  ##
  ## Not gated behind `when defined(windows)` deliberately — it is pure string
  ## work, and gating it would put the one piece of the Windows spawn path this
  ## workspace can actually EXECUTE behind a `when` that never fires here.
  ## The split must be on the FIRST `=`, mirroring the one `envPairs` made: the
  ## VALUE may legally contain further `=` characters (a directory named `a=b`
  ## in a per-drive entry is a valid NTFS path), and splitting on the last one
  ## would fold them into the NAME — where an `=` past index 0 is exactly what
  ## `encodeWindowsEnvironmentBlock` rejects, turning a repairable entry back
  ## into the `OSError` this proc exists to prevent.
  let sep = value.find('=')
  if sep < 0:
    return ("", "")
  ("=" & value[0 ..< sep], value[sep + 1 .. ^1])

proc addHostEnvEntry(dest: StringTableRef; key, value: string) =
  ## Put ONE entry of the hosting process's environment into the child's table.
  ##
  ## Split out of `childEnv` so it can be EXERCISED: `envPairs()` on a POSIX
  ## development host never yields the empty-named entry the repair below
  ## exists for, so a test driving `childEnv` cannot reach that branch and
  ## unwiring the repair reddened nothing. Called directly, it can. See
  ## `tests/portable/test_io_mon_windows_child_env_block.nim`.
  if key.len == 0:
    # A Windows hidden `=NAME=VALUE` entry, which `envPairs` reports with an
    # empty name (see `windowsHiddenEnvEntry`). Repairing it rather than
    # dropping it keeps the child's per-drive current directories intact AND
    # keeps the empty name — which the block encoder rejects — out of the
    # table. Unreachable on POSIX, where `environ` has no such entries.
    let hidden = windowsHiddenEnvEntry(value)
    if hidden.name.len > 0:
      dest[hidden.name] = hidden.value
  else:
    dest[key] = value

# The name-matching discipline the child's environment table uses: Windows
# environment variable names are case-INSENSITIVE, every POSIX arm's are not.
#
# Named, and a parameter of `childEnv` below, rather than written inline as a
# `when` inside the constructor call. The reason is testability, and it was
# found by mutation: flipping the Windows arm of that inline `when` to
# `modeCaseSensitive` reddened NOTHING — not the suite (the branch is not
# compiled on a POSIX host) and not `nim check --os:windows` (both mode names
# are valid `StringTableMode` values, so the swap type-checks). Meanwhile
# `docs/usage.md` promises callers a behaviour that rests entirely on it: on
# Windows a `Path` entry in `request.env` OVERRIDES the inherited `PATH`
# instead of joining the table as a second, competing variable — and, more to
# the point, a caller cannot dodge io-mon's injection by spelling
# `repro_monitor_shim_lib` in a different case.
#
# With the mode as an argument, that promise is EXECUTABLE on any host: see
# `tests/portable/test_io_mon_child_env_layering.nim`, which composes under
# `modeCaseInsensitive` explicitly. What stays compile-only is one thing only —
# that Windows is the arm that selects it.
const ChildEnvMode =
  when defined(windows): modeCaseInsensitive else: modeCaseSensitive

proc childEnv(request: FsSnoopRequest;
              injected: openArray[(string, string)];
              mode: StringTableMode = ChildEnvMode): StringTableRef =
  ## The COMPLETE environment for the monitored child: the hosting process's
  ## environment, then the caller's per-call `request.env`, then io-mon's own
  ## injection variables (which win, so a caller cannot switch monitoring off by
  ## accident). Nothing here is visible to the hosting process.
  ##
  ## ONE implementation for all three arms. Linux and macOS hand the result to
  ## `osproc.startProcess(env = …)`; Windows hands it to `runWithMonitorShim`'s
  ## `env`, which encodes it into an explicit `CreateProcessW` environment
  ## block. Composing the child environment in one place is the point: the
  ## layering rule above is a correctness rule (injection must WIN), and three
  ## copies of it are three chances for one arm to drift into letting a caller
  ## switch monitoring off.
  ##
  ## `mode` defaults to `ChildEnvMode`, which is what every production call
  ## passes; it is a parameter so a test can drive the WINDOWS discipline on a
  ## POSIX host (see `ChildEnvMode`).
  ##
  ## **The §4.1 start-time prune depends on this proc being the ONLY route by
  ## which an injection needle reaches a process.** `liveInjectedDescendants`
  ## skips every process that PREDATES the monitored root, which is sound only
  ## because `REPRO_MONITOR_SESSION` and `REPRO_MONITOR_FRAGMENT_DIR` travel
  ## exclusively through this child-only environment — so a carrier is
  ## necessarily a descendant, and a descendant is necessarily younger than its
  ## root. A `putEnv`/`setenv` of either name in the HOSTING process, followed
  ## by any spawn at all, would put a needle in a process that is not descended
  ## from the root; the prune would then drop it silently and the edge would
  ## grade `mcComplete` with a live escapee — the cardinal sin. If a host-side
  ## write of either name ever becomes necessary, the prune has to go first.
  ## (The shim's own `setenv("REPRO_MONITOR_EXEC_GEN", …)` in
  ## `hooks/linux_preload_runtime.nim` is not a needle and runs only inside
  ## processes that are already descendants, so it does not bear on this.)
  result = newStringTable(mode)
  for key, value in envPairs():
    addHostEnvEntry(result, key, value)
  for (key, value) in request.env:
    result[key] = value
  for (key, value) in injected:
    result[key] = value

proc injectionValue(shimLib, existing: string): string =
  ## Prepend the shim to whatever the child's preload list would otherwise be.
  ## `existing` comes from `requestEnvValue`, so a per-call `LD_PRELOAD` is
  ## extended exactly like an inherited one — the injection never silently
  ## discards a caller's preload.
  if existing.len == 0:
    shimLib
  else:
    shimLib & $PathSep & existing

# DH-1 — the run identity has to be unique per CALL, not merely per wall-clock
# instant. `$epochTime()` alone is not: two concurrent `runMonitored` calls can
# read the same value.
#
# What that costs is a FABRICATED event loss, not a naming clash. The run id no
# longer names anything on disk — since nim-shm-gset HM-1 the chain is
# `{appId}~{chainSeq}.{boot}.{pid}.shardN` and the run id lives in shard0's
# HEADER, so two chains may legally share one (`shm_gset.createSetT`). The
# load-bearing use is the §4.1 detached-descendant guard:
# `liveInjectedDescendants` walks ALL of `/proc` — not a process subtree — and
# claims every process whose `environ` carries `REPRO_MONITOR_SESSION=<runId>`
# (or `REPRO_MONITOR_FRAGMENT_DIR=<dir>`; `createLocalTempDir`'s nonce is atomic
# for the same reason). Two monitors sharing either value cross-attribute: the
# one whose root exits first sees the OTHER's still-live child as its own
# escapee, and `waitForLinuxInjectedDescendants` invents an `mrEventLoss` past
# the grace window — a false `mcIncomplete` on an edge that lost nothing.
# Measured; regression-tested by
# `tests/linux/test_io_mon_per_call_env_and_cwd.nim`
# (`t_concurrent_runs_do_not_fabricate_an_event_loss`), which reddens under a
# forced collision of EITHER value.
#
# Uniqueness argument: `nonce` is distinct within a process (atomic fetch-add)
# and `pid` is distinct between processes that are alive at the same time, so no
# two CONCURRENT runs can collide — which is the only window in which the /proc
# scan can misattribute. `epochTime` then separates same-pid runs across a pid
# recycle.
var runIdNonce: Atomic[uint64]

proc newRunId(): string =
  let nonce = runIdNonce.fetchAdd(1'u64) + 1'u64
  $epochTime() & "-" & $getCurrentProcessId() & "-" & $nonce

proc renderStreamToPath(depfilePath: string; mode: FsSnoopOutputMode;
                        streamPath: string) =
  case mode
  of fsoNone:
    discard
  of fsoBinaryStream:
    if streamPath.len == 0:
      raise newException(ValueError,
        "--events binary requires --event-stream so child output stays separate")
    ensureParentDir(streamPath)
    writeFile(extendedPath(streamPath), readFile(extendedPath(depfilePath)))
  of fsoText, fsoJsonl:
    var lines: seq[string] = @[]
    for item in streamMonitorDepFile(depfilePath):
      if mode == fsoText:
        lines.add(renderMonitorStreamItemText(item))
      else:
        lines.add(renderMonitorStreamItemJsonl(item))
    if streamPath.len > 0:
      ensureParentDir(streamPath)
      writeFile(extendedPath(streamPath), lines.join("\n") & "\n")
    else:
      for line in lines:
        stderr.writeLine(line)

type
  MonitorResult* = object
    ## Result of a completed `runMonitored` host run (the §5 consumer-side
    ## batch entry point). Carries the monitored command's exit status plus the
    ## canonical depfile the host wrote — so a parent gets the depfile path, the
    ## decoded records, and the honest completeness signal without re-reading the
    ## file or reasoning about the shm/fragment lifecycle itself.
    exitCode*: int              ## the monitored command's exit status
    depFilePath*: string        ## where the canonical RMDF depfile was written
    depFile*: MonitorDepFile    ## the merged depfile: `.records`, `.completeness`, …

proc completeness*(r: MonitorResult): MonitorCompleteness =
  ## Convenience accessor: the honest completeness of the captured dependency
  ## set (`mcComplete` ⇒ the observed set may be trusted; `mcIncomplete` ⇒ the
  ## consumer must conservatively re-run).
  r.depFile.completeness

proc records*(r: MonitorResult): seq[MonitorRecord] =
  ## Convenience accessor: the merged, canonicalised dependency records.
  r.depFile.records

# ---------------------------------------------------------------------------
# IoMon-Decomposed-Host-API DH-2 — the lifecycle behind a handle.
#
# `runMonitored` used to BE the lifecycle: one call created the consumer, spawned
# the tree, blocked on it, and finalised the evidence. That is unusable for a
# build engine, whose scheduler polls N in-flight children in one loop — calling
# a blocking `runMonitored` per action serialises the whole build.
#
# So the lifecycle is now three steps a caller can interleave:
#
#     var h = startMonitor(request)        # consumer up, tree spawned
#     while not pollMonitor(h): ...        # non-blocking; poll N of these
#     let res = finishMonitor(move h)      # evidence
#
# and `runMonitored` is `finishMonitor(startMonitor(request))` — the SAME code
# path, not a second implementation of it (see its docstring, and
# `tests/linux/test_io_mon_decomposed_host_api.nim`, which asserts the
# delegation at RUNTIME through the lifecycle counters below).
# ---------------------------------------------------------------------------

var
  monitorsStartedCount: Atomic[uint64]
  monitorsFinishedCount: Atomic[uint64]
  monitorsReleasedCount: Atomic[uint64]
  monitorsSettledCount: Atomic[uint64]

proc monitorLifecycleCounts*():
    tuple[started, finished, released, live, settled: int] =
  ## Process-wide census of monitors handled by THIS module.
  ##
  ## `started` counts `startMonitor` calls that got as far as owning something
  ## (past shim resolution); `finished` counts `finishMonitor` calls;
  ## `released` counts monitors whose consumer structure and scratch state have
  ## been torn down — by `finishMonitor` OR by a dropped handle's destructor.
  ## `live` is `started - released`. `settled` counts monitors whose §4.1
  ## detached-descendant guard has run (`settleMonitorDescendants`).
  ##
  ## Three jobs, all real rather than test-only:
  ##
  ##  * a long-lived host can assert `live == 0` at shutdown, which is the LF-2
  ##    property stated as a number it can check;
  ##  * `finished < released` is exactly "somebody dropped a handle", which is a
  ##    host bug worth reporting even though this module survives it; and
  ##  * `settled == finished` is the DH-3 property stated as a number: every
  ##    monitor that produced evidence went through the descendant guard first.
  ##    It cannot be violated by a host — the guard is inside the funnel every
  ##    `MonitorResult` comes out of (see `collectMonitorEvidence`) — so what
  ##    this number catches is a change to THIS module, which is the only way it
  ##    could be violated at all.
  ##
  ## It is also what pins `runMonitored`'s delegation executably: a
  ## reimplementation that stopped going through `startMonitor`/`finishMonitor`
  ## would stop moving these numbers.
  let started = int(monitorsStartedCount.load())
  let finished = int(monitorsFinishedCount.load())
  let released = int(monitorsReleasedCount.load())
  let settled = int(monitorsSettledCount.load())
  (started: started, finished: finished, released: released,
   live: started - released, settled: settled)

type
  MonitorHandle* = object
    ## A monitor whose WAIT the caller owns: `startMonitor` produces one,
    ## `pollMonitor` advances it without blocking, `finishMonitor` consumes it
    ## and yields the `MonitorResult`.
    ##
    ## ── THE LF-2 GUARANTEE, RESTATED FOR A CALLER-OWNED WAIT ───────────────
    ##
    ## `runMonitored` could promise "a producer never runs without a consumer"
    ## the easy way: it OWNED the whole lifecycle, so the consumer-owned
    ## `nim-shm-gset` and the fragment directory were created and destroyed
    ## inside one call and no caller could ever hold one end of it. Moving the
    ## wait out is precisely what re-opens that window. A host that starts a
    ## monitor and then loses interest — an early `return`, a raised exception,
    ## a `break` out of its poll loop — would release (or, on process exit,
    ## simply abandon) the consumer while the monitored tree is still running
    ## and still publishing. §4.1's incident is that shape: a descendant
    ## appending to an unlinked `.rmdf-frag` until it filled the root tmpfs.
    ##
    ## A documented "you must always call `finishMonitor`" would not hold that
    ## line, so the type holds it instead. Three properties, none of them a rule
    ## a caller can forget:
    ##
    ##  1. **The handle is the only way to reach a producer.** `startMonitor` is
    ##     the sole spawn site for a monitored tree in this module, and it
    ##     hands back the consumer's owner in the same value. "Spawned but
    ##     unowned" is not a state that can be constructed. The fields are
    ##     private and there is no public constructor, so a caller cannot
    ##     assemble a half-handle either.
    ##  2. **The handle cannot be copied** — `=copy` is `{.error.}`. Two owners
    ##     of one consumer cannot be written down, so "the other copy will
    ##     finish it" is never an argument. Non-copyability propagates
    ##     transitively through `seq`, arrays and any wrapping object, so the
    ##     `seq[MonitorHandle]` an N-way poll loop holds is itself exclusive.
    ##     (Prior art: `nim-shm-gset`'s `SetLease`, which made "two leases over
    ##     one chain" unrepresentable in the same way.)
    ##  3. **Dropping the handle FINISHES it** — `=destroy` runs the safety half
    ##     of the lifecycle: it waits for the monitored root to exit, and only
    ##     then marks the consumer gone and removes the fragment directory. So
    ##     the ordering that makes an orphan possible — release the consumer
    ##     while a producer still runs — is not reachable by dropping,
    ##     returning early, unwinding, or moving the handle somewhere it is
    ##     never finished. What a dropped handle costs is the WAIT the caller
    ##     was trying to skip and the EVIDENCE it never asked for; what it can
    ##     never cost is an orphaned producer.
    ##
    ## Point 3 is why the destructor waits rather than killing the tree: killing
    ## would make dropping a handle destroy the caller's work, and `runMonitored`
    ## does not kill either. Note the honest consequence — a dropped handle whose
    ## child never exits blocks in the destructor exactly as long as
    ## `runMonitored` would have blocked in the wait.
    ##
    ## ── WHAT IS NOT COVERED ────────────────────────────────────────────────
    ## A host killed with `SIGKILL` runs no destructor; that is the reaper's job
    ## (`shm_gset`'s cross-restart sweep), not this type's, and it is unchanged
    ## from `runMonitored`.
    active: bool                   ## owns something releasable
    exited: bool                   ## the monitored root has been reaped
    settled: bool                  ## the §4.1 descendant grace has run.
                                   ## Written ONLY by `settleMonitorDescendants`
                                   ## and read by `collectMonitorEvidence`'s
                                   ## gate — the DH-3 mechanism that makes the
                                   ## guard unskippable rather than merely
                                   ## present.
    exitCode: int
    rootPid: uint64
    runId: string
    fragmentDir: string
    request: FsSnoopRequest
    when defined(linux) or defined(macosx):
      process: Process
    when defined(linux):
      depSet: SetHost
      depSetLive: bool
      rootStartTicks: uint64   ## The monitored ROOT's own start time (field 22
                               ## of `/proc/<rootPid>/stat`, USER_HZ ticks since
                               ## boot), captured immediately after the spawn.
                               ## The §4.1 sweep uses it to skip processes that
                               ## PREDATE the root and therefore cannot be its
                               ## descendants — see `liveInjectedDescendants`.
                               ## `0` means "unknown", which disables the skip
                               ## and restores the exhaustive sweep.
    when defined(macosx):
      sandboxDir: string
      ownsSandboxDir: bool
    when defined(windows):
      shimLib: string
      spawnEnv: StringTableRef
      injection: WindowsInjectionResult
      spawned: bool

proc `=copy`*(dst: var MonitorHandle; src: MonitorHandle) {.error:
  "a MonitorHandle exclusively owns one live monitor: `move` it (or take it by " &
  "`sink`), or start another monitor. Copying would give two owners to one " &
  "consumer, which is how a producer ends up with none (LF-2).".}

proc live*(h: MonitorHandle): bool =
  ## Does this handle still own a monitor? False for a default-constructed
  ## handle, for one that has been moved from, and for one already finished.
  h.active

proc hasExited*(h: MonitorHandle): bool =
  ## Has the monitored ROOT been reaped? Equivalent to the last `pollMonitor`
  ## result, without polling again.
  h.exited

proc rootPid*(h: MonitorHandle): uint64 =
  ## The monitored root's OS pid — what the R1 root-guard is stated over, and
  ## what a scheduler reports in its own diagnostics. `0` when nothing has been
  ## spawned yet (which on Windows is the whole window between `startMonitor`
  ## and the first `pollMonitor`; see `pollMonitor`).
  h.rootPid

proc recordRootExit(h: var MonitorHandle; code: int) =
  ## **The ONLY writer of `h.exitCode` and `h.exited`
  ## (IoMon-Decomposed-Host-API DH-4).**
  ##
  ## The root's exit status used to have TWO writers: `pollMonitor` on the polled
  ## path and `waitForMonitorRoot` on the batch path. They agreed, and nothing
  ## pinned that they must — which matters more here than it would elsewhere,
  ## because the two launch paths differ ONLY in which of them runs
  ## (`waitForMonitorRoot` returns at its `if h.exited: return` for a handle a
  ## host already polled). So a change to either one is a change to ONE launch
  ## path's evidence and not the other's, and DH-4's whole claim is that the two
  ## agree. That is the same shape as the `h.settled` divergence DH-3 measured,
  ## one field over; folding both writers into one makes the agreement true by
  ## construction instead of by coincidence.
  ##
  ## Reaping the `Process` belongs here too, so "the monitored root has exited"
  ## is ONE state transition rather than a four-line sequence each caller
  ## repeats — and so a caller that reaps without recording, or records without
  ## reaping, is not a shape that can be written.
  h.exitCode = code
  h.exited = true
  when defined(linux) or defined(macosx):
    if h.process != nil:
      close(h.process)
      h.process = nil

proc waitForMonitorRoot(h: var MonitorHandle) =
  ## BLOCK until the monitored root has exited, and record its status.
  ## Idempotent: a root already reaped by `pollMonitor` is not waited on twice.
  ##
  ## This is the first half of the safety teardown, and the reason the second
  ## half is safe: nothing that releases the consumer runs before this returns.
  ##
  ## NOTE for anyone changing this proc — the early return below is not merely
  ## the idempotence guard DH-2 classified it as. It is the ONE code-level seam
  ## along which the two launch paths can differ: `h.exited` is `false` here for
  ## `runMonitored` (so the whole body runs) and `true` for a host that polled
  ## (so this returns at its first statement). **Any state a change puts after
  ## it executes on the batch path and is skipped on the polled one**, which is
  ## how DH-3's M5 produced a false `mcComplete` on one path while the other
  ## stayed honest. Put per-run state transitions in `recordRootExit`, which both
  ## paths reach, not after the guard.
  if h.exited:
    return
  when defined(linux) or defined(macosx):
    if h.process != nil:
      recordRootExit(h, waitForExit(h.process))
  elif defined(windows):
    # The Windows spawn is `stackable_hooks/windows_injector.runWithMonitorShim`,
    # which spawns AND waits in one blocking call and returns only a completed
    # `WindowsInjectionResult`. There is no handle to poll, so this arm performs
    # the SPAWN here rather than in `startMonitor` — see `pollMonitor` for what
    # that costs and why it is still the honest shape.
    if not h.spawned:
      h.spawned = true
      h.injection = runWithMonitorShim(h.request.command, h.shimLib,
                                       cwd = h.request.cwd,
                                       captureStdio = h.request.captureChildStdio,
                                       captureStdioPath = h.request.captureStdioPath,
                                       env = h.spawnEnv)
      h.rootPid =
        if h.injection.monitoringSkipped: 0'u64 else: h.injection.rootPid
      recordRootExit(h, h.injection.exitCode)

proc settleMonitorDescendants(h: var MonitorHandle) =
  ## The §4.1 detached-descendant grace (Linux). Idempotent.
  ##
  ## This is an EVIDENCE step, not a safety step, which is why the evidence
  ## funnel runs it and a dropped handle's destructor does not: what it produces
  ## is an `mrEventLoss` marker that downgrades the edge to `mcIncomplete`, and a
  ## dropped handle publishes no edge for it to downgrade. The safety of a
  ## surviving descendant is provided by the release order instead — the root is
  ## reaped first, and a descendant that outlives the consumer then fast-fails
  ## with `emConsumerGone` (LF-4).
  ##
  ## **DH-3 — this is the guard an external host must not be able to skip.**
  ## `waitForLinuxInjectedDescendants` and its detector `liveInjectedDescendants`
  ## stay PRIVATE deliberately: exporting them would hand a host a proc it can
  ## forget to call, which reproduces the false-`mcComplete` hazard one level up
  ## instead of closing it. The guard is instead the FIRST act of
  ## `collectMonitorEvidence`, the single funnel every `MonitorResult` is
  ## produced through, and that funnel REFUSES to merge for a handle this proc
  ## has not marked. So "a host that owns its own spawn" is not a configuration
  ## the public surface can reach: `startMonitor` is the only spawn site, and
  ## `finishMonitor` is the only exit.
  ##
  ## `h.settled` is the flag the funnel's gate reads, and this proc is its ONLY
  ## writer — which is what makes the gate a check on the guard rather than a
  ## restatement of it.
  if h.settled:
    return
  h.settled = true
  discard monitorsSettledCount.fetchAdd(1'u64)
  when defined(linux):
    let launcherLossPath0 =
      if h.depSetLive and h.depSet.available: h.depSet.path0 else: ""
    waitForLinuxInjectedDescendants(h.fragmentDir, h.runId, h.rootPid,
      h.rootStartTicks, launcherLossPath0)
  else:
    # macOS and Windows have no §4.1 equivalent yet — the detached-descendant
    # scan is a `/proc` walk. The STEP still runs (and still marks the handle),
    # so an arm that grows a real guard later inherits the gate below for free
    # rather than having to remember to re-add it.
    discard

proc releaseMonitor(h: var MonitorHandle) =
  ## Release everything the monitor owns: mark the consumer gone and unmap it,
  ## then delete the scratch directories. Idempotent.
  ##
  ## MUST NOT be called while the monitored root can still be running — that
  ## ordering IS the LF-2 hazard. Every caller goes through `endMonitor` or
  ## `finishMonitor`, both of which reap the root first.
  ##
  ## The order inside mirrors what `runMonitored`'s `defer`s executed in before
  ## DH-2 (consumer first, then sandbox, then fragment dir), so the decomposition
  ## did not quietly reorder teardown.
  if not h.active:
    return
  h.active = false
  when defined(linux):
    if h.depSetLive:
      h.depSetLive = false
      # Announce the consumer is gone (a late orphan `emit` then fast-fails with
      # `emConsumerGone` instead of growing the set — LF-4), then unmap.
      h.depSet.finish()
  when defined(macosx):
    if h.ownsSandboxDir and h.sandboxDir.len > 0:
      removeLocalTempDir(h.sandboxDir)
      h.sandboxDir = ""
      h.ownsSandboxDir = false
  if h.fragmentDir.len > 0:
    removeLocalTempDir(h.fragmentDir)
    h.fragmentDir = ""
  discard monitorsReleasedCount.fetchAdd(1'u64)

proc endMonitor(h: var MonitorHandle) =
  ## The SAFETY half of the lifecycle, whole and in order: reap the root, THEN
  ## release the consumer. `finishMonitor` runs these same two steps with the
  ## evidence collected between them, and `=destroy` runs them alone — so the
  ## ordering that LF-2 depends on has ONE implementation, not one per path.
  if not h.active:
    return
  waitForMonitorRoot(h)
  releaseMonitor(h)

proc `=destroy`*(h: MonitorHandle) =
  ## Dropping a live handle finishes it — see `MonitorHandle`, point 3. This is
  ## what makes an LF-2 orphan unrepresentable rather than merely forbidden: the
  ## producer is reaped before the consumer is released, on EVERY path out of the
  ## scope that owns the handle, including an exception unwinding through it.
  ##
  ## A handle that `finishMonitor` already consumed, and one that was moved from
  ## (`wasMoved` zeroes it), is inactive here, so this is a no-op for it — no
  ## double release, no double wait.
  let self = cast[ptr MonitorHandle](addr h)
  try:
    endMonitor(self[])
  except CatchableError as err:
    try:
      stderr.writeLine("io-mon: warning: a dropped MonitorHandle could not be " &
        "released cleanly: " & err.msg)
    except CatchableError:
      discard
  # Release every field GENERICALLY. A custom `=destroy` suppresses the
  # compiler's own field destruction (measured: 200k drops of an object with a
  # string and a seq leak ~28 MB when the hook forgets them), and this handle
  # carries strings, a `seq`, a `Process` ref and a `StringTableRef`. Walking
  # `fieldPairs` means a field added later cannot silently start leaking.
  for name, value in fieldPairs(self[]):
    `=destroy`(value)

proc startMonitorInner(h: var MonitorHandle; request: FsSnoopRequest) =
  h.request = request
  when defined(macosx):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.dylib; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    h.fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    h.active = true
    discard monitorsStartedCount.fetchAdd(1'u64)
    ensureParentDir(request.depFilePath)

    # SIP bypass: ensure CT_SANDBOX_TOOLS_DIR exists and contains non-SIP
    # copies of the shell binaries that monitored subprocesses commonly
    # exec. Without this, /bin/sh (used by osproc.execCmdEx) loses
    # DYLD_INSERT_LIBRARIES and the shim falls silent for the rest of
    # the process tree.
    var sandboxDir = requestEnvValue(request, "CT_SANDBOX_TOOLS_DIR")
    h.ownsSandboxDir = sandboxDir.len == 0
    if h.ownsSandboxDir:
      sandboxDir = createLocalTempDir("repro-fs-snoop-sandbox-tools")
    # Only the fallback created by this invocation belongs to io-mon.  An
    # operator-provided CT_SANDBOX_TOOLS_DIR may be a persistent, pre-built
    # bundle and must never be removed.  Recording ownership on the HANDLE
    # before populating the tree is what releases the same invocation-local
    # path on setup failures, spawn failures, non-zero child exits, successful
    # runs — and now on a dropped handle too.
    h.sandboxDir = sandboxDir
    populateReproSandboxTools(sandboxDir)

    # DH-1 — the macOS injection set, threaded through the SPAWN. Six variables;
    # no `putEnv`, so the hosting process's own `DYLD_INSERT_LIBRARIES` is never
    # briefly pointed at the shim (which would have injected the monitor into
    # anything else the host spawned in that window).
    let injected = @[
      ("CT_SANDBOX_TOOLS_DIR", sandboxDir),
      ("DYLD_INSERT_LIBRARIES",
        injectionValue(shimLib,
          requestEnvValue(request, "DYLD_INSERT_LIBRARIES"))),
      ("REPRO_MONITOR_FRAGMENT_DIR", h.fragmentDir),
      ("REPRO_MONITOR_OUTPUT", request.depFilePath),
      ("REPRO_MONITOR_SESSION", newRunId()),
      ("REPRO_MONITOR_SHIM_LIB", shimLib)
    ]
    let spawnEnv = childEnv(request, injected)

    # SIP shebang bypass: if the target is a shell script whose
    # interpreter (``#!/bin/sh`` etc.) lives under a SIP-protected
    # prefix, ``posix_spawnp`` would let the kernel re-exec into the
    # SIP-protected interpreter, stripping ``DYLD_INSERT_LIBRARIES`` so
    # the shim never loads. Rewriting the invocation to the non-SIP
    # sandbox interpreter (typically a symlink to a Nix or Homebrew
    # shell, dropped into ``CT_SANDBOX_TOOLS_DIR`` by
    # ``populateReproSandboxTools``) sidesteps that strip — the shim
    # loads in the interpreter and observes the script's reads/writes.
    let effectiveCommand = rewriteScriptCommandForSip(request.command,
      sandboxDir)
    let childArgs =
      if effectiveCommand.len > 1:
        effectiveCommand[1 .. ^1]
      else:
        @[]
    h.process = startProcess(effectiveCommand[0],
      workingDir = request.cwd,
      args = childArgs,
      env = spawnEnv,
      options = {poUsePath, poParentStreams})
    # ROUND-2 R1 — remember the root pid so the merge can PROVE the root was
    # monitored. A SIP/hardened/notarized root (e.g. /bin/cat) strips
    # DYLD_INSERT_LIBRARIES and emits no process-start; passing its pid to
    # mergeFragments downgrades that case to mcIncomplete instead of asserting a
    # false mcComplete over an empty record set.
    h.rootPid = uint64(h.process.processID)
  elif defined(linux):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.so; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    h.fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    h.active = true
    discard monitorsStartedCount.fetchAdd(1'u64)
    ensureParentDir(request.depFilePath)

    # DH-1 — the Linux injection set, threaded through the SPAWN. Seven
    # variables in the fully-enabled case (`REPRO_MONITOR_DEP_SHM` and
    # `REPRO_MONITOR_APP_ID` only when the shm-gset host came up); no `putEnv`,
    # so a second monitor running concurrently in this process is unaffected.
    h.runId = newRunId()
    var injected = @[
      ("LD_PRELOAD",
        injectionValue(shimLib, requestEnvValue(request, "LD_PRELOAD"))),
      ("REPRO_MONITOR_FRAGMENT_DIR", h.fragmentDir),
      ("REPRO_MONITOR_OUTPUT", request.depFilePath),
      ("REPRO_MONITOR_SESSION", h.runId)
    ]

    # io-mon-Lossless-Event-Capture M3 (part 1) — the CONSUMER hosts the edge's
    # shared-memory SET (nim-shm-gset, the M1-winning transport) BEFORE launching
    # the process tree, and names it via REPRO_MONITOR_DEP_SHM = its shard0 path
    # (ends `.shard0`, which is how the shim's producer selects the set over the
    # legacy ring). Producers IDEMPOTENTLY INSERT each observed record into this
    # consumer-owned set as the PRIMARY channel; anything they cannot publish
    # (oversize encoding for the stack buffer, or a saturated/gone set) falls back
    # to a `.rmdf-frag` file (the correctness FALLBACK retained for part 1). Unlike
    # the ring, the set needs NO drain loop — it dedups at source and grows by
    # sharding — so we simply `snapshot` it ONCE at finalize and decode each
    # element back to a `MonitorRecord`. The set lives in consumer-owned memory
    # that outlives every producer, so a producer SIGKILLed after publishing loses
    # ZERO records (LF-3). DISABLED (env left unset) when REPRO_MONITOR_DEP_SHM_DISABLE
    # is set — the pure-file baseline used by the LF-6 byte-identical regression.
    let depSetEnabled = shmGSetSupported and
      requestEnvValue(request, "REPRO_MONITOR_DEP_SHM_DISABLE").len == 0
    if depSetEnabled:
      # The appId scopes the SET's cross-restart reaper so one application never
      # reaps another's shared-memory segments (segment name gains an `{appId}~`
      # prefix; content is unaffected). Defaults to "io-mon"; a consumer that
      # shares a segments directory (reprobuild/codetracer) overrides it via
      # REPRO_MONITOR_APP_ID so its reaper stays scoped to its own segments.
      var depSetAppId = requestEnvValue(request, "REPRO_MONITOR_APP_ID")
      if depSetAppId.len == 0:
        depSetAppId = "io-mon"
      h.depSet = startHost(h.fragmentDir, h.runId, appId = depSetAppId)
      # From here the CONSUMER structure exists, so the handle owns it: every
      # exit from this proc, and every exit from the caller's scope, goes
      # through `releaseMonitor`'s `finish()` (markConsumerGone + unmap).
      h.depSetLive = h.depSet.available
      if h.depSetLive:
        injected.add ("REPRO_MONITOR_DEP_SHM", h.depSet.path0)
        # Export the resolved appId too, so a producer that re-derives the
        # reaper scope (or an in-tree consumer that shares the segments dir)
        # sees the SAME tag the host created shard0 under — part of the §5
        # host owning the whole structure lifecycle, not just naming it.
        injected.add ("REPRO_MONITOR_APP_ID", depSetAppId)
    injected.add ("REPRO_MONITOR_SHIM_LIB", shimLib)
    let spawnEnv = childEnv(request, injected)

    let childArgs =
      if request.command.len > 1:
        request.command[1 .. ^1]
      else:
        @[]
    h.process = startProcess(request.command[0],
      workingDir = request.cwd,
      args = childArgs,
      env = spawnEnv,
      options = {poUsePath, poParentStreams})
    # ROUND-2 R1 — see the macOS branch: prove the root was monitored.
    h.rootPid = uint64(h.process.processID)
    # The root's own creation time, read the moment it exists. Every process
    # that can carry this monitor's injection markers is a descendant of this
    # root, so none of them can be older than it — which is what lets the §4.1
    # sweep skip the (overwhelming) majority of the machine's processes without
    # narrowing the guard by one pid. Reading it here rather than at settle time
    # is not an optimisation but a necessity: by then the root is gone.
    #
    # A `0` (the root exited between `startProcess` returning and this read —
    # a real race, just a vanishingly rare one) disables the skip for this
    # monitor and it pays the old exhaustive sweep. Slower, never blinder.
    h.rootStartTicks = procStartTicks(h.rootPid)
  elif defined(windows):
    # Windows: same end-to-end flow as macOS, but the injection uses
    # CreateProcess(CREATE_SUSPENDED) + CreateRemoteThread(LoadLibraryW)
    # instead of the DYLD_INSERT_LIBRARIES env var. Fragment-dir + output
    # path env vars are still set so the in-DLL hook bodies know where to
    # append RMDF fragments.
    h.shimLib = findShimLibrary()
    if h.shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.dll; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    h.fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    h.active = true
    discard monitorsStartedCount.fetchAdd(1'u64)
    ensureParentDir(request.depFilePath)

    # DH-1 — the Windows injection set, threaded through the SPAWN. Four
    # variables: REPRO_MONITOR_FRAGMENT_DIR, REPRO_MONITOR_OUTPUT,
    # REPRO_MONITOR_SESSION, REPRO_MONITOR_SHIM_LIB. (There is no preload
    # variable — injection is CreateRemoteThread + LoadLibraryW — and no
    # DEP_SHM/APP_ID, because the shm-gset arm is Linux only.)
    #
    # This arm used to be the ONE that still mutated the hosting process's
    # environment, scope-restored by a `defer`: the spawn is not
    # `osproc.startProcess` but `stackable_hooks/windows_injector`'s
    # `runWithMonitorShim`, whose `CreateProcessW` passed
    # `lpEnvironment = nil`, so the child could only receive the variables by
    # inheriting the parent's block. Two concurrent `runMonitored` calls
    # therefore clobbered each other's monitoring, and the restore made the
    # damage invisible AFTER the fact while doing nothing DURING it.
    #
    # `runWithMonitorShim` now takes an `env` (nim-stackable-hooks 6a53408): a
    # non-nil table is the child's COMPLETE environment, encoded into an
    # explicit `CreateProcessW` block. `nil` still means "inherit", so the
    # parameter costs nothing to callers that do not use it. We compose that
    # table with the SAME `childEnv` the two POSIX arms use, so the layering
    # rule (host env, then `request.env`, then io-mon's injection, injection
    # winning) has one implementation rather than three. NO arm mutates the
    # host any more.
    let injected = @[
      ("REPRO_MONITOR_FRAGMENT_DIR", h.fragmentDir),
      ("REPRO_MONITOR_OUTPUT", request.depFilePath),
      ("REPRO_MONITOR_SESSION", newRunId()),
      ("REPRO_MONITOR_SHIM_LIB", h.shimLib)
    ]
    h.spawnEnv = childEnv(request, injected)

    # NOTE (executable resolution, unchanged by the above): a bare
    # `request.command[0]` is resolved from the HOST's `PATH`, not `spawnEnv`'s.
    # `CreateProcessW` is called with `lpApplicationName = NULL`, whose
    # documented search runs in the CALLING process and never consults
    # `lpEnvironment`; `runWithMonitorShim`'s MSYS/Cygwin fork-runtime check
    # resolves the same bare name with `findExe`, i.e. from that same host
    # `PATH`. The two therefore agree on WHICH image is being talked about,
    # which is what matters — the upstream `env`/`findExe` hazard note is about
    # a caller whose `env` PATH disagrees with the host's, and here that
    # disagreement cannot separate the checked image from the launched one.
    # It does mean a `PATH` in `request.env` changes what the CHILD sees but
    # not which binary is launched. The POSIX arms answer the same way, though
    # by different routes — Linux `findExe`s in the forked child (whose
    # `environ` is still the parent's) and then `execve`s; macOS uses
    # `posix_spawnp`, which reads `PATH` from the CALLING process, not from the
    # `envp` it is given. Same answer on all three, three mechanisms; see
    # `types.nim`'s `env*`. Pass an absolute `command[0]` when that distinction
    # matters.
    #
    # THE SPAWN ITSELF IS DEFERRED to `waitForMonitorRoot` on this arm, because
    # `runWithMonitorShim` spawns and waits in one blocking call. See
    # `pollMonitor`.
  else:
    raise newException(OSError,
      "fs-snoop hooks backend currently supports macOS, Linux, and Windows only")

proc startMonitor*(request: FsSnoopRequest): MonitorHandle =
  ## **Public parent-host API (IoMon-Decomposed-Host-API DH-2).** Bring the
  ## consumer up and launch the monitored process tree, returning the handle
  ## that owns both. Does NOT wait.
  ##
  ## Everything `runMonitored` does before its wait happens here: the shim is
  ## resolved, the fragment directory is created, on Linux the consumer-owned
  ## `nim-shm-gset` is created via `transport.startHost`, the injection
  ## variables are composed into a CHILD-ONLY environment (DH-1: no `putEnv` on
  ## any arm) and the tree is spawned with `request.cwd` as its working
  ## directory.
  ##
  ## The returned handle must be finished — but "must" here is a description of
  ## what happens, not an obligation on the caller: dropping it runs the same
  ## safety teardown, in the same order (see `MonitorHandle`). A caller that
  ## wants the EVIDENCE calls `finishMonitor`.
  ##
  ## Raises on a genuine setup failure (no shim, unsupported platform). A raise
  ## here leaves nothing behind: the partially-built handle is released on the
  ## way out, so a failed start cannot leave a spawned tree, a mapped consumer,
  ## or a scratch directory.
  ##
  ## **WINDOWS.** `runWithMonitorShim` spawns and waits in one call, so this arm
  ## prepares the injection and defers the spawn to the first `pollMonitor` /
  ## `finishMonitor`. Nothing is running when this returns there.
  try:
    startMonitorInner(result, request)
  except CatchableError as err:
    # Release whatever was built before the failure — including a tree that was
    # spawned before a later step raised, which `endMonitor` reaps before
    # letting go of the consumer. The cleanup's own failure must not REPLACE
    # the diagnostic the caller needs, so it is swallowed and `err` is re-raised
    # explicitly rather than with a bare `raise`.
    try:
      endMonitor(result)
    except CatchableError:
      discard
    raise err

proc pollMonitor*(handle: var MonitorHandle): bool =
  ## Advance the monitor WITHOUT blocking. `true` means the monitored root has
  ## exited, i.e. `finishMonitor` will not block on it.
  ##
  ## This is the whole point of DH-2: a scheduler holding N handles polls them
  ## in one loop and finishes each as it completes, instead of serialising the
  ## build behind N blocking `runMonitored` calls.
  ##
  ## Polling is NOT required — `finishMonitor` waits by itself, which is exactly
  ## what `runMonitored` relies on. It is also not a drain: the `nim-shm-gset`
  ## transport dedups at the producer and is snapshotted once at finish, so
  ## there is no consumer-side work that polling more often would get done
  ## sooner. What polling buys is the caller's own scheduling.
  ##
  ## Raises `ValueError` for a handle that is not live (default-constructed,
  ## moved-from, or already finished) rather than answering `true`, which would
  ## read as "your monitor is done".
  ##
  ## **WINDOWS — this call BLOCKS.** `runWithMonitorShim` gives no pollable
  ## handle: it spawns the child, waits for it and returns a completed result.
  ## So the first poll on that arm performs the whole run and returns `true`,
  ## and an N-way poll loop there executes serially. Stated as a limit rather
  ## than hidden behind a `false`, which would spin forever. Lifting it needs a
  ## non-blocking spawn in nim-stackable-hooks and is not DH-2's scope.
  if not handle.active:
    raise newException(ValueError,
      "pollMonitor: this MonitorHandle does not own a live monitor (it was " &
        "default-constructed, moved from, or already finished)")
  if handle.exited:
    return true
  when defined(linux) or defined(macosx):
    if handle.process == nil:
      return true
    let code = peekExitCode(handle.process)
    if code < 0:
      return false
    # DH-4 — through the SAME writer the batch path uses, so the two launch
    # paths cannot disagree about the status they report.
    recordRootExit(handle, code)
    return true
  elif defined(windows):
    waitForMonitorRoot(handle)
    return true
  else:
    return true

proc collectMonitorEvidence(h: var MonitorHandle): MonitorDepFile =
  ## **The single funnel every `MonitorResult`'s evidence comes out of
  ## (IoMon-Decomposed-Host-API DH-3).** Runs the §4.1 detached-descendant guard,
  ## then merges the edge's evidence into the canonical depfile.
  ##
  ## WHY THIS PROC EXISTS AT ALL — it would be shorter to inline these steps back
  ## into `finishMonitor`, and that is exactly what DH-2 had. The problem with an
  ## inlined guard is that it is a STATEMENT: it holds only while the statement
  ## is where somebody put it, and the failure mode of losing it is the cardinal
  ## sin — a `mcComplete` edge over a dependency set a detached descendant was
  ## still adding to. So the guard and the merge are made ONE step with the guard
  ## first, and the step is gated on the guard's own flag:
  ##
  ##  * `settleMonitorDescendants` is the only writer of `h.settled`;
  ##  * nothing here merges anything for a handle where that flag is false;
  ##  * `finishMonitor` contains no merge of its own, so there is no second
  ##    route to a `MonitorDepFile` for a handle.
  ##
  ## What each half catches is different, and both are needed. Deleting or
  ## reordering the guard call trips the gate, so a bypass surfaces as a LOUD
  ## `ValueError` on every arm instead of a quiet false `mcComplete` — the
  ## cardinal sin is converted into a crash. A guard that is called but does
  ## nothing still passes the gate, and that is what
  ## `tests/linux/test_io_mon_external_host_descendant_guard.nim` catches, by
  ## running a real detached descendant past a real grace window and demanding
  ## the `mcIncomplete` downgrade.
  ##
  ## ORDER IS LOAD-BEARING ON LINUX, which is the other reason this is one proc.
  ## The guard publishes its `mrEventLoss` INTO the consumer-owned `nim-shm-gset`
  ## (`appendLauncherEventLoss` → `emitLauncherLossToSet`), and the snapshot
  ## below is taken ONCE. A settle that ran after the snapshot would insert a
  ## marker nobody ever reads: `summarizeRecords` would never count it into
  ## `eventLossCount`, and the edge would publish `mcComplete`. So "the guard
  ## ran" and "the guard ran in time" are the same requirement here, and keeping
  ## both inside one proc is what stops them drifting apart.
  settleMonitorDescendants(h)
  if not h.settled:
    # Unreachable while `settleMonitorDescendants` is what runs above — which is
    # the point. This is not a defensive nicety: it is the mechanism that makes
    # the guard unskippable rather than merely present, and it fails CLOSED.
    raise newException(ValueError,
      "io-mon internal invariant: refusing to produce evidence for a monitor " &
        "whose §4.1 detached-descendant guard has not run — that would risk a " &
        "false mcComplete over a set a detached descendant is still growing")
  when defined(macosx):
    result = mergeFragments(h.fragmentDir, h.request.depFilePath,
      expectedRootPid = h.rootPid)
  elif defined(linux):
    # io-mon-Lossless-Event-Capture M3 part 2a — SINGLE-THREADED final merge over
    # the SET's DISTINCT elements. The DEP-FLUSH shutdown guarantees every producer
    # published its last record, so snapshot the deduped union of all shards and
    # decode each element (identity element-key + trailing incarnation-image bytes)
    # back to a `MonitorRecord` (seq reconstructs as 0). These fold into the
    # merge via the `setRecords` argument.
    #
    # The guard above already ran, so a launcher-side event-loss (a descendant
    # still alive past the grace window) is ALREADY in the consumer-owned set and
    # this snapshot picks it up — file-free end-to-end on Linux, no `.rmdf-frag`.
    #
    # DETERMINISM: `snapshot` yields elements in hash-slot order (non-deterministic
    # across runs), and two DISTINCT elements can tie in `canonicalOrder` because
    # the identity key drops `seq` (decoded to 0). Sort the raw distinct elements —
    # a total order, since they are unique — BEFORE decoding, so the stable
    # canonical sort in `writeCanonicalInPlace` breaks those ties deterministically
    # and the depfile is byte-reproducible (the golden-regression invariant).
    var depDrained: seq[MonitorRecord] = @[]
    if h.depSetLive:
      var elems = h.depSet.snapshot()
      elems.sort(proc (a, b: seq[byte]): int =
        let m = min(a.len, b.len)
        for i in 0 ..< m:
          if a[i] != b[i]: return cmp(a[i], b[i])
        cmp(a.len, b.len))
      for elem in elems:
        var ok = false
        let rec = decodeDepRecord(elem, ok)
        if ok:
          depDrained.add rec
      # A SIGNALLED growth failure (OOM) is LOUD, never a silent drop: surface it
      # so the merged edge is understood as potentially incomplete.
      let growthFailed = h.depSet.growthFailures()
      if growthFailed > 0'u64:
        stderr.writeLine("io-mon: dep-set growth failed " & $growthFailed &
          " time(s); dependency capture may be incomplete for this edge")
    result = mergeFragments(h.fragmentDir, h.request.depFilePath,
      expectedRootPid = h.rootPid, currentRunId = h.runId,
      setRecords = depDrained)
  elif defined(windows):
    var launcherRecords: seq[MonitorRecord] = @[]
    if h.injection.monitoringSkipped:
      launcherRecords.add MonitorRecord(
        kind: mrEventLoss,
        observationKind: moEventLoss,
        osPid: uint64(getCurrentProcessId()),
        detail: "unmonitored subtree/peer (" & h.injection.skipReason & ")")
    # ROUND-2 R1, applied to Windows. macOS and Linux have always passed the
    # root pid so the merge can PROVE the root reported; Windows did not, and
    # the asymmetry hid a real failure: a WOW64 child whose shim loaded but
    # never initialised emitted nothing at all, and with no expected pid to
    # miss, the merge asserted mcComplete over a record set containing only
    # the backend-provenance banner. An injected root that reports nothing is
    # the one case where "no evidence" and "no dependencies" look identical
    # from the inside, so the launcher has to supply the pid that should have
    # appeared.
    #
    # Skipped when monitoring was deliberately skipped (an MSYS/Cygwin fork
    # runtime): that subtree is already recorded as an unmonitored-peer loss
    # just above, and demanding a process-start from a process we chose not
    # to inject would report the same gap twice. `h.rootPid` is already 0 in
    # that case (`waitForMonitorRoot`).
    #
    # ARMED SINCE DH-1's follow-up — this is new capability, not a restored
    # regression. nim-stackable-hooks 485a30c added `rootPid` (the pid
    # `CreateProcessW` already produces, `pi.dwProcessId`), so the pid exists to
    # pass. What changes: an injected root that emits NOTHING used to be
    # published as `mcComplete` over an empty record set — a zero-effort false
    # cache hit for the whole action — and is now downgraded to `mcIncomplete`.
    result = mergeFragments(h.fragmentDir, h.request.depFilePath,
      expectedRootPid = h.rootPid, setRecords = launcherRecords)

proc finishMonitor*(handle: sink MonitorHandle): MonitorResult =
  ## **Public parent-host API (IoMon-Decomposed-Host-API DH-2).** Consume the
  ## handle and produce the evidence: wait for the root if it has not exited,
  ## run the §4.1 detached-descendant grace, snapshot the consumer-owned set,
  ## write the canonical depfile, and release everything.
  ##
  ## Takes the handle by `sink`: the result is obtainable only by GIVING UP the
  ## handle, so a caller cannot keep polling (or finishing) a monitor whose
  ## consumer has been released. Pass a `move`d handle when the caller's binding
  ## is not dead at the call site.
  ##
  ## The steps are the same procs a dropped handle's destructor runs, in the
  ## same order, with the evidence collected between them — `waitForMonitorRoot`
  ## then `releaseMonitor` — so LF-2's ordering has one implementation and this
  ## path cannot drift from that one.
  ##
  ## **DH-3 — the §4.1 descendant guard is NOT SKIPPABLE from out here.** It is
  ## not a step this proc politely remembers to take: the evidence is produced by
  ## `collectMonitorEvidence`, whose first act is the guard and which refuses to
  ## merge for a handle the guard has not marked. Combined with `startMonitor`
  ## being the module's only spawn site and this proc being the only producer of
  ## a `MonitorResult`, a host CANNOT reach an edge's completeness verdict along
  ## a path the guard did not run on — which is why
  ## `waitForLinuxInjectedDescendants` / `liveInjectedDescendants` stay private
  ## rather than being exported for hosts to call themselves.
  ##
  ## Raises `ValueError` for a handle that is not live.
  var h = move(handle)
  if not h.active:
    raise newException(ValueError,
      "finishMonitor: this MonitorHandle does not own a live monitor (it was " &
        "default-constructed, moved from, or already finished)")
  discard monitorsFinishedCount.fetchAdd(1'u64)
  result.depFilePath = h.request.depFilePath

  waitForMonitorRoot(h)
  result.exitCode = h.exitCode

  # DH-3 — the evidence is produced HERE and only here, by the one funnel that
  # runs the §4.1 descendant guard first and refuses to merge without it. There
  # is deliberately no per-arm merge in this proc: a second route to a
  # `MonitorDepFile` is a second route around the guard.
  result.depFile = collectMonitorEvidence(h)

  renderStreamToPath(h.request.depFilePath, h.request.streamMode,
    h.request.eventStreamPath)
  releaseMonitor(h)

proc runMonitored*(request: FsSnoopRequest): MonitorResult =
  ## **Public parent-host API (io-mon-Lossless-Event-Capture §5, M6 part A).**
  ##
  ## The blessed BATCH consumer-side entry point: run one monitored command to
  ## completion and return its evidence. It is the CLI's entry point
  ## (`runFsSnoopCli`) and the reference behaviour every other launch path is
  ## diffed against.
  ##
  ## Since DH-2 it is **exactly** `finishMonitor(startMonitor(request))` — one
  ## expression, and the ONLY implementation of the lifecycle lives in those two
  ## procs. That is deliberate rather than tidy: a batch form and a decomposed
  ## form maintained side by side would drift, and the whole premise of DH-4
  ## (byte-identical evidence from an external host) is that they agree. The
  ## delegation is asserted at RUNTIME, not just here, by
  ## `tests/linux/test_io_mon_decomposed_host_api.nim` via
  ## `monitorLifecycleCounts`.
  ##
  ## What the two halves do, unchanged from the pre-DH-2 single proc:
  ##
  ##   1. resolve the interpose shim (`findShimLibrary`);
  ##   2. on Linux, CREATE the consumer-owned `nim-shm-gset` (via
  ##      `transport.startHost`, appId defaulting to `"io-mon"` or
  ##      `REPRO_MONITOR_APP_ID`) and export `REPRO_MONITOR_DEP_SHM` +
  ##      `REPRO_MONITOR_APP_ID` so the shim's producers attach the RIGHT set;
  ##   3. inject the shim and SPAWN the monitored process tree;
  ##   4. wait for the tree, run the §4.1 descendant grace, SNAPSHOT the deduped
  ##      set, and write the canonical depfile via `mergeFragments` (passing the
  ##      spawned root pid as the R1 root-guard, so an un-monitored root
  ##      downgrades to `mcIncomplete` instead of a false `mcComplete`);
  ##   5. on FINISH call `SetHost.finish` (`markConsumerGone` + detach), so a
  ##      late orphan `emit` fast-fails with `emConsumerGone` (LF-4) and the
  ##      consumer-owned memory is released.
  ##
  ## **LF-2 (no orphan spill) and LF-4 (consumer liveness) still hold by
  ## construction** — but for a different reason than before DH-2, and the
  ## difference matters to anyone reading this as the reference. It used to be
  ## that this proc owned the whole lifecycle so no caller could hold one end of
  ## it. Now the GUARANTEE lives in `MonitorHandle`: it cannot be copied and
  ## dropping it reaps the monitored root before releasing the consumer. This
  ## proc inherits that like any other host; it is not privileged.
  ##
  ## Never spawns a consumer-less producer; still raises on a genuine setup
  ## failure (no shim, unsupported platform) — the CLI wrapper `runFsSnoopCli`
  ## converts those to a diagnostic + non-zero exit.
  ##
  ## **CONCURRENCY (IoMon-Decomposed-Host-API DH-1).** On ALL THREE arms this
  ## proc mutates NOTHING process-global: the injection variables and
  ## `request.env` are composed into a child-only environment handed to the
  ## spawn, and `request.cwd` is the child's working directory. Two (or N) calls
  ## may therefore run concurrently on separate threads of one host process and
  ## each gets its own complete, uncontaminated evidence. Since DH-2 a host does
  ## not even need the threads: `startMonitor` + `pollMonitor` interleaves N
  ## monitors in ONE thread.
  ##
  ## One residual, documented exception: **macOS** inherits `osproc`'s own
  ## global `setCurrentDir` around its `posix_spawn` path, so a non-empty
  ## `request.cwd` is not thread-safe there. Linux forks and `chdir`s in the
  ## child and Windows passes `lpCurrentDirectory`, so both are.
  finishMonitor(startMonitor(request))

proc runFsSnoopCli*(programName: string; args: seq[string]): int =
  try:
    var parsed = parseFsSnoopCommand(args)
    if parsed.inspectMode:
      echo renderMonitorDepFile(parsed.inspectPath, parsed.inspectFormat)
      return 0

    var tempRoot = ""
    if parsed.request.depFilePath.len == 0:
      tempRoot = createLocalTempDir("repro-fs-snoop")
      parsed.request.depFilePath = tempRoot / "evidence.rdep"
    try:
      # The CLI is a thin wrapper over the public batch host API — no duplicated
      # lifecycle. `runMonitored` owns the shm/consumer setup; we only surface
      # its exit code (the depfile it wrote is inspected out-of-band).
      result = runMonitored(parsed.request).exitCode
    finally:
      if tempRoot.len > 0:
        # Best-effort cleanup. On Windows the monitor shim's lingering
        # handles (file-handle reuse, deferred delete on close) can
        # leave directory entries that the regular ``removeDir`` cannot
        # immediately unlink — Windows reports "the directory is not
        # empty" even when the rdep / metadata files have already been
        # opened+closed cleanly. Surfacing that as an action failure
        # masks the underlying build's actual exit status (the cargo
        # build that just succeeded), so suppress the diagnostic and
        # let the OS reap the temp tree on the next scratch sweep. The
        # temp directory's contents are evidence-only and never
        # cross-process consumed.
        try:
          removeLocalTempDir(tempRoot)
        except OSError:
          discard
  except CatchableError as err:
    stderr.writeLine(programName & ": error: " & err.msg)
    result = 1
