import std/[os, osproc, strutils, times]
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
  import std/[algorithm, monotimes, sequtils]

  const
    LinuxInjectedDescendantGraceMsDefault = 500
    LinuxInjectedDescendantPollMsDefault = 25

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

  proc linuxProcState(pid: int): tuple[state: char; ok: bool] =
    let statPath = "/proc" / $pid / "stat"
    try:
      let stat = readFile(extendedPath(statPath))
      let closeParen = stat.rfind(")")
      if closeParen < 0 or closeParen + 2 >= stat.len:
        return ('\0', false)
      return (stat[closeParen + 2], true)
    except IOError, OSError:
      return ('\0', false)

  proc environCarriesInvocation(environ, runId, fragmentDir: string): bool =
    let sessionNeedle = "REPRO_MONITOR_SESSION=" & runId
    let fragmentNeedle = "REPRO_MONITOR_FRAGMENT_DIR=" & fragmentDir
    for entry in environ.split('\0'):
      if entry == sessionNeedle or entry == fragmentNeedle:
        return true
    false

  proc liveInjectedDescendants(runId, fragmentDir: string; rootPid: uint64):
      tuple[pids: seq[int]; scanFailed: bool] =
    if not dirExists("/proc"):
      return (@[], true)
    let selfPid = getCurrentProcessId()
    try:
      for kind, path in walkDir("/proc"):
        if kind != pcDir:
          continue
        let name = path.extractFilename
        if name.len == 0 or not name.allIt(it in {'0' .. '9'}):
          continue
        let pid = parseInt(name)
        if pid == selfPid or uint64(pid) == rootPid:
          continue
        let procState = linuxProcState(pid)
        if not procState.ok:
          continue
        if procState.state == 'Z':
          continue
        let envPath = path / "environ"
        var envBytes = ""
        try:
          envBytes = readFile(extendedPath(envPath))
        except IOError, OSError:
          continue
        if environCarriesInvocation(envBytes, runId, fragmentDir):
          result.pids.add pid
    except OSError:
      return (@[], true)

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
      rootPid: uint64; depSetPath0 = "") =
    let graceMs = envInt("IO_MON_LINUX_DESCENDANT_GRACE_MS",
      LinuxInjectedDescendantGraceMsDefault, 0)
    let pollMs = envInt("IO_MON_LINUX_DESCENDANT_POLL_MS",
      LinuxInjectedDescendantPollMsDefault, 1)
    let start = getMonoTime()
    while true:
      let live = liveInjectedDescendants(runId, fragmentDir, rootPid)
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

var tempDirNonce = uint64(getCurrentProcessId())

proc createLocalTempDir(prefix: string): string =
  inc tempDirNonce
  let now = getTime()
  result = getTempDir() / (prefix & "-" & $getCurrentProcessId() & "-" &
    $now.toUnix & "-" & $now.nanosecond & "-" & $tempDirNonce)
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

proc setEnvVar(name, value: string; oldValues: var seq[(string, string, bool)]) =
  oldValues.add((name, getEnv(name), existsEnv(name)))
  putEnv(name, value)

proc restoreEnv(oldValues: seq[(string, string, bool)]) =
  for i in countdown(oldValues.high, 0):
    let (name, value, existed) = oldValues[i]
    if existed:
      putEnv(name, value)
    else:
      delEnv(name)

proc injectionValue(shimLib: string): string =
  when defined(linux):
    const injectionEnv = "LD_PRELOAD"
  else:
    const injectionEnv = "DYLD_INSERT_LIBRARIES"
  let existing = getEnv(injectionEnv)
  if existing.len == 0:
    shimLib
  else:
    shimLib & $PathSep & existing

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

proc runMonitored*(request: FsSnoopRequest): MonitorResult =
  ## **Public parent-host API (io-mon-Lossless-Event-Capture §5, M6 part A).**
  ##
  ## The blessed, batch consumer-side entry point for hosting an io-mon monitor.
  ## This proc OWNS the entire producer/consumer lifecycle so a well-formed
  ## parent can never end up with a producer and no consumer (the structural
  ## cause of an LF-2 orphan spill):
  ##
  ##   1. resolves the interpose shim (`findShimLibrary`);
  ##   2. on Linux, CREATES the consumer-owned `nim-shm-gset` (via
  ##      `transport.startHost`, appId defaulting to `"io-mon"` or
  ##      `REPRO_MONITOR_APP_ID`) and exports `REPRO_MONITOR_DEP_SHM` +
  ##      `REPRO_MONITOR_APP_ID` so the shim's producers attach the RIGHT set;
  ##   3. injects the shim and SPAWNS the monitored process tree;
  ##   4. waits for the tree, SNAPSHOTS the deduped set, and writes the canonical
  ##      depfile via `mergeFragments` (passing the spawned root pid as the R1
  ##      root-guard, so an un-monitored root downgrades to `mcIncomplete`
  ##      instead of a false `mcComplete`);
  ##   5. on FINISH calls `SetHost.finish` (`markConsumerGone` + detach), so a
  ##      late orphan `emit` fast-fails with `emConsumerGone` (LF-4) and the
  ##      consumer-owned memory is released.
  ##
  ## Because the consumer structure is created, named, and torn down HERE — not
  ## by the caller — LF-2 (no orphan spill) and LF-4 (consumer liveness) hold by
  ## construction for any parent that uses this proc. Prefer this over copying
  ## the driver: a copy that skips step 2 is exactly the producer-with-no-consumer
  ## bug this API exists to prevent.
  ##
  ## Never spawns a consumer-less producer; still raises on a genuine setup
  ## failure (no shim, unsupported platform) — the CLI wrapper `runFsSnoopCli`
  ## converts those to a diagnostic + non-zero exit.
  result.depFilePath = request.depFilePath
  when defined(macosx):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.dylib; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    let fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    defer: removeLocalTempDir(fragmentDir)
    ensureParentDir(request.depFilePath)

    # SIP bypass: ensure CT_SANDBOX_TOOLS_DIR exists and contains non-SIP
    # copies of the shell binaries that monitored subprocesses commonly
    # exec. Without this, /bin/sh (used by osproc.execCmdEx) loses
    # DYLD_INSERT_LIBRARIES and the shim falls silent for the rest of
    # the process tree.
    var sandboxDir = getEnv("CT_SANDBOX_TOOLS_DIR")
    let ownsSandboxDir = sandboxDir.len == 0
    if ownsSandboxDir:
      sandboxDir = createLocalTempDir("repro-fs-snoop-sandbox-tools")
    # Only the fallback created by this invocation belongs to io-mon.  An
    # operator-provided CT_SANDBOX_TOOLS_DIR may be a persistent, pre-built
    # bundle and must never be removed.  Register ownership cleanup before
    # populating the tree so setup failures, spawn failures, non-zero child
    # exits, and successful runs all release the same invocation-local path.
    defer:
      if ownsSandboxDir:
        removeLocalTempDir(sandboxDir)
    populateReproSandboxTools(sandboxDir)

    var oldEnv: seq[(string, string, bool)] = @[]
    setEnvVar("CT_SANDBOX_TOOLS_DIR", sandboxDir, oldEnv)
    setEnvVar("DYLD_INSERT_LIBRARIES", injectionValue(shimLib), oldEnv)
    setEnvVar("REPRO_MONITOR_FRAGMENT_DIR", fragmentDir, oldEnv)
    setEnvVar("REPRO_MONITOR_OUTPUT", request.depFilePath, oldEnv)
    setEnvVar("REPRO_MONITOR_SESSION", $epochTime(), oldEnv)
    setEnvVar("REPRO_MONITOR_SHIM_LIB", shimLib, oldEnv)
    defer: restoreEnv(oldEnv)

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
    let process = startProcess(effectiveCommand[0],
      args = childArgs,
      options = {poUsePath, poParentStreams})
    # ROUND-2 R1 — remember the root pid so the merge can PROVE the root was
    # monitored. A SIP/hardened/notarized root (e.g. /bin/cat) strips
    # DYLD_INSERT_LIBRARIES and emits no process-start; passing its pid to
    # mergeFragments downgrades that case to mcIncomplete instead of asserting a
    # false mcComplete over an empty record set.
    let rootPid = uint64(process.processID)
    result.exitCode = waitForExit(process)
    close(process)

    result.depFile = mergeFragments(fragmentDir, request.depFilePath,
      expectedRootPid = rootPid)
    renderStreamToPath(request.depFilePath, request.streamMode,
      request.eventStreamPath)
  elif defined(linux):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.so; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    let fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    defer: removeLocalTempDir(fragmentDir)
    ensureParentDir(request.depFilePath)

    var oldEnv: seq[(string, string, bool)] = @[]
    let runId = $epochTime()
    setEnvVar("LD_PRELOAD", injectionValue(shimLib), oldEnv)
    setEnvVar("REPRO_MONITOR_FRAGMENT_DIR", fragmentDir, oldEnv)
    setEnvVar("REPRO_MONITOR_OUTPUT", request.depFilePath, oldEnv)
    setEnvVar("REPRO_MONITOR_SESSION", runId, oldEnv)

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
    var depSet: SetHost
    let depSetEnabled = shmGSetSupported and
      getEnv("REPRO_MONITOR_DEP_SHM_DISABLE").len == 0
    if depSetEnabled:
      # The appId scopes the SET's cross-restart reaper so one application never
      # reaps another's shared-memory segments (segment name gains an `{appId}~`
      # prefix; content is unaffected). Defaults to "io-mon"; a consumer that
      # shares a segments directory (reprobuild/codetracer) overrides it via
      # REPRO_MONITOR_APP_ID so its reaper stays scoped to its own segments.
      let depSetAppId = getEnv("REPRO_MONITOR_APP_ID", "io-mon")
      depSet = startHost(fragmentDir, runId, appId = depSetAppId)
      if depSet.available:
        setEnvVar("REPRO_MONITOR_DEP_SHM", depSet.path0, oldEnv)
        # Export the resolved appId too, so a producer that re-derives the
        # reaper scope (or an in-tree consumer that shares the segments dir)
        # sees the SAME tag the host created shard0 under — part of the §5
        # host owning the whole structure lifecycle, not just naming it.
        setEnvVar("REPRO_MONITOR_APP_ID", depSetAppId, oldEnv)
    setEnvVar("REPRO_MONITOR_SHIM_LIB", shimLib, oldEnv)
    defer: restoreEnv(oldEnv)
    defer:
      # End the host lifecycle: announce the consumer is gone (a late orphan
      # `emit` then fast-fails with `emConsumerGone` instead of growing the set —
      # LF-4 / the orphan-bounded property), then unmap.
      if depSet.available:
        depSet.finish()

    let childArgs =
      if request.command.len > 1:
        request.command[1 .. ^1]
      else:
        @[]
    let process = startProcess(request.command[0],
      args = childArgs,
      options = {poUsePath, poParentStreams})
    # ROUND-2 R1 — see the macOS branch: prove the root was monitored.
    let rootPid = uint64(process.processID)

    # The set requires NO concurrent drain (idempotent inserts, no backpressure),
    # so just wait for the tree to exit.
    result.exitCode = waitForExit(process)
    close(process)

    # io-mon-Lossless-Event-Capture M7 (Linux slice) — hand the live set's shard0
    # path so a launcher-side event-loss (a descendant still alive past the grace
    # window) is inserted into the CONSUMER-OWNED set, folded into the depfile by
    # the snapshot below, with NO `.rmdf-frag` file — Linux is file-free end-to-end.
    let launcherLossPath0 = if depSet.available: depSet.path0 else: ""
    waitForLinuxInjectedDescendants(fragmentDir, runId, rootPid, launcherLossPath0)
    # io-mon-Lossless-Event-Capture M3 part 2a — SINGLE-THREADED final merge over
    # the SET's DISTINCT elements. The DEP-FLUSH shutdown guarantees every producer
    # published its last record, so snapshot the deduped union of all shards and
    # decode each element (identity element-key + trailing incarnation-image bytes)
    # back to a `MonitorRecord` (seq reconstructs as 0). These fold into the
    # merge via the `setRecords` argument.
    #
    # DETERMINISM: `snapshot` yields elements in hash-slot order (non-deterministic
    # across runs), and two DISTINCT elements can tie in `canonicalOrder` because
    # the identity key drops `seq` (decoded to 0). Sort the raw distinct elements —
    # a total order, since they are unique — BEFORE decoding, so the stable
    # canonical sort in `writeCanonicalInPlace` breaks those ties deterministically
    # and the depfile is byte-reproducible (the golden-regression invariant).
    var depDrained: seq[MonitorRecord] = @[]
    if depSet.available:
      var elems = depSet.snapshot()
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
      let growthFailed = depSet.growthFailures()
      if growthFailed > 0'u64:
        stderr.writeLine("io-mon: dep-set growth failed " & $growthFailed &
          " time(s); dependency capture may be incomplete for this edge")
    result.depFile = mergeFragments(fragmentDir, request.depFilePath,
      expectedRootPid = rootPid, currentRunId = runId,
      setRecords = depDrained)
    renderStreamToPath(request.depFilePath, request.streamMode,
      request.eventStreamPath)
  elif defined(windows):
    # Windows: same end-to-end flow as macOS, but the injection uses
    # CreateProcess(CREATE_SUSPENDED) + CreateRemoteThread(LoadLibraryW)
    # instead of the DYLD_INSERT_LIBRARIES env var. Fragment-dir + output
    # path env vars are still set so the in-DLL hook bodies know where to
    # append RMDF fragments.
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.dll; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    let fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    defer: removeLocalTempDir(fragmentDir)
    ensureParentDir(request.depFilePath)

    var oldEnv: seq[(string, string, bool)] = @[]
    setEnvVar("REPRO_MONITOR_FRAGMENT_DIR", fragmentDir, oldEnv)
    setEnvVar("REPRO_MONITOR_OUTPUT", request.depFilePath, oldEnv)
    setEnvVar("REPRO_MONITOR_SESSION", $epochTime(), oldEnv)
    setEnvVar("REPRO_MONITOR_SHIM_LIB", shimLib, oldEnv)
    defer: restoreEnv(oldEnv)

    let injection = runWithMonitorShim(request.command, shimLib,
                                       captureStdio = request.captureChildStdio,
                                       captureStdioPath = request.captureStdioPath)
    result.exitCode = injection.exitCode

    var launcherRecords: seq[MonitorRecord] = @[]
    if injection.monitoringSkipped:
      launcherRecords.add MonitorRecord(
        kind: mrEventLoss,
        observationKind: moEventLoss,
        osPid: uint64(getCurrentProcessId()),
        detail: "unmonitored subtree/peer (" & injection.skipReason & ")")
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
    # to inject would report the same gap twice.
    result.depFile = mergeFragments(fragmentDir, request.depFilePath,
      expectedRootPid =
        if injection.monitoringSkipped: 0'u64 else: injection.rootPid,
      setRecords = launcherRecords)
    renderStreamToPath(request.depFilePath, request.streamMode,
      request.eventStreamPath)
  else:
    raise newException(OSError,
      "fs-snoop hooks backend currently supports macOS, Linux, and Windows only")

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
