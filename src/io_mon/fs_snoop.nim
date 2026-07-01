import std/[os, osproc, strutils, times]
from io_mon/paths import extendedPath

import io_mon/reader
import io_mon/render
import io_mon/types
import io_mon/writer

when defined(linux):
  import std/[monotimes, sequtils]

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

  proc appendLauncherEventLoss(fragmentDir, runId, detail: string) =
    appendFragmentRecord(fragmentDir, MonitorRecord(
      kind: mrEventLoss,
      observationKind: moEventLoss,
      osPid: uint64(getCurrentProcessId()),
      detail: detail & " run=" & runId))

  proc waitForLinuxInjectedDescendants(fragmentDir, runId: string;
      rootPid: uint64) =
    let graceMs = envInt("IO_MON_LINUX_DESCENDANT_GRACE_MS",
      LinuxInjectedDescendantGraceMsDefault, 0)
    let pollMs = envInt("IO_MON_LINUX_DESCENDANT_POLL_MS",
      LinuxInjectedDescendantPollMsDefault, 1)
    let start = getMonoTime()
    while true:
      let live = liveInjectedDescendants(runId, fragmentDir, rootPid)
      if live.scanFailed:
        appendLauncherEventLoss(fragmentDir, runId,
          "linux injected-descendant /proc scan failed")
        return
      if live.pids.len == 0:
        return
      let elapsedMs = inMilliseconds(getMonoTime() - start)
      if elapsedMs >= graceMs:
        appendLauncherEventLoss(fragmentDir, runId,
          "linux injected descendants still live after root exit pids=" &
            live.pids.join(","))
        return
      sleep(min(pollMs, graceMs - int(elapsedMs)))

# Windows: pull in the CreateRemoteThread+LoadLibraryW injector that
# substitutes for the macOS DYLD_INSERT_LIBRARIES env-var injection.
when defined(windows):
  import io_mon/windows_injector

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
    "/usr/bin/sleep"
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
    ## symlink to the non-SIP alternative found on PATH; when none exists we
    ## fall back to a byte-copy (effective on Linux / pre-arm64e macOS).
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
      # No non-SIP alternative on PATH — fall back to byte-copy. This
      # is the documented path for Linux and pre-arm64e macOS; on
      # macOS 26 / arm64e the copy will fail to execute and the spawn
      # hook will fall back to the SIP-stripped original.
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

proc candidateShimLibraries(): seq[string] =
  let appDir = getAppDir()
  # Windows: the shim builds as a .dll instead of a .dylib; probe both so the
  # same lookup logic works on either platform without runtime branching at
  # every call site. The explicit env override is still honoured first.
  when defined(windows):
    result = @[
      getEnv("REPRO_MONITOR_SHIM_LIB"),
      appDir / ".." / "lib" / "librepro_monitor_shim.dll",
      appDir / "librepro_monitor_shim.dll",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dll"
    ]
  elif defined(linux):
    result = @[
      getEnv("REPRO_MONITOR_SHIM_LIB"),
      appDir / ".." / "lib" / "librepro_monitor_shim.so",
      appDir / "librepro_monitor_shim.so",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.so"
    ]
  else:
    result = @[
      getEnv("REPRO_MONITOR_SHIM_LIB"),
      appDir / ".." / "lib" / "librepro_monitor_shim.dylib",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dylib"
    ]

proc findShimLibrary*(): string =
  ## **Public since M9.R.13c.2** — the build engine's ``monitoredAction``
  ## now seeds ``REPRO_MONITOR_SHIM_LIB`` on the action's env at wrap
  ## time, so the daemon-spawned ``repro internal fs-snoop`` subprocess
  ## resolves the shim without inheriting the user's shell environment.
  ##
  ## Lookup order (see ``candidateShimLibraries``):
  ##   1. ``$REPRO_MONITOR_SHIM_LIB`` env override (operator pin).
  ##   2. ``<appDir>/../lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (canonical build layout — what ``just build`` produces).
  ##   3. ``<appDir>/librepro_monitor_shim.{dll,so}`` (Windows-only
  ##      side-by-side install layout).
  ##   4. ``<cwd>/build/lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (running from the repo root with a freshly built tree).
  ##
  ## Returns the absolute path of the first existing candidate, or the
  ## empty string when no candidate exists.
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

proc runMonitoredCommand(request: FsSnoopRequest): int =
  when defined(macosx):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.dylib; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    let fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    defer: removeDir(extendedPath(fragmentDir))
    ensureParentDir(request.depFilePath)

    # SIP bypass: ensure CT_SANDBOX_TOOLS_DIR exists and contains non-SIP
    # copies of the shell binaries that monitored subprocesses commonly
    # exec. Without this, /bin/sh (used by osproc.execCmdEx) loses
    # DYLD_INSERT_LIBRARIES and the shim falls silent for the rest of
    # the process tree.
    var sandboxDir = getEnv("CT_SANDBOX_TOOLS_DIR")
    if sandboxDir.len == 0:
      sandboxDir = createLocalTempDir("repro-fs-snoop-sandbox-tools")
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
    result = waitForExit(process)
    close(process)

    discard mergeFragments(fragmentDir, request.depFilePath,
      expectedRootPid = rootPid)
    discard readMonitorDepFile(request.depFilePath)
    renderStreamToPath(request.depFilePath, request.streamMode,
      request.eventStreamPath)
  elif defined(linux):
    let shimLib = findShimLibrary()
    if shimLib.len == 0:
      raise newException(IOError,
        "cannot find librepro_monitor_shim.so; run just build or set " &
          "REPRO_MONITOR_SHIM_LIB")

    let fragmentDir = createLocalTempDir("repro-fs-snoop-fragments")
    defer: removeDir(extendedPath(fragmentDir))
    ensureParentDir(request.depFilePath)

    var oldEnv: seq[(string, string, bool)] = @[]
    let runId = $epochTime()
    setEnvVar("LD_PRELOAD", injectionValue(shimLib), oldEnv)
    setEnvVar("REPRO_MONITOR_FRAGMENT_DIR", fragmentDir, oldEnv)
    setEnvVar("REPRO_MONITOR_OUTPUT", request.depFilePath, oldEnv)
    setEnvVar("REPRO_MONITOR_SESSION", runId, oldEnv)
    setEnvVar("REPRO_MONITOR_SHIM_LIB", shimLib, oldEnv)
    defer: restoreEnv(oldEnv)

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
    result = waitForExit(process)
    close(process)

    waitForLinuxInjectedDescendants(fragmentDir, runId, rootPid)
    discard mergeFragments(fragmentDir, request.depFilePath,
      expectedRootPid = rootPid, currentRunId = runId)
    discard readMonitorDepFile(request.depFilePath)
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
    defer: removeDir(extendedPath(fragmentDir))
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
    result = injection.exitCode

    discard mergeFragments(fragmentDir, request.depFilePath)
    discard readMonitorDepFile(request.depFilePath)
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
      result = runMonitoredCommand(parsed.request)
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
          removeDir(extendedPath(tempRoot))
        except OSError:
          discard
  except CatchableError as err:
    stderr.writeLine(programName & ": error: " & err.msg)
    result = 1
