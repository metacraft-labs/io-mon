## Two separately identified io-mon shims meeting in one nested capture.
##
## An outer monitor (shim A) runs a host that starts an inner monitor with its
## own shim B, the way a development build of a tool meets an installed one.
## The inner monitor's child is then preloaded with both images, and a
## monitored process must carry exactly one ACTIVE io-mon shim: the child is
## recorded by the inner run alone, and the outer run sees it through the
## nested handoff.
##
## B is a copy of A with its own SONAME (`patchelf --set-soname`), so the
## loader treats the two as distinct objects, as it does a separately built
## shim; a plain byte copy is the weaker fixture the macOS port warned about.
## Two hosts meet the two shims in different preload orders:
##
## - `inherited`: io-mon's own host (`runMonitored`) prepends B to the
##   LD_PRELOAD it inherited from A's process, so the child gets `B:A`. Run
##   over both dependency transports: the shared-memory set deduplicates
##   identical records, so only the file fragments show a record written by
##   both images (two active images write two process-starts for the
##   reader's pid).
## - `engine-route`: a host that keeps A as its own shim seeds a complete
##   route naming B into the child's environment, the way a build engine seeds
##   an action's environment, and spawns the child itself. The spawn passes
##   through shim A's hook, which must hand the child to B rather than put A
##   in front of it. The host merges the inner fragments and hands them to the
##   outer run through the nested handoff, as an inner monitor does. File
##   fragments only: the set is created by a monitor host, and this host is
##   not one.
##
## No mocks: the production shim, real processes, real captures. Every launch
## is bounded by the 30-second wait below.
import std/[os, osproc, sequtils, streams, strtabs, strutils, tempfiles,
            unittest]
import io_mon
import io_mon/nested_capture
import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc mappedShimImages(): seq[string] =
  ## The io-mon shim files mapped into this process, from /proc/self/maps.
  for line in lines("/proc/self/maps"):
    let at = line.find('/')
    if at < 0: continue
    let path = line[at .. ^1]
    if path.extractFilename == "librepro_monitor_shim.so" and path notin result:
      result.add path

type ActiveQuery = proc (): cint {.cdecl, raises: [].}
proc dlopen(path: cstring; flags: cint): pointer
  {.importc, header: "<dlfcn.h>".}
proc dlsym(handle: pointer; name: cstring): pointer
  {.importc, header: "<dlfcn.h>".}
proc dlclose(handle: pointer): cint {.importc, header: "<dlfcn.h>".}
let rtldNow {.importc: "RTLD_NOW", header: "<dlfcn.h>".}: cint
let rtldNoload {.importc: "RTLD_NOLOAD", header: "<dlfcn.h>".}: cint

proc activeShimImages(): seq[string] =
  ## The mapped shim images that report themselves active. An image that does
  ## not export the query, such as an older shim build, initialises its
  ## recording runtime unconditionally and is counted as active.
  for path in mappedShimImages():
    let image = dlopen(path.cstring, rtldNow or rtldNoload)
    doAssert image != nil, "mapped shim is not loaded: " & path
    let query = dlsym(image, "repro_linux_monitor_shim_is_active")
    # dlsym on an image handle may resolve through the image's dependencies;
    # only a definition inside this image answers for it.
    if query == nil or cast[ActiveQuery](query)() != 0:
      result.add path
    discard dlclose(image)

if paramCount() == 3 and paramStr(1) == "--reader":
  # The inner monitor's child.
  let work = paramStr(2)
  let order = paramStr(3)
  let mapped = mappedShimImages()
  if order == "inherited":
    # The child inherits shim A from its host's LD_PRELOAD and gets B in
    # front of it: it carries both images, or this order proves nothing
    # about their coexistence.
    doAssert mapped.len == 2, "mapped shims: " & $mapped & " LD_PRELOAD=" &
      getEnv("LD_PRELOAD")
  else:
    # The route named B alone; A's spawn hook must not have added itself.
    doAssert mapped.len == 1, "mapped shims: " & $mapped & " LD_PRELOAD=" &
      getEnv("LD_PRELOAD")
  let active = activeShimImages()
  doAssert active.len == 1, "active shims: " & $active & " LD_PRELOAD=" &
    getEnv("LD_PRELOAD")
  # The active image is the one the inner monitor asked for.
  doAssert sameFile(active[0], getEnv("REPRO_MONITOR_SHIM_LIB")),
    "active=" & active[0] & " requested=" & getEnv("REPRO_MONITOR_SHIM_LIB") &
    " LD_PRELOAD=" & getEnv("LD_PRELOAD")
  doAssert readFile(work / "inner-input") == "inner"
  writeFile(work / "inner-output", "written")
  quit(0)

if paramCount() == 4 and paramStr(1) == "--host":
  # Runs under the outer monitor (shim A); starts the inner run with shim B.
  let work = paramStr(2)
  let order = paramStr(3)
  let innerShim = paramStr(4)
  let reader = @["--reader", work, order]
  if order == "inherited":
    putEnv("REPRO_MONITOR_SHIM_LIB", innerShim)
    let inner = runMonitored(FsSnoopRequest(
      command: @[getAppFilename()] & reader,
      depFilePath: work / "inner.iomon",
      streamMode: fsoNone))
    doAssert inner.exitCode == 0, "inner reader failed"
  else:
    # This process's own REPRO_MONITOR_SHIM_LIB stays A. The child's route is
    # a new run: its own fragment directory and session, shim B, B preloaded.
    let session = "engine-route-" & $getCurrentProcessId()
    let fragments = work / "inner-fragments"
    createDir(fragments)
    let capture = startNestedCapture(getEnv("REPRO_MONITOR_FRAGMENT_DIR"),
      getEnv("REPRO_MONITOR_SESSION"), session)
    var env = newStringTable(modeCaseSensitive)
    for key, value in envPairs(): env[key] = value
    # The enclosing route's other controls name A's run, not this one.
    for name in ["REPRO_MONITOR_INTEREST", "REPRO_MONITOR_EVIDENCE",
                 "REPRO_MONITOR_DEP_SHM", "REPRO_MONITOR_APP_ID",
                 "REPRO_MONITOR_COLLECTION_EVIDENCE", "REPRO_MONITOR_OUTPUT"]:
      env.del(name)
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragments
    env["REPRO_MONITOR_SESSION"] = session
    env["REPRO_MONITOR_SHIM_LIB"] = innerShim
    env["REPRO_MONITOR_EXEC_GEN"] = "0"
    env["LD_PRELOAD"] = innerShim
    let child = startProcess(getAppFilename(), args = reader, env = env,
      options = {poParentStreams})
    let childPid = child.processID
    let code = child.waitForExit()
    child.close()
    doAssert code == 0, "inner reader failed"
    let inner = mergeFragments(fragments, work / "inner.iomon",
      expectedRootPid = uint64(childPid), currentRunId = session)
    finishNestedCapture(capture, inner.records)
  doAssert readFile(work / "outer-input") == "outer"
  quit(0)

if paramCount() == 5 and paramStr(1) == "--outer":
  let work = paramStr(2)
  putEnv("REPRO_MONITOR_SHIM_LIB", paramStr(3))
  let outer = runMonitored(FsSnoopRequest(
    command: @[getAppFilename(), "--host", work, paramStr(4), paramStr(5)],
    depFilePath: work / "outer.iomon",
    streamMode: fsoNone))
  doAssert outer.exitCode == 0, "outer host failed"
  quit(0)

proc copyLinuxShimAsDistinctImage(shim, dest: string) =
  ## A second, separately identified shim: same code, its own SONAME.
  copyFile(shim, dest)
  let (output, code) = execCmdEx(quoteShellCommand(["patchelf",
    "--set-soname", "librepro_monitor_shim_inner.so", dest]))
  doAssert code == 0, "patchelf: " & output
  let (soname, sonameCode) = execCmdEx(quoteShellCommand(["patchelf",
    "--print-soname", dest]))
  doAssert sonameCode == 0 and soname.strip == "librepro_monitor_shim_inner.so",
    "SONAME of " & dest & ": " & soname

suite "Linux nested capture with two distinct shims":
  let work = createTempDir("io-mon-nested-distinct-shims-", "")
  defer: removeDir(work)
  let shim = buildPrivateLinuxShim(repoRoot)
  createDir(work / "inner-shim")
  let second = work / "inner-shim" / "librepro_monitor_shim.so"
  copyLinuxShimAsDistinctImage(shim, second)

  for (order, transport) in [("inherited", "set"), ("inherited", "files"),
                             ("engine-route", "files")]:
    test order & " preload order, " & transport &
        " transport: one active shim":
      let nested = work / (order & "-" & transport)
      createDir(nested)
      writeFile(nested / "inner-input", "inner")
      writeFile(nested / "outer-input", "outer")
      # The monitors read the transport switch from the environment they
      # inherit.
      var env = newStringTable(modeCaseSensitive)
      for key, value in envPairs(): env[key] = value
      if transport == "files": env["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
      else: env.del("REPRO_MONITOR_DEP_SHM_DISABLE")
      let runner = startProcess(getAppFilename(), args = @["--outer", nested,
        shim, order, second], env = env, options = {poStdErrToStdOut})
      var code = runner.waitForExit(30_000)
      if code == -1:
        runner.kill()
        code = runner.waitForExit()
      let output = runner.outputStream.readAll()
      runner.close()
      checkpoint("exit=" & $code & " output=" & output)
      require code == 0

      let inner = readMonitorDepFile(nested / "inner.iomon")
      checkpoint("inner losses=" &
        $inner.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail))
      check inner.completeness == mcComplete
      check inner.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "inner-input")
      check inner.records.anyIt(it.kind == mrFileWrite and
        it.path == nested / "inner-output")
      # Two active shims in the reader would each record its start.
      let starts = inner.records.filterIt(it.kind == mrProcessStart)
      check starts.len == starts.mapIt(it.osPid).deduplicate.len
      # The shims are the monitor's own machinery, not the child's inputs.
      check not inner.records.anyIt(it.kind == mrLibraryLoad and
        it.path in [shim, second, expandFilename(shim), expandFilename(second)])

      let outer = readMonitorDepFile(nested / "outer.iomon")
      checkpoint("outer losses=" &
        $outer.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail))
      check outer.completeness == mcComplete
      check outer.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "outer-input")
      check outer.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "inner-input")
