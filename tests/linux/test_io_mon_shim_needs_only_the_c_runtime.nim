## Linux: every compile of the shim needs only the C runtime.
##
## The shim is LD_PRELOADed into programs built elsewhere, so each DT_NEEDED
## entry it carries is a library every monitored program must be able to
## load. It uses `libc.so.6` and the loader and nothing else, but Nim adds
## `-lm -lrt -ldl` and `-pthread` to every Linux link, so without
## `--as-needed` AHEAD of those flags the shim also needs `libm.so.6`,
## `librt.so.1`, `libdl.so.2` and `libpthread.so.0`. Those resolve through
## the loading program's search path, and a program's DT_RUNPATH applies only
## to its own direct dependencies, never to a preloaded object's (ld.so(8),
## https://man7.org/linux/man-pages/man8/ld.so.8.html). A program that finds
## its own glibc through its DT_RUNPATH -- what current linkers emit, and
## what a toolchain relocated into a store keeps -- therefore dies before
## main under such a shim:
##
##   ar: error while loading shared libraries: libm.so.6: cannot open shared
##     object file: No such file or directory
##
## THE DEFECT. Only `scripts/build_shim.sh` put `--as-needed` there (through
## `--gcc.linkTmpl` / `--clang.linkTmpl`, which a `--passL` cannot replace: it
## lands after Nim's `-l` flags). A consumer that compiles
## `linux_preload.nim` itself -- Reprobuild's own shim edge does -- linked all
## four satellites in (reprobuild-pm issue 2026-11-14, "the engine-built
## Linux shim needs unused C-runtime satellites"). The settings now live in
## `src/io_mon/shim/linux_preload.nim.cfg`, which every compile of that file
## reads.
##
## The cases: the builder's shim; a plain `nim c` of the shim source with
## only the flags its source requires (what any consumer passes), once per
## compiler family found on PATH; and the polarity control, the same plain
## compile with Nim's default link template restored on the command line,
## which must bring the satellites back. Without it a toolchain that never
## adds them would make the plain case pass over a missing setting.
##
## NO MOCKS: the real compiler, linker, builder and `readelf`.

import foreign_preload_isolation

import std/[os, osproc, sets, streams, strutils, tempfiles, unittest]

import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  ShimSource = "src/io_mon/shim/linux_preload.nim"
  VersionScript = "src/io_mon/hooks/linux_preload_versions.map"
  NimDefaultLinkTmpl = "$buildgui $builddll -o $exefile $objfiles $options"
    ## Nim's own `linkTmpl` for gcc and clang (compiler/extccomp.nim), i.e.
    ## the template a compile gets when nothing overrides it.

proc siblingSrc(envName, sibling: string): string =
  ## A dependency's source directory, resolved as `scripts/build_shim.sh`
  ## resolves it: the environment override, else the workspace sibling.
  result = getEnv(envName)
  if result.len == 0:
    result = repoRoot.parentDir / sibling / "src"

proc neededOf(lib: string): seq[string] =
  ## The DT_NEEDED sonames of `lib`, in order. Asserts that `readelf` read
  ## the file, so an empty answer cannot mean "could not read".
  let (output, code) = execCmdEx("readelf -d -W " & quoteShell(lib))
  doAssert code == 0, output
  for line in output.splitLines:
    if "(NEEDED)" in line:
      let start = line.find('[')
      let stop = line.rfind(']')
      if start >= 0 and stop > start:
        result.add line[start + 1 ..< stop]
  doAssert "libc.so.6" in result, lib & " has no libc.so.6 NEEDED:\n" & output

proc unexpectedNeeds(needed: seq[string]): seq[string] =
  ## Every NEEDED entry that is neither `libc.so.6` nor the loader.
  for soname in needed:
    if soname != "libc.so.6" and not soname.startsWith("ld-linux"):
      result.add soname

proc onGlibc(): bool =
  execCmdEx("getconf GNU_LIBC_VERSION").exitCode == 0

proc plainCompile(work, cc: string; extra: openArray[string] = []):
    tuple[code: int; output, shim: string] =
  ## `nim c` of the shim source with the flags its own source requires and
  ## nothing from `scripts/build_shim.sh`'s link settings: what a consumer
  ## that compiles the shim itself passes.
  let outDir = work / cc
  createDir(outDir)
  result.shim = outDir / "librepro_monitor_shim.so"
  var args = @["c", "--hints:off", "--cc:" & cc, "-d:useMalloc",
    "--app:lib", "--threads:on",
    "--path:src",
    "--path:" & siblingSrc("STACKABLE_HOOKS_SRC", "nim-stackable-hooks"),
    "--path:" & siblingSrc("SHM_QUEUE_SRC", "nim-shm-queue"),
    "--path:" & siblingSrc("SHM_GSET_SRC", "nim-shm-gset"),
    "--nimcache:" & (outDir / "nimcache"),
    "--out:" & result.shim]
  if onGlibc():
    args.add "-d:ioMonGlibcPrivateHeap"
    args.add "--passL:-Wl,--version-script=" & VersionScript
  for flag in extra: args.add flag
  args.add ShimSource
  let p = startProcess(findExe("nim"), workingDir = repoRoot, args = args,
    options = {poStdErrToStdOut})
  result.output = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()

suite "io-mon Linux shim needs only the C runtime":
  test "the builder's shim needs only libc and the loader":
    if findExe("readelf").len == 0:
      checkpoint("skipped: readelf is required to read the shim's dynamic section")
      skip()
    else:
      let needed = neededOf(buildPrivateLinuxShim(repoRoot))
      checkpoint("NEEDED: " & needed.join(" "))
      check unexpectedNeeds(needed).len == 0

  test "a plain compile of the shim source needs only libc and the loader":
    if findExe("readelf").len == 0 or findExe("nim").len == 0:
      checkpoint("skipped: readelf and nim are required")
      skip()
    else:
      let work = createTempDir("io-mon-shim-needed-", "")
      defer: removeDir(work)
      var compilers: seq[string]
      for cc in ["gcc", "clang"]:
        if findExe(cc).len > 0: compilers.add cc
      checkpoint("compilers: " & compilers.join(" "))
      require compilers.len > 0
      for cc in compilers:
        let built = plainCompile(work, cc)
        if built.code != 0:
          checkpoint(cc & " compile failed:\n" & built.output)
        check built.code == 0
        if built.code == 0:
          let needed = neededOf(built.shim)
          checkpoint(cc & " NEEDED: " & needed.join(" "))
          check unexpectedNeeds(needed).len == 0

      # POLARITY: the same compile with Nim's default link template restored
      # on the command line (which outranks the project configuration) must
      # bring the satellites back, or this toolchain never adds them and the
      # case above proved nothing about the configuration.
      let control = plainCompile(work / "control", compilers[0],
        ["--" & compilers[0] & ".linkTmpl:" & NimDefaultLinkTmpl])
      if control.code != 0:
        checkpoint("control compile failed:\n" & control.output)
      require control.code == 0
      let controlNeeded = neededOf(control.shim).toHashSet
      checkpoint("control NEEDED: " & $controlNeeded)
      # `libm` and `librt` specifically: a trailing `--passL:-Wl,--as-needed`
      # already drops `libdl` and `libpthread`, so only these two tell the
      # template apart from a flag placed after Nim's `-l` arguments.
      for soname in ["libm.so.6", "librt.so.1"]:
        check soname in controlNeeded
