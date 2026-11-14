## Linux: the built shim carries no DT_RUNPATH.
##
## The shim is LD_PRELOADed into programs built elsewhere, so its C-runtime
## dependencies must resolve through the program that loads it. glibc's loader
## consults the DT_RPATHs of the requesting object's loaders, the program
## included, only when the requesting object has no DT_RUNPATH (ld.so(8),
## https://man7.org/linux/man-pages/man8/ld.so.8.html; `_dl_map_object` in
## glibc's elf/dl-load.c). So any DT_RUNPATH on the shim, even one naming a
## directory that does not exist, makes a program that finds its own glibc
## through its DT_RPATH die before main:
##
##   ar: error while loading shared libraries: libm.so.6: cannot open shared
##     object file: No such file or directory
##
## A nixpkgs dev shell gives every link such a runpath: stdenv's setup puts
## `-rpath $out/lib` into NIX_LDFLAGS, with `$out` the nonexistent
## `<checkout>/outputs/out`, and the `ld` wrapper adds the C runtime's own
## directory. `scripts/build_shim.sh` removes both from its link and refuses
## to publish a shim that carries a runpath anyway.
##
## NO MOCKS: the real builder, compiler, linker wrapper and `readelf`. The one
## fabricated input is `NIX_LDFLAGS="-rpath <work>/outputs/out/lib"`, the exact
## value a dev shell holds, set explicitly so the case does not depend on the
## shell it was started from.

import std/[os, osproc, strutils, tempfiles, unittest]

import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc runpathOf(lib: string): string =
  ## The DT_RUNPATH value, or "" when the tag is absent. The caller also
  ## checks that `readelf` read the file, so "" cannot mean "could not read".
  let (output, code) = execCmdEx("readelf -d -W " & quoteShell(lib))
  doAssert code == 0, output
  for line in output.splitLines:
    if "(RUNPATH)" in line:
      let start = line.find('[')
      let stop = line.rfind(']')
      if start >= 0 and stop > start:
        return line[start + 1 ..< stop]

suite "io-mon Linux shim search path":
  test "a dev shell's NIX_LDFLAGS runpath does not reach the shim":
    if findExe("readelf").len == 0:
      checkpoint("skipped: readelf is required to read the shim's dynamic section")
      skip()
    else:
      let work = createTempDir("io-mon-shim-runpath-", "")
      defer: removeDir(work)
      let missing = work / "outputs" / "out" / "lib"
      let saved = getEnv("NIX_LDFLAGS")
      let hadSaved = existsEnv("NIX_LDFLAGS")
      putEnv("NIX_LDFLAGS", "-rpath " & missing)
      defer:
        if hadSaved: putEnv("NIX_LDFLAGS", saved)
        else: delEnv("NIX_LDFLAGS")
      let shim = buildPrivateLinuxShim(repoRoot)
      let section = execCmdEx("readelf -d -W " & quoteShell(shim)).output
      check "(NEEDED)" in section
      check "libc.so.6" in section
      let runpath = runpathOf(shim)
      if runpath.len > 0:
        checkpoint("DT_RUNPATH: " & runpath)
      check runpath.len == 0
      check missing notin section

  test "the builder refuses to publish a shim that carries a runpath":
    if findExe("readelf").len == 0:
      checkpoint("skipped: readelf is required to read the shim's dynamic section")
      skip()
    else:
      # A runpath the environment cannot remove: an explicit linker flag. The
      # builder must refuse it rather than publish.
      var refused = ""
      try:
        discard buildPrivateLinuxShimWithFlags(repoRoot,
          ["--passL:-Wl,-rpath,/nonexistent/io-mon-runpath-probe"])
      except IOError as err:
        refused = err.msg
      checkpoint(refused)
      check "DT_RUNPATH /nonexistent/io-mon-runpath-probe" in refused
