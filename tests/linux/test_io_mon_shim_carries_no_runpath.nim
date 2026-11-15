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
## A shell that is NOT a dev shell gives the link the same runpath by another
## route: the `ld` wrapper reads `NIX_DONT_SET_RPATH` only through its
## role-suffixed name, which add-flags.sh fills from the plain name only when
## a stdenv role variable (`NIX_BINTOOLS_WRAPPER_TARGET_HOST_<suffix>`) is
## set. A plain shell, and every `repro` action launched from one, sets none,
## so the wrapper added the C runtime's directory and the builder refused its
## own shim (reprobuild-pm issue
## 2026-11-15-io-mon-shim-build-from-a-plain-shell-gets-a-glibc-runpath-and-is-refused.md).
##
## NO MOCKS: the real builder, compiler, linker wrapper and `readelf`. The
## fabricated inputs are environments: `NIX_LDFLAGS="-rpath
## <work>/outputs/out/lib"`, the exact value a dev shell holds, and the
## plain-shell environment, which is this process's with the stdenv wrapper
## variables removed. Both are set explicitly so the cases do not depend on the
## shell they were started from.

import foreign_preload_isolation

import std/[os, osproc, strtabs, strutils, tempfiles, unittest]

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

proc nixLinkerWrapperSuffix(driver: string): string =
  ## The suffix of the nixpkgs linker wrapper `driver` (a compiler wrapper or
  ## the `ld` wrapper) runs, read from the guard its script names; "" when
  ## `driver` is not such a wrapper.
  const guard = "NIX_BINTOOLS_WRAPPER_FLAGS_SET_"
  let path = findExe(driver)
  if path.len == 0:
    return ""
  let text = try: readFile(path) except IOError: ""
  if not text.startsWith("#!"):
    return ""
  let at = text.find(guard)
  if at < 0:
    return ""
  var stop = at + guard.len
  while stop < text.len and text[stop] in IdentChars:
    inc stop
  text[at + guard.len ..< stop]

proc plainShellEnv(): StringTableRef =
  ## This process's environment as a shell that is not a dev shell has it:
  ## without the stdenv role variables (`NIX_BINTOOLS_WRAPPER_TARGET_*`,
  ## `NIX_CC_WRAPPER_TARGET_*`), the guards and settings a wrapper exports
  ## once it has run (`*_FLAGS_SET_*`, `NIX_DONT_SET_RPATH*`), and
  ## `NIX_LDFLAGS*`. Everything else, PATH included, is kept, so the build
  ## runs the same toolchain.
  result = newStringTable(modeCaseSensitive)
  for key, value in envPairs():
    if key.startsWith("NIX_BINTOOLS_WRAPPER_") or
        key.startsWith("NIX_CC_WRAPPER_") or
        key.startsWith("NIX_DONT_SET_RPATH") or
        key.startsWith("NIX_LDFLAGS"):
      continue
    result[key] = value

suite "io-mon Linux shim search path":
  test "a plain shell's linker wrapper does not give the shim a runpath":
    # The shim action links with `gcc` (repro.nim's backendCompiler).
    let suffix = nixLinkerWrapperSuffix("gcc")
    if findExe("readelf").len == 0:
      checkpoint("skipped: readelf is required to read the shim's dynamic section")
      skip()
    elif suffix.len == 0:
      checkpoint("skipped: gcc is not a nixpkgs compiler wrapper, so no " &
        "linker wrapper adds a runpath")
      skip()
    else:
      let env = plainShellEnv()
      checkpoint("linker wrapper suffix: " & suffix)
      # Positive control: in this environment the wrapper ignores the plain
      # NIX_DONT_SET_RPATH and adds the C runtime's directory to an ordinary
      # shared-library link. Without it, a passing shim check below would
      # prove nothing about the plain-shell condition.
      let work = createTempDir("io-mon-plain-shell-runpath-", "")
      defer: removeDir(work)
      writeFile(work / "control.c", "int io_mon_control(void) { return 0; }\n")
      var controlEnv = newStringTable(modeCaseSensitive)
      for key, value in env: controlEnv[key] = value
      controlEnv["NIX_DONT_SET_RPATH"] = "1"
      let control = execCmdEx("gcc -shared -fPIC -o " &
        quoteShell(work / "control.so") & " " & quoteShell(work / "control.c"),
        env = controlEnv)
      checkpoint(control.output)
      require control.exitCode == 0
      let controlRunpath = runpathOf(work / "control.so")
      checkpoint("control DT_RUNPATH: " & controlRunpath)
      require controlRunpath.len > 0

      var built = ""
      var refused = ""
      try:
        built = buildPrivateLinuxShimInEnv(repoRoot, env)
      except IOError as err:
        refused = err.msg
      checkpoint(refused)
      check refused.len == 0
      if built.len > 0:
        let section = execCmdEx("readelf -d -W " & quoteShell(built)).output
        check "(NEEDED)" in section
        check "libc.so.6" in section
        let runpath = runpathOf(built)
        if runpath.len > 0:
          checkpoint("DT_RUNPATH: " & runpath)
        check runpath.len == 0

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
