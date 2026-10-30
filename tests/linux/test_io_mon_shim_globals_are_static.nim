## The shim's patch-status globals must be STATIC C initializers.
##
## WHY. `librepro_monitor_shim.so` installs its hooks from an ELF constructor
## (`repro_linux_monitor_constructor`). Nim initialises a module's globals in
## `NimMainInit` (`<module>_Init000`), which the generated C file runs AFTER
## that constructor. A global whose type is plain old data gets a static C
## initializer (`= {…}`) and is in place before any constructor runs; a global
## with a GC-managed field (`string`, `seq`, `ref`) cannot, and Nim assigns it
## at runtime in `Init000` -- wiping whatever the constructor stored.
##
## That happened at io-mon 7a3e4c89: `InlineSyscallPatchStatus` gained a
## `firstThumbPath: string`, so `inlineSyscallPatchStatus` was reset to its
## declared value after the constructor had installed the SIGTRAP/SIGILL
## handler and recorded the startup scan. `inlineSyscallPatchAttempted` (a
## bool, static) stayed true, so nothing re-ran the installer: the status read
## `handlerInstalled=false scan=invalid-argument`, every later dlopen/JIT scan
## was refused, and every process that loaded a library carried the loss
## `late inline raw-syscall scanner unavailable source=dlopen` -- on armhf AND
## x86-64 (`tests/linux/test_io_mon_linux_stdio_ipc.nim` failed 4 cases;
## `gcc && ./hello` on rpi2 graded mcIncomplete). The field is a `char` array
## now; this test keeps the whole set of constructor-owned globals POD.
##
## HOW. Compile the shim module exactly as `scripts/build_shim.sh` does (into a
## private nimcache, `--compileOnly`) and read the generated C of
## `linux_preload_runtime`: every listed global must be declared WITH an
## initializer on its declaration line, and the module's `Init000` body must
## not assign any of them. A new constructor-owned global is added to the list
## below when it is introduced.

import std/[os, osproc, re, streams, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  ## Globals the constructor writes and later code reads back. Nim mangles a
  ## module global as `<name>__<module-hash>_u<n>`, so each is matched as a
  ## prefix followed by `__`.
  constructorOwnedGlobals = [
    "inlineSyscallPatchStatus", "inlineSyscallPatchAttempted",
    "rawSyscallPatchStatus", "rawSyscallPatchAttempted"]

proc siblingPath(envName, relative: string): string =
  let override = getEnv(envName)
  if override.len > 0: override else: repoRoot / relative

suite "the shim's constructor-owned globals are static C initializers":
  test "no runtime init of the patch-status globals":
    let dir = repoRoot / "build" / "globals-static-probe"
    removeDir(dir); createDir(dir)
    let args = @["c", "--hints:off", "--warnings:off", "--compileOnly",
      "--app:lib", "--threads:on", "-d:useMalloc",
      "--nimcache:" & (dir / "cache"),
      "--path:" & (repoRoot / "src"),
      "--path:" & siblingPath("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src"),
      "--path:" & siblingPath("SHM_QUEUE_SRC", "../nim-shm-queue/src"),
      "--path:" & siblingPath("SHM_GSET_SRC", "../nim-shm-gset/src"),
      repoRoot / "src" / "io_mon" / "shim" / "linux_preload.nim"]
    let p = startProcess(getEnv("NIM", "nim"), workingDir = repoRoot, args = args,
      options = {poStdErrToStdOut, poUsePath})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(output)
    require code == 0
    # The generated file names are mangled; find the runtime's C as the file
    # that DECLARES the global (other modules only reference its type).
    # A module-global declaration is `N_LIB_PRIVATE <type> <name>__<hash>` then
    # ` = <init>;` or `;` (a function prototype has `N_NIMCALL(` / `N_CDECL(`).
    proc declPattern(name: string): Regex =
      re("^N_LIB_PRIVATE [A-Za-z0-9_]+ " & name & "__[A-Za-z0-9_]+( =|;)")
    var cPath = ""
    for path in walkFiles(dir / "cache" / "*.nim.c"):
      for line in readFile(path).splitLines():
        if line.match(declPattern("inlineSyscallPatchStatus")):
          cPath = path
          break
      if cPath.len > 0: break
    require cPath.len > 0
    let c = readFile(cPath)
    let lines = c.splitLines()
    for name in constructorOwnedGlobals:
      var declared = false
      for line in lines:
        # `N_LIB_PRIVATE <type> <name>__<hash> = {…};` or `= NIM_FALSE;`
        if line.match(declPattern(name)):
          checkpoint(name & ": " & line[0 ..< min(line.len, 160)])
          check " = " in line                       # STATIC initializer present
          declared = true
      check declared
    # The module's Init000 (NimMainInit) must not assign any of them.
    let initStart = c.find(re"[A-Za-z0-9_]+_Init000\)\(void\) \{")
    require initStart >= 0
    let initEnd = c.find("\n}", initStart)
    require initEnd > initStart
    let initBody = c[initStart ..< initEnd]
    for name in constructorOwnedGlobals:
      checkpoint("Init000 must not mention " & name)
      check (name & "__") notin initBody
