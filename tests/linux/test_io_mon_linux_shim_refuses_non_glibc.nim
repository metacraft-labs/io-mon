## The Linux shim must refuse to compile against a libc other than glibc.
##
## WHY. The shim finds the real `dlsym` with glibc's `dlvsym(RTLD_NEXT,
## "dlsym", <base version>)`, which does not pass through the shim's own
## exported `dlsym`. Until io-mon carried this test, a non-glibc build took an
## `#else` branch that resolved it with `ct_resolve("dlsym")` instead, which is
## `dlsym(RTLD_NEXT, "dlsym")`. The shim's own calls bind to its own exports,
## so that call reached the shim's `dlsym`, whose entry stub calls back into
## the resolver while the real pointer is unpublished: unbounded recursion
## (io-mon issue 2026-11-08-linux-shim-on-a-non-glibc-libc-recurses-resolving-
## the-real-dlsym). Nothing builds or tests the shim against another libc, so
## the contract (docs/contributors/architecture.md, "glibc only") is that the
## shim refuses one, with its own message, before any other diagnostic.
## Measured before the fix at io-mon 17d97cea5: a musl compile of the hook
## runtime's translation unit failed only by accident, on `unknown type name
## 'off64_t'`, so its refusal depended on whichever glibc-only spelling the
## compiler met first. (The shim's other C translation unit, the private heap
## `src/io_mon/shim/linux_private_heap.c`, has refused a non-glibc libc with
## its own `#error` since 6453936f3; this test covers the runtime's.)
##
## HOW. No mocks. Generate the shim's C exactly as `scripts/build_shim.sh`
## does (`nim c --app:lib --compileOnly` into a private nimcache), take the
## runtime's own C file and the compile command Nim recorded for it, and run
## that command twice:
##   * with the host's glibc compiler (the positive control: the same file and
##     flags compile, so the musl failure below is about the libc and not
##     about the command);
##   * with a real musl-targeting `gcc` (nixpkgs `pkgsCross` musl, from the dev
##     shell's `IO_MON_TEST_MUSL_CC` or the recipe's `io-mon-test-musl-cc`):
##     it must fail, and the FIRST error must be the shim's glibc-only refusal.
## It also checks that the resolver of the real `dlsym` has no route through
## `ct_resolve`, the call that recursed.
##
## The musl compiler (a glibc-hosted cross gcc that targets musl) is required
## on x86_64-linux and aarch64-linux, where the flake provides it (a missing
## value FAILS the test there), and the test skips on other systems, where it
## is not provisioned.

import foreign_preload_isolation

import std/[json, os, osproc, streams, strtabs, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  muslApplicable = defined(linux) and (defined(amd64) or defined(arm64))
  refusal = "io-mon: the Linux shim supports glibc only"

proc siblingPath(envName, relative: string): string =
  let override = getEnv(envName)
  if override.len > 0: override else: repoRoot / relative

proc run(exe: string, args: seq[string], env: StringTableRef = nil): (string, int) =
  let p = startProcess(exe, workingDir = repoRoot, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "the Linux shim refuses a libc other than glibc":
  test "a musl compile of the shim runtime stops on the glibc-only refusal":
    let muslCc = getEnv("IO_MON_TEST_MUSL_CC", findExe("io-mon-test-musl-cc"))
    when not muslApplicable:
      checkpoint("skipped: no musl compiler is provisioned on this system")
      skip()
    else:
      checkpoint("IO_MON_TEST_MUSL_CC=" & muslCc)
      require muslCc.len > 0
      require fileExists(muslCc)

      let dir = repoRoot / "build" / "non-glibc-refusal-probe"
      removeDir(dir); createDir(dir)
      let cache = dir / "cache"
      let (genOutput, genCode) = run(getEnv("NIM", "nim"), @["c", "--hints:off",
        "--warnings:off", "--compileOnly", "--app:lib", "--threads:on",
        "-d:useMalloc", "--nimcache:" & cache,
        # GCC-dialect flags (`-fmax-errors`, not clang's `-ferror-limit`), so
        # the recorded command is valid for the musl gcc too.
        "--cc:gcc",
        "--path:" & (repoRoot / "src"),
        "--path:" & siblingPath("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src"),
        "--path:" & siblingPath("SHM_QUEUE_SRC", "../nim-shm-queue/src"),
        "--path:" & siblingPath("SHM_GSET_SRC", "../nim-shm-gset/src"),
        repoRoot / "src" / "io_mon" / "shim" / "linux_preload.nim"])
      checkpoint(genOutput)
      require genCode == 0

      # The runtime's C file is the one that DEFINES the real-dlsym resolver
      # (generated file names are mangled).
      var runtimeC = ""
      for path in walkFiles(cache / "*.nim.c"):
        if "static ct_dlsym_real_fn ct_real_dlsym_fn(void) {" in readFile(path):
          runtimeC = path
          break
      checkpoint("runtime C: " & runtimeC)
      require runtimeC.len > 0

      # The resolver must not reach the real dlsym through ct_resolve.
      let source = readFile(runtimeC)
      let start = source.find("static ct_dlsym_real_fn ct_real_dlsym_fn(void) {")
      let body = source[start ..< source.find("\n}\n", start)]
      checkpoint(body)
      check "ct_resolve(" notin body
      check "dlvsym(RTLD_NEXT, \"dlsym\"" in body

      # The command Nim recorded for that file: [compiler, args...]. Replace
      # the object path so the two runs below do not race on one file.
      # Nim names the build's JSON after the output (`lib<module>.json` for
      # --app:lib); exactly one is written into this private cache.
      var jsonPath = ""
      for path in walkFiles(cache / "*.json"): jsonPath = path
      require jsonPath.len > 0
      let recorded = parseFile(jsonPath)
      var command: seq[string]
      for entry in recorded["compile"]:
        if entry[0].getStr() == runtimeC:
          command = parseCmdLine(entry[1].getStr())
      checkpoint("recorded command: " & command.join(" "))
      require command.len > 1
      let oIndex = command.find("-o")
      require oIndex > 0 and oIndex + 1 < command.len

      proc compileWith(cc, objName: string, env: StringTableRef): (string, int) =
        var args = command[1 .. ^1]
        args[oIndex] = dir / objName
        run(cc, args, env)

      # Positive control: the host's glibc compiler builds the same file
      # with the same flags.
      let (glibcOutput, glibcCode) = compileWith(command[0], "glibc.o", nil)
      checkpoint("glibc compile:\n" & glibcOutput)
      check glibcCode == 0
      check refusal notin glibcOutput

      let (muslOutput, muslCode) = compileWith(muslCc, "musl.o", nil)
      checkpoint("musl compile:\n" & muslOutput)
      check muslCode != 0
      var firstError = ""
      for line in muslOutput.splitLines():
        if "error:" in line:
          firstError = line
          break
      checkpoint("first error: " & firstError)
      check refusal in firstError
      check not fileExists(dir / "musl.o")
