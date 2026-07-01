## test_io_mon_macos_mmap_reentrancy — regression: the shim must not crash a
## monitored program by routing its mmaps through the Nim runtime.
##
## ROOT CAUSE (fixed): the `mmap` interpose thunk `repro_wrap_mmap` forwarded EVERY
## mmap through the Nim hook `repro_hook_mmap`, which touches the `inMmapHook`
## {.threadvar.} (a re-entrancy guard). `mmap` is issued from INSIDE the C allocator
## (libmalloc grows an arena via mmap WHILE HOLDING its arena lock). On macOS a
## threadvar / `__thread` in a dlopen'd dylib is a dyld TLV, and the FIRST access on a
## given thread calls tlv_get_addr → tlv_allocate_and_initialize_for_key → malloc — so
## a worker thread's first mmap re-enters libmalloc under its own lock → heap
## corruption → SIGSEGV. This is APPLICATION-level threadvar state, not compiler
## machinery: the crash survives --stackTrace:off, --exceptions:quirky,
## --tlsEmulation:off and -d:danger (all verified on the generated C). `rustc` (and
## `cmake` driving it) hit it DETERMINISTICALLY; a trivial `cc -c` and threaded
## malloc/mmap micro-benchmarks do NOT — the trigger is a mapping in rustc's Rust-std
## runtime. rustc's own SIGSEGV handler masks the fault (no crash report; it "works"
## under lldb), so the deterministic exit-code flip is the reliable oracle.
##
## FIX: `repro_wrap_mmap` decides from the mmap FLAGS ALONE (pure C, no threadvar,
## no allocation) whether a mapping could ever be recorded. Only a MAP_SHARED mapping
## with a real fd can carry a recordable fact (a MAP_SHARED|PROT_WRITE file
## content-write or a MAP_SHARED shm read — see recordMmap), and libmalloc never
## issues those; every other mapping forwards via the raw inline-asm syscall WITHOUT
## touching the Nim hook or its threadvar. All mmap recording behaviour is preserved
## (see the R9 / S1b tests); only the unsafe threadvar access on the hot path is
## removed.
##
## This test uses `rustc` because it is the only reliable reproducer (verified: 10/10
## crash pre-fix, 10/10 clean post-fix). It SKIPS cleanly when rustc is unavailable.
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]

when defined(macosx):
  import std/[osproc, streams, strtabs]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  rustcRuns = 5

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc findRustc(): string =
    let env = getEnv("RUSTC")
    if env.len > 0 and fileExists(env): return env
    findExe("rustc")

  proc shimEnv(shim, fragmentDir: string): StringTableRef =
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      result[k] = v
    result["DYLD_INSERT_LIBRARIES"] = shim
    result["REPRO_MONITOR_SHIM_LIB"] = shim
    result["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    result["REPRO_MONITOR_SESSION"] = "io-mon-mmap-reentrancy"

suite "io-mon macOS mmap reentrancy (rustc must not crash under the shim)":
  when defined(macosx):
    let rustc = findRustc()
    if rustc.len == 0 or not fileExists(rustc):
      test "rustc unavailable — mmap-reentrancy regression SKIPPED":
        checkpoint("rustc not found (set RUSTC=... to run); fix still built")
        check true
    else:
      let shim = buildShim()
      let work = getTempDir() / ("io-mon-mmap-reentry-" & $getCurrentProcessId())
      removeDir(work); createDir(work)
      let src = work / "probe.rs"
      writeFile(src, "fn main(){ println!(\"ok\"); }\n")

      test "rustc --emit=metadata does not crash under the shim (every run)":
        # Pre-fix this SIGSEGV'd (rc>128) deterministically while producing no
        # output; the fix keeps the mmap hot path out of the Nim runtime.
        var crashes = 0
        var produced = 0
        for i in 0 ..< rustcRuns:
          let fragmentDir = work / ("frags" & $i)
          createDir(fragmentDir)
          let outMeta = work / ("probe" & $i & ".rmeta")
          let p = startProcess(rustc,
            args = @["--emit=metadata", src, "-o", outMeta],
            env = shimEnv(shim, fragmentDir), options = {poStdErrToStdOut})
          let outText = p.outputStream.readAll()
          let code = p.waitForExit()
          p.close()
          if code > 128:
            inc crashes
            checkpoint("run " & $i & " CRASHED signal=" & $(code - 128) &
              " out=" & outText)
          if fileExists(outMeta): inc produced
        check crashes == 0
        check produced == rustcRuns

      removeDir(work)
  else:
    test "mmap reentrancy regression is macOS-only (no-op here)":
      check true
