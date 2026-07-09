## test_io_mon_shim_thread_local_teardown — FUP-C regression test (Linux).
##
## Reproduces + guards the intermittent SIGSEGV in the Linux LD_PRELOAD shim's
## thread-local interception path (distinct from the fixed rmdir-rel32 SIGILL).
##
## ROOT CAUSE (see io-mon/src/io_mon/hooks/linux_preload_runtime.nim FUP-C
## comments): the shim's anonymous-mmap ownership table used to be a
## process-global ``seq[AnonymousExecutableRange]``. Under ``--mm:orc`` a
## global ``seq``'s backing buffer lives in the thread-local ``MemRegion`` of
## whichever thread first grew it, but ``recordAnonymousPrivateMmap`` /
## ``removeAnonymousPrivateRange`` run from EVERY host thread's ``mmap`` /
## ``munmap`` hook. ORC's ``reallocSharedImpl`` routes to the CALLING thread's
## region (the shared-heap lock is compiled out when ``gcDestructors`` is
## defined), so a ``seq`` realloc from a thread other than the buffer's owner
## frees a chunk in the wrong region and corrupts its free-list —
## intermittent SIGSEGV in ``rawDealloc`` / ``listRemove``.
##
## The reproducer is a C program that spawns many pthreads, each of which
## hammers ``malloc``/``free`` (forcing the process's own allocator to grow
## its heap via anonymous-private ``mmap`` — the exact call the shim's mmap
## hook records) and then exits, tearing down its TLS. Every worker's heap
## growth drives a concurrent ``repro_hook_mmap`` on the shim's shared table.
## On the OLD shim this SIGSEGVs within a handful of iterations; on the fixed
## shim (fixed-capacity POD table, no cross-thread allocation) it is stable.

import std/[os, osproc, streams, strtabs, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildNim(work, name, source: string): string =
  ## Build the reproducer child with the SAME memory model as the real
  ## trigger: ``--mm:orc --threads:on``. Under ORC each thread's Nim
  ## allocator grows its heap via anonymous-private ``mmap``; running many
  ## such threads concurrently drives dense, concurrent ``repro_hook_mmap``
  ## traffic on the shim's shared anonymous-range table — the exact race the
  ## FUP-C fix removes.
  result = work / name
  let sourcePath = work / (name & ".nim")
  writeFile(sourcePath, source)
  let built = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--mm:orc", "-d:release",
    "--threads:on", "-o:" & result, sourcePath])
  checkpoint(name & " nim c: " & built.output)
  check built.code == 0
  check fileExists(result)

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

proc childEnvWith(shimLib, fragDir: string): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib
  result["LD_PRELOAD"] = shimLib
  result["REPRO_MONITOR_FRAGMENT_DIR"] = fragDir
  result["REPRO_MONITOR_SESSION"] = "tls-teardown-run"

# The reproducer child — an ORC + threads Nim program. Each worker thread
# allocates + drops many heap objects (its Nim thread-local allocator grows
# via anonymous-private mmap, driving the shim's mmap hook), then exits,
# tearing down its TLS. Running several worker batches concurrently maximises
# the concurrent mmap-hook table traffic. On the OLD shim (global ``seq``
# ownership table) this SIGSEGVs within a handful of iterations; on the fixed
# shim (fixed-capacity POD table, no cross-thread allocation) it is stable.
const reproducerNim = """
type WorkerArg = tuple[idx: int]

proc worker(arg: WorkerArg) {.thread.} =
  # Heavy per-thread allocation so the ORC allocator repeatedly grows/shrinks
  # its thread-local heap via mmap/munmap while the shim's mmap hook records
  # each anonymous-private mapping on its shared table.
  var sink: seq[seq[int]] = @[]
  for i in 0 ..< 400:
    var s = newSeq[int](256 + (i mod 128))
    for j in 0 ..< s.len:
      s[j] = i * j
    sink.add s
    if sink.len > 32:
      sink.delete(0)

proc main() =
  const Threads = 8
  for batch in 0 ..< 6:
    var th: array[Threads, Thread[WorkerArg]]
    for i in 0 ..< Threads:
      createThread(th[i], worker, (idx: i))
    joinThreads(th)

main()
"""

suite "io-mon shim thread-local teardown (FUP-C)":
  let work = getTempDir() / ("io-mon-tls-teardown-" & $getCurrentProcessId())
  createDir(work)

  test "t_shim_thread_local_teardown_no_segv":
    let shimLib = ensureShim()
    let child = buildNim(work, "tls_teardown_child", reproducerNim)

    const iterations = 60
    var crashes = 0
    var firstBadCode = 0
    for it in 0 ..< iterations:
      let fragDir = work / ("frags-" & $it)
      createDir(fragDir)
      let env = childEnvWith(shimLib, fragDir)
      let cap = run(child, @[], env)
      if cap.code != 0:
        inc crashes
        if firstBadCode == 0:
          firstBadCode = cap.code
          checkpoint("iteration " & $it & " exited with code " & $cap.code &
            "\n" & cap.output)
      removeDir(fragDir)

    check crashes == 0
    check firstBadCode == 0
