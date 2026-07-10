## test_io_mon_shim_fd_path_concurrency — FUP-H regression test (Linux).
##
## Guards the Linux LD_PRELOAD shim's fd -> path tracking table against
## cross-thread ORC heap corruption (a sibling of the FUP-C anonymous-mmap
## table bug, at a different site).
##
## ROOT CAUSE (see io-mon/src/io_mon/shim/linux_pod_tables.nim): the shim's
## ``fdPaths`` map used to be a process-global ``Table[cint, string]`` (and
## ``dirPaths`` / ``streamPaths`` / the observed-input dedup set / the
## empty-fd + inherited-fd sets were process-global ``Table`` / ``HashSet``
## values too). ``updateFdPath`` / ``removeFdPath`` run from EVERY host
## thread's ``open`` / ``close`` hook. Under ``--mm:orc`` the ``Table``
## backing seq and the ``string`` payloads live in the thread-local
## ``MemRegion`` of whichever thread first allocated them, but a ``Table``
## rehash / ``string`` ``=sink`` from a DIFFERENT thread frees a chunk in
## the wrong region and corrupts its free-list — even though ``fdLock``
## serialises access, because the lock does not change which region owns the
## chunk (the shared-heap lock is compiled out under ``gcDestructors``).
##
## This crashed live-Vulkan replay under the monitor: Mesa's
## ``VkLayer_MESA_device_select`` opens ``/sys`` PCI files concurrently
## while the executor runs, so a SIGSEGV surfaced in ``rawDealloc`` off
## ``updateFdPath`` -> ``Table.[]=`` -> ``string`` ``=sink`` (confirmed by
## gdb on ``test_feedback_loop_vk``: 6/6 SIGSEGV pre-fix, 0/6 post-fix).
##
## The FUP-H fix moves those tables to ``linux_pod_tables``: fixed-capacity
## POD storage whose variable-length path payloads use libc ``malloc`` /
## ``free`` (which IS safe for cross-thread free), so no Nim GC heap is
## touched on the mutation path.
##
## The reproducer is an ORC + threads Nim program whose workers churn the
## shim's fd->path table cross-thread: each iteration opens a long,
## unique-path descriptor plus a ``/dev/null`` descriptor, then drops BOTH
## via ``close_range`` — a close variant the shim does NOT hook, so the
## table entries go stale and the reused fd numbers get their (cross-thread)
## string payloads freed on the next thread's ``open`` overwrite. With the
## fragment writer active (``REPRO_MONITOR_FRAGMENT_DIR`` set) the extra
## record-building heap churn makes the cross-thread free reliably fatal on
## the OLD shim within a few child runs; on the fixed shim it is stable.

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
  # The fragment writer must be active: its per-record heap churn is what
  # makes the cross-thread fd->path free reliably fatal on the old shim.
  result["REPRO_MONITOR_FRAGMENT_DIR"] = fragDir
  result["REPRO_MONITOR_SESSION"] = "fd-path-concurrency-run"

const reproducerNim = """
import std/[os, posix]

proc c_syscall(n: clong): clong
  {.importc: "syscall", varargs, header: "<unistd.h>".}

const
  SYS_close_range = 436   # x86_64
  Threads = 8
  Iters = 40000

proc worker(idx: int) {.thread.} =
  # Long, unique paths -> large heap string payloads. Each iteration
  # registers a fresh fd; close_range drops it WITHOUT the shim's close hook
  # so the table entry goes stale and the reused fd number's (cross-thread)
  # string is freed on the next open's overwrite ``=sink``.
  let pad = "/some/deliberately/long/nonexistent/path/segment/to/force/" &
    "large/heap/string/allocations/for/the/fd/path/table/entry/"
  for i in 0 ..< Iters:
    let path = pad & $idx & "_" & $i
    let fd = open(path.cstring, O_RDONLY, 0.Mode)
    let rfd = open(cstring("/dev/null"), O_RDONLY, 0.Mode)
    if rfd >= 0:
      discard c_syscall(SYS_close_range, cuint(rfd), cuint(rfd), cint(0))
    if fd >= 0:
      discard c_syscall(SYS_close_range, cuint(fd), cuint(fd), cint(0))

proc main() =
  var rl: RLimit
  if getrlimit(RLIMIT_NOFILE, rl) == 0:
    rl.rlim_cur = rl.rlim_max
    discard setrlimit(RLIMIT_NOFILE, rl)
  for batch in 0 ..< 4:
    var th: array[Threads, Thread[int]]
    for i in 0 ..< Threads:
      createThread(th[i], worker, i)
    joinThreads(th)

main()
"""

suite "io-mon shim fd->path table cross-thread safety (FUP-H)":
  let work = getTempDir() / ("io-mon-fd-path-" & $getCurrentProcessId())
  createDir(work)

  test "t_shim_fd_path_concurrency_no_segv":
    let shimLib = ensureShim()
    let child = buildNim(work, "fd_path_child", reproducerNim)

    const iterations = 12
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
      removeDir(fragDir)   # bound disk use to a single run's fragments

    check crashes == 0
    check firstBadCode == 0
