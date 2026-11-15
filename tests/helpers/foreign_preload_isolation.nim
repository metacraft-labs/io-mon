## Runs a Linux test process, and everything it starts, without an
## interposer that propagates itself into processes the test did not choose.
##
## Every test in `tests/linux/` and `tests/posix/` imports this module FIRST
## (`tests/portable/test_live_tests_isolate_foreign_preloads.nim` checks that).
## Module initialisation runs in import order, so the re-exec below happens
## before any other module of the test, or the test body, has done anything.
##
## WHY. io-mon's live tests are experiments on one interposer: the shim the
## test builds and selects. They compare evidence byte for byte across launch
## paths, count successful lookups, run a "bare" control without any shim,
## bound heap growth, and drive allocator-lock and loader-lock orderings that
## a second interposer changes. `unmonitored_env` already removes what an
## enclosing io-mon or Reprobuild monitor exports (`LD_PRELOAD`,
## `REPRO_MONITOR_*`). That is not enough for an interposer that puts itself
## back. Agent-harbor's command-trace shim (`libah_command_trace_shim.so`,
## loaded into every process of an agent session) does. Its stackable-hooks
## exec hooks add it to `LD_PRELOAD` again in every child, whatever
## environment the parent passed, unless the shim was told not to when it was
## initialised. The test then measures two interposers. Measured on
## nixos-ci-bare-001, io-mon `e774151`, agent-harbor-cli 0.6.17: eleven tests
## in seven files fail that way and pass once the shim is gone (reprobuild-pm
## issue 2026-11-15-linux-eleven-io-mon-tests-fail-on-the-agents-baseline):
##
##   * its `close` hook registers a thread-local destructor
##     (`__cxa_thread_atexit_impl`), which calls `calloc` and takes the
##     dynamic loader's lock. That re-enters the allocator host's lock even in
##     the shim-free control, and deadlocks a `connect` that runs while
##     another thread holds the loader lock in `dlopen`;
##   * its `connect` hook reads the address before the kernel does, so
##     a `connect` through an unreadable pointer dies with SIGSEGV instead of
##     failing with EFAULT;
##   * its exec hooks leave about 28 KiB behind in the parent of every exec
##     from a `vfork` child, which the vfork heap-growth bound catches;
##   * its own I/O (`/proc/<pid>` probes, connects to its trace socket) shows
##     up in io-mon's evidence and differs between launch paths.
##
## The first three are defects in that shim, recorded in agent-harbor-pm
## (`issues/2026-11-15-the-command-trace-shims-close-hook-allocates-and-takes-the-loader-lock-on-a-threads-first-close.md`,
## `...-connect-hook-crashes-on-an-address-the-kernel-would-reject-with-efault.md`,
## `...-the-command-trace-shim-grows-a-vfork-and-exec-loop-by-about-28-kib-per-exec.md`),
## and so is its coming back after `LD_PRELOAD` is unset
## (`issues/2026-11-14-the-command-trace-shim-comes-back-in-children-after-ld-preload-is-unset.md`).
## Isolation is still needed once they are fixed: a test started from an
## agent shell inherits the shim in its own `LD_PRELOAD`, and a second
## interposer's own I/O and memory are noise in an exact evidence comparison,
## so these experiments must run without one.
##
## HOW. Agent-harbor's shim decides at initialisation whether it propagates:
## it does not when `AH_CMDTRACE_DISABLE_AUTO_PROPAGATION` is set in its own
## environment (`compute_init_decisions`, agent-harbor
## `crates/ah-command-trace-shim/src/lib.rs`). A process that has it loaded
## cannot change that decision, so this module re-execs the test image:
##
##   1. The shim is mapped and propagating. Set the flag, drop the shim from
##      `LD_PRELOAD` and exec `/proc/self/exe` with the same argv. The old
##      image's exec hook puts the shim back into the new image's
##      `LD_PRELOAD`, but now with the flag set, so it no longer propagates.
##   2. The shim is mapped again, not propagating. Drop it from `LD_PRELOAD`
##      and exec once more. Nothing adds it back now.
##   3. The shim is not mapped. Continue with the test.
##
## Any other `LD_PRELOAD` entry is kept, so an enclosing Reprobuild monitor
## that `repro test` chose still sees the test. The hop counter bounds the
## loop: if the shim is still mapped after `MaxHops` re-execs, the test stops
## with a message rather than run as an experiment it was not designed to be.
##
## The test process is not under any monitor when this check runs, so it is
## a no-op outside agent sessions: nothing is mapped, nothing is re-executed.
##
## macOS: agent-harbor injects the shim with `DYLD_INSERT_LIBRARIES` there,
## and no failure of that kind has been observed or diagnosed, so the module
## does nothing on other operating systems.

{.used.}  # Imported for its initialisation; on other OSes it exports nothing.

when defined(linux):
  import std/[os, posix, strutils]

  const
    AgentHarborShimName* = "libah_command_trace_shim.so"
      ## File name of agent-harbor's command-trace shim, as it appears in
      ## `LD_PRELOAD` and in `/proc/self/maps`.
    AgentHarborDisablePropagationEnv* = "AH_CMDTRACE_DISABLE_AUTO_PROPAGATION"
      ## Agent-harbor's switch that keeps its shim out of the children of a
      ## process whose shim saw it set at initialisation.
    IsolationHopsEnv* = "IO_MON_TEST_FOREIGN_PRELOAD_HOPS"
      ## How many times this module has re-executed the test image so far.
    RemovedPreloadEnv = "IO_MON_TEST_FOREIGN_PRELOAD_REMOVED"
      ## Carries what was removed from `LD_PRELOAD` across the re-execs.
    MaxHops = 2
      ## Two re-execs are enough (see the module comment); a third would mean
      ## the shim is being loaded some other way.

  var removedForeignPreload*: string
    ## The agent-harbor shim path this module removed from the test process,
    ## or "" when the test was not started with it. A test can name it in a
    ## diagnostic, or run the real shim on purpose.

  proc isAgentHarborShim(path: string): bool =
    path.extractFilename == AgentHarborShimName

  proc agentHarborShimMapped*(): bool =
    ## True when agent-harbor's command-trace shim is mapped into this process.
    ## `/proc/self/maps` is the authority: `LD_PRELOAD` says what the loader
    ## was asked for, the map says what it loaded.
    let maps = try: readFile("/proc/self/maps") except IOError: ""
    for line in maps.splitLines():
      let slash = line.find('/')
      if slash >= 0 and isAgentHarborShim(line[slash .. ^1]):
        return true
    false

  proc withoutAgentHarborShim*(preload: string): string =
    ## `preload` (an `LD_PRELOAD` value) without the agent-harbor shim's
    ## entries. The loader accepts both spaces and colons as separators
    ## (ld.so(8)); the remaining entries are kept, joined with ':'.
    var kept: seq[string]
    for entry in preload.split({':', ' '}):
      if entry.len > 0 and not isAgentHarborShim(entry):
        kept.add entry
    kept.join(":")

  proc dropAgentHarborShimFromPreload() =
    let preload = getEnv("LD_PRELOAD")
    for entry in preload.split({':', ' '}):
      if entry.len > 0 and isAgentHarborShim(entry) and
          not existsEnv(RemovedPreloadEnv):
        putEnv(RemovedPreloadEnv, entry)
    let kept = withoutAgentHarborShim(preload)
    if kept.len == 0:
      delEnv("LD_PRELOAD")
    else:
      putEnv("LD_PRELOAD", kept)

  proc reexecWithoutForeignPreload() =
    let hops = try: parseInt(getEnv(IsolationHopsEnv, "0")) except ValueError: MaxHops
    if not agentHarborShimMapped():
      # Done (or never needed). The bookkeeping is ours; the test and its
      # children must not see it.
      dropAgentHarborShimFromPreload()
      removedForeignPreload = getEnv(RemovedPreloadEnv)
      delEnv(RemovedPreloadEnv)
      delEnv(IsolationHopsEnv)
      return
    if hops >= MaxHops:
      stderr.writeLine("foreign_preload_isolation: " & AgentHarborShimName &
        " is still mapped after " & $hops & " re-execs; this test cannot run " &
        "without it. Run the test outside the agent-harbor session, or with " &
        AgentHarborDisablePropagationEnv & "=1 and without the shim in " &
        "LD_PRELOAD.")
      quit(1)
    putEnv(AgentHarborDisablePropagationEnv, "1")
    putEnv(IsolationHopsEnv, $(hops + 1))
    dropAgentHarborShimFromPreload()
    # Same image, same argv: the unittest filters and arguments survive.
    var args = @[getAppFilename()]
    for i in 1 .. paramCount():
      args.add paramStr(i)
    let argv = allocCStringArray(args)
    discard execv("/proc/self/exe", argv)
    let err = osErrorMsg(osLastError())
    deallocCStringArray(argv)
    stderr.writeLine("foreign_preload_isolation: re-exec of " &
      getAppFilename() & " failed: " & err)
    quit(1)

  reexecWithoutForeignPreload()
