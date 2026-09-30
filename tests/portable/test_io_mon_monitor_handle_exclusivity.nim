## test_io_mon_monitor_handle_exclusivity — IoMon-Decomposed-Host-API DH-2.
##
## `MonitorHandle` exclusively owns one live monitor: the consumer-owned
## `nim-shm-gset`, the fragment directory and the monitored process tree. Two
## owners of one consumer is the state that makes an LF-2 orphan reachable —
## one owner finishes, releasing the consumer and deleting the fragment
## directory, while the other still believes it has a monitor to poll and the
## producer is still running. DH-2 makes that state UNREPRESENTABLE rather than
## forbidden, by giving the type a `=copy` that is `{.error.}`.
##
## That is a COMPILE-TIME property, so it is pinned by driving the real
## compiler at real programs and reading the exit code — the only instrument
## that can see it.
##
## `compiles()` CANNOT: the `=copy` hook is injected AFTER semantic analysis
## (the destructor-injection pass), while `compiles()` answers from sem alone.
## Measured, not assumed — `static: doAssert not compiles((var a: T; var b = a;
## discard b; discard a.active))` was written first and FAILED with the
## `{.error.}` hook in place, i.e. it reported the copy as compiling. So an
## in-process `compiles()` assertion here would have been a test that cannot
## fail, and the check moved out of process, where the same copy really does
## stop the compiler with exit 1.
##
## NO MOCKS, and nothing stubbed: each case writes a real Nim program, runs the
## real compiler over the real `io_mon` module, and asserts on the real exit
## code and diagnostic. The negative cases must fail FOR THE STATED REASON (the
## diagnostic has to name `=copy`), so a typo in a probe cannot masquerade as
## the guarantee holding.
##
##   t_copying_a_handle_does_not_compile — the property itself.
##   t_copying_a_seq_of_handles_does_not_compile — the transitive propagation
##       that matters in practice: an N-way poll loop holds its monitors in a
##       `seq`, and a `seq` of a non-copyable element is non-copyable too.
##   t_copying_an_object_wrapping_a_handle_does_not_compile — the other way a
##       host would carry one (a scheduler's per-action record).
##   t_moving_a_handle_compiles — the positive control. Without it every case
##       above would also pass against a probe that failed to compile for some
##       unrelated reason, and against an `io_mon` that did not build at all.
##   t_the_poll_loop_shape_compiles — the second positive control, and the one
##       that matters to the caller: exclusivity must not cost the very shape
##       DH-2 exists to enable (`seq[MonitorHandle]`, `pollMonitor` on an
##       element, `finishMonitor(move(…))` out of it).

import std/[os, osproc, streams, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

  copyRefusalNeedle = "'=copy' is not available"
    ## The diagnostic Nim emits for a `{.error.}`-annotated `=copy`. Asserting
    ## on it is what distinguishes "the guarantee held" from "the probe was
    ## broken in some other way".

# --------------------------------------------------------------------------
# Helpers. Anything that ASSERTS is a `template` — `check` inside a plain
# `proc` prints "Check failed" and still labels the case `[OK]`. Helpers that
# merely DO something are procs and RAISE on failure.
# --------------------------------------------------------------------------

proc probeDir(): string =
  ## Probe programs live INSIDE the repo so the compiler resolves this repo's
  ## `config.nims` the same way the rest of the suite does; the explicit
  ## `--path` switches below make the resolution independent of that anyway.
  result = repoRoot / "build" / "dh2-handle-probes"
  createDir(result)

proc siblingPath(envName, relative: string): string =
  ## Mirror `config.nims`' own resolution: the sibling checkout by default, an
  ## explicit override when the environment supplies one (a Nix flake input
  ## builds from a read-only store path).
  let override = getEnv(envName)
  if override.len > 0: override else: repoRoot / relative

proc compileProbe(name, source: string): tuple[output: string; code: int] =
  ## Write `source` as a probe program and COMPILE it (never run it). Returns
  ## the merged compiler output and its exit status.
  let dir = probeDir()
  let path = dir / (name & ".nim")
  writeFile(path, source)
  let args = @[
    "c",
    "--hints:off",
    "--warnings:off",
    "--compileOnly",
    # ONE nimcache for every probe: they all compile the same `io_mon`, and a
    # per-probe cache would recompile the whole module five times. Probe
    # projects have distinct names, so their artefacts do not collide.
    "--nimcache:" & (dir / "cache"),
    "--path:" & (repoRoot / "src"),
    "--path:" & siblingPath("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src"),
    "--path:" & siblingPath("SHM_QUEUE_SRC", "../nim-shm-queue/src"),
    "--path:" & siblingPath("SHM_GSET_SRC", "../nim-shm-gset/src"),
    path
  ]
  let p = startProcess(getEnv("NIM", "nim"), workingDir = repoRoot, args = args,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

template checkRefusedAsUncopyable(name, source: string) =
  ## The probe must FAIL, and fail because the copy was refused.
  let (output, code) = compileProbe(name, source)
  checkpoint(name & ": exit " & $code & "\n" & output)
  check code != 0
  check copyRefusalNeedle in output

template checkCompiles(name, source: string) =
  let (output, code) = compileProbe(name, source)
  checkpoint(name & ": exit " & $code & "\n" & output)
  check code == 0

suite "io-mon MonitorHandle exclusivity (DH-2)":

  test "t_copying_a_handle_does_not_compile":
    # `a` is read AFTER `b` is bound, so the compiler cannot turn the
    # assignment into a move. That detail is load-bearing: with only
    # `var b = a` and no later use of `a`, Nim's last-read analysis moves
    # instead of copying and the probe compiles even with the hook in place.
    checkRefusedAsUncopyable("dh2_copy_direct", """
import io_mon

proc probe() =
  var a: MonitorHandle
  var b = a
  doAssert b.live == a.live

probe()
""")

  test "t_copying_a_seq_of_handles_does_not_compile":
    checkRefusedAsUncopyable("dh2_copy_seq", """
import io_mon

proc probe() =
  var s: seq[MonitorHandle] = @[]
  var t = s
  doAssert t.len == s.len

probe()
""")

  test "t_copying_an_object_wrapping_a_handle_does_not_compile":
    checkRefusedAsUncopyable("dh2_copy_wrapper", """
import io_mon

type
  ScheduledAction = object
    name: string
    handle: MonitorHandle

proc probe() =
  var a = ScheduledAction(name: "action")
  var b = a
  doAssert b.name == a.name

probe()
""")

  test "t_moving_a_handle_compiles":
    checkCompiles("dh2_move_ok", """
import io_mon

proc probe() =
  var a: MonitorHandle
  var b = move(a)
  doAssert not b.live
  doAssert not a.live

probe()
""")

  test "t_the_poll_loop_shape_compiles":
    checkCompiles("dh2_poll_loop_shape", """
import io_mon

proc drive(handles: var seq[MonitorHandle]): seq[MonitorResult] =
  ## The shape a build engine's scheduler holds: N monitors in one container,
  ## polled in one loop, each consumed by `finishMonitor` as it completes.
  result = @[]
  var remaining = handles.len
  while remaining > 0:
    for i in 0 ..< handles.len:
      if handles[i].live and pollMonitor(handles[i]):
        result.add finishMonitor(move(handles[i]))
        dec remaining

proc probe() =
  var handles: seq[MonitorHandle] = @[]
  if handles.len > 0:
    discard drive(handles)

probe()
""")
