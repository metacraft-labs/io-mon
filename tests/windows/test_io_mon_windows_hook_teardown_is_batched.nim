## Tearing down the hook table must cost a BOUNDED number of thread freezes.
##
## Why this is a test and not a comment.
##
## Every monitored process installs the shim's 31-entry inline-detour table and
## restores it from an `addExitProc` handler before its code pages go away.
## `ct_inline_hook_uninstall` freezes the process's other threads around each
## patch, and that freeze is a `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` --
## a SYSTEM-WIDE thread enumeration whose cost is set by the load of the whole
## machine rather than by how many threads the caller has. On the host this was
## measured on it is ~23.5 ms.
##
## The teardown used to call it once per hook. That is ~0.73 s of pure freeze
## in EVERY monitored process, paid at exit, doing no observation whatsoever.
## Since a build is overwhelmingly short-lived compiler processes, that single
## loop was the dominant cost of monitoring: a monitored `nim c` of one trivial
## file took 8.9 s against 1.1 s unmonitored, and batching the teardown took it
## to 2.0 s. `installAllHooks` had always grouped its patches into one
## transaction for exactly this reason; teardown simply never got the same
## treatment, and nothing failed when it did not.
##
## A wall-clock budget would be the obvious test and the wrong one -- it would
## flake on a loaded runner and would say nothing about WHY. The property that
## actually matters is structural and exact: the number of freeze rounds a
## teardown performs is O(1) in the number of hooks. `inlineHookSuspendRoundCount`
## exposes the round counter so that can be asserted directly.
##
## The first test is the control. An assertion that "N teardowns cost one
## round" is worthless unless the counter can also be shown to move once per
## round when the batching is absent -- otherwise a counter stuck at 1 would
## pass.
##
## Cheapness is only half of it, and the less important half. A teardown that
## restored NOTHING would be cheaper still, and would leave a JMP into the
## shim's code pages after they are unmapped. So both teardown tests also
## CALL every target -- before patching, while patched, and after teardown --
## and require the answers to come back to their pre-patch values. That is an
## observation of the machine. The teardown's own restore count is not: a
## mutation that begins and commits an empty transaction, restores nothing,
## and returns the target count satisfies `restored == installed` and the
## one-round bound, and it passed every assertion in this file until the
## call-based checks were added.

when not defined(windows):
  {.error: "windows-only test".}

import std/unittest

import io_mon/shim/windows_interpose
import stackable_hooks/inline_hook/windows_inline_hook

# Hook targets defined in C rather than in Nim on purpose. The installer has to
# decode and relocate at least five bytes of the target's prologue, so a target
# whose whole body the optimiser can fold into `lea eax,[rdi+rdi]; ret` is not
# reliably patchable. The `volatile` array forces a stack frame -- and hence a
# multi-byte prologue -- at every optimisation level, and `noinline` keeps the
# symbols addressable.
{.emit: """
#define S4_TEARDOWN_TARGET(N)                                   \
  __attribute__((noinline)) int io_mon_s4_teardown_target_##N(   \
      int a, int b) {                                            \
    volatile int slots[4];                                       \
    slots[0] = a + N; slots[1] = b - N;                          \
    slots[2] = a * (N + 1); slots[3] = b + a;                    \
    return slots[0] + slots[1] + slots[2] + slots[3];            \
  }
S4_TEARDOWN_TARGET(0)
S4_TEARDOWN_TARGET(1)
S4_TEARDOWN_TARGET(2)
S4_TEARDOWN_TARGET(3)
S4_TEARDOWN_TARGET(4)
S4_TEARDOWN_TARGET(5)

/* One shared detour body. The test CALLS the targets -- before installing,
 * while patched, and after teardown -- because that is the only way to
 * observe that a restore actually happened. Asking the teardown how many
 * restores it performed would just be reading its own claim back; a
 * teardown that queued nothing and returned the target count would satisfy
 * that, and would leave every detour in place. `a ^ b` is chosen so the
 * patched answer cannot collide with any target's real one. */
int io_mon_s4_teardown_detour(int a, int b) { return a ^ b; }
""".}

proc target0(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_0", cdecl.}
proc target1(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_1", cdecl.}
proc target2(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_2", cdecl.}
proc target3(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_3", cdecl.}
proc target4(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_4", cdecl.}
proc target5(a, b: cint): cint {.importc: "io_mon_s4_teardown_target_5", cdecl.}
proc detour(a, b: cint): cint {.importc: "io_mon_s4_teardown_detour", cdecl.}

type TargetProc = proc (a, b: cint): cint {.cdecl.}

proc allTargets(): seq[pointer] =
  @[cast[pointer](target0), cast[pointer](target1), cast[pointer](target2),
    cast[pointer](target3), cast[pointer](target4), cast[pointer](target5)]

proc allProcs(): seq[TargetProc] =
  ## The same six entry points, callable. Kept in the same order as
  ## `allTargets` so index i of one names index i of the other.
  @[TargetProc(target0), TargetProc(target1), TargetProc(target2),
    TargetProc(target3), TargetProc(target4), TargetProc(target5)]

const
  CallA = 3'i32
  CallB = 5'i32

proc callAll(procs: seq[TargetProc]): seq[cint] =
  ## What every target returns right now. Compared against a snapshot taken
  ## before any patching, this is a DIRECT observation of whether the
  ## original prologue bytes are back — the property the exit handler
  ## exists to guarantee, and the one a self-reported restore count cannot
  ## establish.
  for p in procs:
    result.add p(cint(CallA), cint(CallB))

proc allDetoured(procs: seq[TargetProc]): bool =
  ## True when EVERY target currently answers with the detour's body rather
  ## than its own. Used to prove the patches really landed before a teardown
  ## is asked to remove them.
  for v in callAll(procs):
    if v != cint(CallA xor CallB):
      return false
  true

proc installAll(targets: seq[pointer]): int =
  ## Install one detour per target, each in its own (unbatched) call, and
  ## return how many landed. Skipping a target that will not patch keeps the
  ## test honest on a host where a particular prologue is undecodable: the
  ## assertions below are expressed against the number ACTUALLY installed.
  var trampoline: pointer
  for t in targets:
    if inlineHookInstall(t, cast[pointer](detour), addr trampoline) == 0:
      inc result

suite "inline-hook teardown is batched":

  test "the freeze-round counter moves once per unbatched uninstall":
    # The control for the test below. Without this, a counter that never
    # moved would make the batching assertion vacuously true.
    let targets = allTargets()
    let procs = allProcs()
    let pristine = callAll(procs)
    let installed = installAll(targets)
    # Every target on this host, not "at least two": the restore assertions
    # below are only worth as much as the number of patches they cover, and a
    # silent drop to two would weaken them without failing anything.
    require installed == targets.len
    check allDetoured(procs)

    let before = inlineHookSuspendRoundCount()
    var restored = 0
    for t in targets:
      if inlineHookUninstall(t) == 0:
        inc restored
    let rounds = inlineHookSuspendRoundCount() - before

    check restored == installed
    check callAll(procs) == pristine
    # One system-wide thread snapshot per call, batching absent. Uninstalling
    # a target that was never patched still takes the freeze before it
    # discovers there is nothing to restore, so the count is per CALL.
    check rounds == culong(targets.len)

  test "the batched teardown costs ONE freeze round for the whole table":
    # This is the regression assertion. Reverting `uninstallInlineHooksBatched`
    # to a per-hook loop makes `rounds` equal the target count and fails here,
    # without any dependence on how long a round takes.
    let targets = allTargets()
    let procs = allProcs()
    let pristine = callAll(procs)
    let installed = installAll(targets)
    require installed == targets.len
    # The patches are really in: without this the restore check below could
    # be satisfied by an install pass that quietly did nothing.
    check allDetoured(procs)

    let before = inlineHookSuspendRoundCount()
    let restored = uninstallInlineHooksBatched(targets)
    let rounds = inlineHookSuspendRoundCount() - before

    # Every patch is still restored -- the batching changes WHEN the threads
    # are frozen, not WHICH detours come out. Losing a restore would leave a
    # JMP into the shim's code pages after they are unmapped, which is the
    # access violation the exit handler exists to prevent.
    #
    # The load-bearing assertion is the CALL, not the count. `restored` is
    # the teardown's own report; a batched teardown that queued nothing and
    # returned the target count satisfies `restored == installed` and one
    # freeze round while leaving all six detours live -- that exact mutation
    # was written and it passed until this line existed. Calling the targets
    # observes the machine instead of the claim.
    check restored == installed
    check callAll(procs) == pristine
    check rounds == 1'u32

  test "an empty teardown freezes nothing at all":
    # The exit handler runs in processes whose install pass landed no inline
    # hooks (every entry fell through to the IAT fallback). Those must not pay
    # a system-wide thread snapshot to discover they have nothing to do.
    let before = inlineHookSuspendRoundCount()
    check uninstallInlineHooksBatched([]) == 0
    check inlineHookSuspendRoundCount() == before

  test "the transaction capacity is published, not guessed":
    # `uninstallInlineHooksBatched` falls back to the per-hook path above the
    # queue's capacity rather than letting the queue reject ops and silently
    # leave detours installed. That bound is read from the C side; if it ever
    # came back as 0 the batch path would never be taken and the regression
    # would be back with every test still green.
    check inlineHookTransactionCapacity() > 0
    check inlineHookTransactionCapacity() >= 32
