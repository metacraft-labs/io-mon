## test_io_mon_child_env_layering — the two rules `FsSnoopRequest.env` exists to
## obey, exercised on every host the suite runs on.
##
## Both readers of that field are covered here: `fs_snoop.childEnv`, which
## composes the child's whole environment (suite 1), and
## `fs_snoop.requestEnvValue`, which resolves the pre-injection value of a
## single variable so `injectionValue` can EXTEND a caller's preload rather than
## replace it (suite 2). They were unpinned for one and the same reason — see
## below — so closing only the first would have left half the field dead.
##
## WHY THIS FILE EXISTS
## --------------------
## IoMon-Decomposed-Host-API DH-1 gave `FsSnoopRequest` a per-call `env` and
## routed all three arms' injection variables through ONE composition helper,
## `fs_snoop.childEnv`. The stated reason for one helper rather than three is a
## CORRECTNESS rule, not tidiness: the child's environment is the hosting
## process's, then the caller's `request.env`, then io-mon's own injection — and
## io-mon's injection WINS, so a caller cannot point `REPRO_MONITOR_SHIM_LIB`
## somewhere else and silently turn monitoring off.
##
## FOUND BY MUTATION, DURING VERIFICATION OF THE WINDOWS ARM. Swapping the
## `request.env` and `injected` loops inside `childEnv` — inverting exactly that
## rule, so a caller's value beats io-mon's — reddened NOTHING in the full
## 237-case suite, and `nim check` stayed green for `--os:linux`, `--os:macosx`
## AND `--os:windows`. The reason is blunt: no test in io-mon set
## `FsSnoopRequest.env` at all, so the loop the rule is about iterated an empty
## seq everywhere and the swap was a runtime no-op. The field DH-1 added, and
## the rule its shared helper exists for, were unpinned on all three arms at
## once — the composition was verified to be SINGLE, never verified to be RIGHT.
##
## That diagnosis is exhaustive, not a sample: the only `FsSnoopRequest`
## constructions anywhere under `tests/` that set `env` are the ones in this
## file. `tests/linux/test_io_mon_per_call_env_and_cwd.nim` does not, despite its
## name — it pins `cwd` and the fact that the HOST's environment is not mutated,
## which is a different property from what the per-call `env` does once set.
##
## COVERAGE, PRECISELY — read this before quoting the file as proof of anything.
##
## `childEnv` has ONE body and all three arms call it, so suite 1 holds its
## layering rule for the source every arm compiles. `requestEnvValue` also has
## one body, but only the POSIX arms call it (`LD_PRELOAD` /
## `DYLD_INSERT_LIBRARIES`, `REPRO_MONITOR_DEP_SHM_DISABLE`,
## `REPRO_MONITOR_APP_ID`, `CT_SANDBOX_TOOLS_DIR`); the Windows arm composes its
## four injection variables without it. So suite 2 speaks for Linux and macOS
## and says nothing about Windows, because on Windows there is nothing to say.
##
## Two things these cases do NOT hold, both Windows-only:
##   * `childEnv`'s one platform-varying input is `ChildEnvMode`. Its BEHAVIOUR
##     is executed here — the case below passes `modeCaseInsensitive`
##     explicitly, with the case-sensitive contrast beside it — but WHICH arm
##     selects it is compile-time evidence only, pinned by the `static:
##     doAssert` below so that at least a cross-`--os:` check can see it.
##   * These cases drive the helpers directly. That each arm actually PASSES the
##     composed table to its own spawn is held end-to-end on Linux and macOS and
##     is compile-checked only on Windows — deleting `env = spawnEnv` from the
##     Windows spawn leaves `nim check --os:windows` green, which is the honest
##     limit of what this workspace can check.
##
## See the milestone's COVERAGE STATUS for the same split stated once for the
## whole change.
##
## `childEnv` is deliberately unexported, so this file `include`s the module
## rather than importing it — the same approach
## `test_io_mon_windows_child_env_block.nim` takes. Portable on purpose: the
## helper is shared by all three arms, so the rule is host-independent and
## belongs wherever the suite runs, not behind a `when defined(...)` that fires
## on one machine.
##
## No mocks: this drives the real `childEnv` against the real process
## environment.

import std/[strtabs, unittest]

include io_mon/fs_snoop

# WHICH arm selects which discipline — the one thing about `ChildEnvMode` that
# no amount of running on this host can show, asserted where a CROSS-`--os:`
# check can see it instead. `static:` is evaluated during semantic analysis, so
# `nim check --os:windows` reddens on a flipped `ChildEnvMode` even though no
# Windows code is ever run here; `nim check --os:linux` / `--os:macosx` cover
# the POSIX arm. Without this the const is invisible to every tool available in
# this workspace, which is exactly how it went unpinned in the first place.
when defined(windows):
  static: doAssert ChildEnvMode == modeCaseInsensitive
else:
  static: doAssert ChildEnvMode == modeCaseSensitive

suite "io-mon child-environment layering (DH-1 childEnv)":
  test "host env, then request.env, then io-mon's injection — injection WINS":
    # A host entry the caller does not mention must survive into the child.
    # Read out of the live environment rather than `putEnv`'d, so this test
    # mutates nothing process-global — which is the property DH-1 is about.
    var hostKey, hostValue: string
    for key, value in envPairs():
      if key.len > 0 and key != "PATH" and not key.startsWith("REPRO_MONITOR_"):
        hostKey = key
        hostValue = value
        break
    require hostKey.len > 0

    let request = FsSnoopRequest(env: @[
      ("PATH", "/caller/supplied/path"),
      ("REPRO_MONITOR_SHIM_LIB", "/caller/attempt/to/disarm.so")])
    let composed = childEnv(request, @[
      ("REPRO_MONITOR_SHIM_LIB", "/io-mon/real/shim.so"),
      ("REPRO_MONITOR_SESSION", "run-1")])

    # 1. the hosting process's environment is carried through …
    check composed[hostKey] == hostValue
    # 2. … `request.env` layers on top of it …
    check composed["PATH"] == "/caller/supplied/path"
    # 3. … and io-mon's injection layers on top of THAT. This is the assertion
    #    the mutation above inverts, and the whole reason one shared `childEnv`
    #    is worth having: a caller must not be able to redirect the shim, and a
    #    caller who names the same variable must lose.
    check composed["REPRO_MONITOR_SHIM_LIB"] == "/io-mon/real/shim.so"
    check composed["REPRO_MONITOR_SESSION"] == "run-1"

  test "a later request.env entry beats an earlier one (last wins)":
    # `docs/usage.md` promises callers that duplicates in `env` resolve
    # last-wins. Unpinned until now, for the same reason as the rule above:
    # nothing anywhere set `request.env`.
    var noInjection: seq[(string, string)] = @[]
    let request = FsSnoopRequest(env: @[
      ("IO_MON_LAYERING_PROBE", "first"),
      ("IO_MON_LAYERING_PROBE", "last")])
    check childEnv(request, noInjection)["IO_MON_LAYERING_PROBE"] == "last"

  test "under WINDOWS' case-insensitive discipline the injection still wins":
    # FOUND BY MUTATION TOO, and the same shape as the swap above: flipping
    # `ChildEnvMode`'s Windows arm to `modeCaseSensitive` reddened NOTHING —
    # the `when` is not compiled on a POSIX host, and `nim check --os:windows`
    # cannot see it because both mode names type-check. `docs/usage.md`
    # nonetheless promises the behaviour, so it is asserted here by passing the
    # mode explicitly rather than waiting for a Windows host.
    #
    # What it buys is not cosmetic. Under a case-SENSITIVE table a caller could
    # spell the variable in a different case and have BOTH survive into the
    # child's environment block; which one a Windows child then resolved would
    # be up to the OS, and io-mon's injection could lose. Case-insensitive
    # matching is what makes "injection wins" survive a caller who does not
    # spell the name the way io-mon does.
    let request = FsSnoopRequest(env: @[
      ("repro_monitor_shim_lib", "/caller/attempt/to/disarm.so"),
      ("path", "/caller/supplied/path")])
    let composed = childEnv(request, @[
      ("REPRO_MONITOR_SHIM_LIB", "/io-mon/real/shim.so")],
      mode = modeCaseInsensitive)
    # One variable, not two — and it is io-mon's value.
    check composed["REPRO_MONITOR_SHIM_LIB"] == "/io-mon/real/shim.so"
    check composed["repro_monitor_shim_lib"] == "/io-mon/real/shim.so"
    # …and a differently-cased caller entry overrides the inherited host one
    # rather than joining the table beside it, which is the `Path`/`PATH` claim
    # `docs/usage.md` makes.
    check composed["PATH"] == "/caller/supplied/path"

    # The contrast, so this case cannot pass for the wrong reason: under the
    # POSIX discipline the two spellings really are different variables, and the
    # caller's lower-case one survives untouched. If `newStringTable(mode)`
    # ignored `mode`, one of these two blocks would have to fail.
    let posix = childEnv(request, @[
      ("REPRO_MONITOR_SHIM_LIB", "/io-mon/real/shim.so")],
      mode = modeCaseSensitive)
    check posix["REPRO_MONITOR_SHIM_LIB"] == "/io-mon/real/shim.so"
    check posix["repro_monitor_shim_lib"] == "/caller/attempt/to/disarm.so"

  test "composing a child environment leaves the host's untouched":
    # DH-1's headline property, asserted against the composition helper itself
    # rather than only end-to-end through a spawn: a variable that exists ONLY
    # in `request.env` reaches the child's table and never the host's.
    const probe = "IO_MON_LAYERING_HOST_UNTOUCHED"
    check not existsEnv(probe)
    let request = FsSnoopRequest(env: @[(probe, "child-only")])
    let composed = childEnv(request, @[("REPRO_MONITOR_SESSION", "run-2")])
    check composed[probe] == "child-only"
    check not existsEnv(probe)

suite "io-mon per-call preload extension (DH-1 requestEnvValue/injectionValue)":
  # FOUND BY THE SAME MUTATION SWEEP AS THE SUITE ABOVE, and inert for the same
  # single reason: no test in io-mon constructed an `FsSnoopRequest` with an
  # `env` field, so EVERY read of `request.env` was a read of an empty seq.
  # `childEnv` was one such reader; `requestEnvValue` is the other, and closing
  # only the first would have left half the field unpinned.
  #
  # What rests on it: `runMonitored` computes the child's preload variable as
  # `injectionValue(shimLib, requestEnvValue(request, "LD_PRELOAD"))` on Linux
  # and the `DYLD_INSERT_LIBRARIES` equivalent on macOS, and resolves
  # `REPRO_MONITOR_DEP_SHM_DISABLE`, `REPRO_MONITOR_APP_ID` and
  # `CT_SANDBOX_TOOLS_DIR` the same way. `docs/usage.md` and `types.nim`'s
  # `env*` both promise a caller that a per-call preload is EXTENDED rather than
  # discarded; that promise lived only in prose until these cases.
  #
  # Both procs are unexported, so this file `include`s the module (see above).

  test "request.env supplies the pre-injection value, and the LAST entry wins":
    # `requestEnvValue` scans with `countdown`, which is the whole of "last
    # wins". A `countup` scan passes a single-entry request and fails here.
    let request = FsSnoopRequest(env: @[
      ("LD_PRELOAD", "/caller/first.so"),
      ("LD_PRELOAD", "/caller/last.so")])
    check requestEnvValue(request, "LD_PRELOAD") == "/caller/last.so"

  test "with no request.env entry the hosting process's value is used":
    # Read out of the live environment rather than `putEnv`'d: this suite must
    # not mutate the host, which is the property DH-1 is about.
    var hostKey, hostValue: string
    for key, value in envPairs():
      if key.len > 0 and value.len > 0 and not key.startsWith("REPRO_MONITOR_"):
        hostKey = key
        hostValue = value
        break
    require hostKey.len > 0
    var noOverride: seq[(string, string)] = @[]
    check requestEnvValue(FsSnoopRequest(env: noOverride), hostKey) == hostValue

  test "an absent name with no request.env entry is empty, not an error":
    const absent = "IO_MON_REQUEST_ENV_ABSENT_PROBE"
    check not existsEnv(absent)
    var noOverride: seq[(string, string)] = @[]
    check requestEnvValue(FsSnoopRequest(env: noOverride), absent) == ""

  test "a caller-supplied preload is EXTENDED by the shim, never discarded":
    # The composition `runMonitored` actually performs. If `injectionValue`
    # returned the shim alone — or if `requestEnvValue` ignored `request.env` —
    # the caller's preload would vanish from the child with no diagnostic, which
    # is precisely what the `injectionValue` docstring says cannot happen.
    let request = FsSnoopRequest(env: @[("LD_PRELOAD", "/caller/theirs.so")])
    let composed = injectionValue("/io-mon/shim.so",
                                  requestEnvValue(request, "LD_PRELOAD"))
    check composed == "/io-mon/shim.so" & $PathSep & "/caller/theirs.so"
    # Order is load-bearing, not cosmetic: the shim must come FIRST so its
    # interposers are ahead of the caller's in the preload chain.
    check composed.startsWith("/io-mon/shim.so")

  test "with nothing to extend the preload is the shim alone, with no separator":
    # A trailing/leading `PathSep` here would make the child's loader try to
    # load the empty path.
    check injectionValue("/io-mon/shim.so", "") == "/io-mon/shim.so"
