## test_io_mon_windows_child_env_block — the child environment io-mon's Windows
## arm hands `runWithMonitorShim`, exercised on a POSIX development host.
##
## WHY THIS LIVES IN `portable/` DESPITE BEING ABOUT WINDOWS
## ---------------------------------------------------------
## `stackable_hooks/windows_env_block` is deliberately NOT gated behind
## `when defined(windows)` (see its own header): the `lpEnvironment` encoding is
## pure string / UTF-16 work with no Win32 call in it, so it can be compiled,
## EXECUTED and mutation-checked on Linux or macOS. This file takes that offer.
## `tests/windows/` is selected only on a Windows host, so anything placed there
## is compile-checked at best from this workspace; everything below actually
## RUNS on every host the suite runs on.
##
## WHAT IT PINS
## ------------
## IoMon-Decomposed-Host-API DH-1's Windows residual. `runMonitored`'s Windows
## arm no longer `putEnv`s its four injection variables into the HOSTING
## process: it composes the child's COMPLETE environment with `childEnv` — the
## same proc, and therefore the same layering rule, the two POSIX arms use — and
## passes it to `runWithMonitorShim`, whose `env` parameter (nim-stackable-hooks
## 6a53408) turns it into an explicit `CreateProcessW` environment block.
##
## The composition starts from `envPairs()`, and on Windows `envPairs()` yields a
## shape that block encoder REJECTS. Windows keeps HIDDEN variables whose name
## begins with `=` — the per-drive current directories (`=C:=C:\some\dir`), the
## shell's `=ExitCode=00000000`, and `=::=::\`. Nim's `envPairs` reads
## `GetEnvironmentStringsW` directly and splits each entry on the FIRST `=`,
## which for these is at index 0, so it reports an EMPTY name and folds the real
## name into the value. `encodeWindowsEnvironmentBlock` raises `ValueError` on an
## empty name (it would frame as a leading `=VALUE` entry) and
## `runWithMonitorShim` converts that to an `OSError` — so, unrepaired, a host
## launched from `cmd.exe`, where these entries are normal and inherited, could
## not spawn a monitored child AT ALL.
##
## `fs_snoop.windowsHiddenEnvEntry` reverses the split. Both directions are
## asserted below: a test that only shows the REPAIRED pair encoding cleanly
## cannot tell "the repair works" from "there was nothing to repair", so the
## unrepaired pair is asserted to raise.

import std/unittest
import stackable_hooks/windows_env_block

include io_mon/fs_snoop

proc envPairsSplit(entry: string): (string, string) =
  ## Exactly what `std/envvars.envPairsImpl` does on Windows: find the FIRST
  ## `=` and split there (`substr(kv, 0, p-1)` / `substr(kv, p+1)`). Kept here
  ## rather than called, because that code only compiles on a Windows host —
  ## this is the one behaviour of it that matters to `childEnv`.
  let p = entry.find('=')
  (entry[0 ..< p], entry[p + 1 .. ^1])

proc decodeEnvBlock(blk: seq[uint16]): seq[string] =
  ## The child's own view of an `lpEnvironment` block: split the UTF-16 run on
  ## its per-entry NULs and stop at the empty entry that closes the block.
  ## ASCII-only, which every name and every value used below is.
  result = @[]
  var cur = ""
  for unit in blk:
    if unit == 0'u16:
      if cur.len == 0:
        break
      result.add cur
      cur = ""
    else:
      cur.add chr(int(unit) and 0xFF)

suite "io-mon Windows child environment block (DH-1 Windows residual)":
  test "envPairs' empty-named entries rejoin to their real `=`-prefixed names":
    # The three hidden shapes a real Windows process carries. In each case the
    # value below is what `envPairs` hands `childEnv` after its index-0 split.
    check windowsHiddenEnvEntry(r"C:=C:\some\dir") == ("=C:", r"C:\some\dir")
    check windowsHiddenEnvEntry("ExitCode=00000000") == ("=ExitCode", "00000000")
    check windowsHiddenEnvEntry(r"::=::\") == ("=::", r"::\")

  test "an empty-named entry with no `=` at all is dropped, not guessed":
    # Not a well-formed Win32 entry; there is no faithful repair, and emitting
    # a name of `=` with the whole text as its value would invent a variable.
    check windowsHiddenEnvEntry("no-equals-here") == ("", "")

  test "a hidden `=DRIVE` entry survives the CreateProcessW encoder unchanged":
    const raw = r"=C:=C:\some\dir"
    let (nimName, nimValue) = envPairsSplit(raw)
    # What `childEnv` actually receives from `envPairs()` on Windows.
    check nimName == ""
    check nimValue == r"C:=C:\some\dir"

    # UNREPAIRED — the encoder refuses rather than emitting a block the child
    # would silently mis-frame. This is the `OSError` every Windows
    # `runMonitored` would raise if `childEnv` passed `envPairs()` through as
    # it stands. `newStringTable` + the `StringTableRef` overload is the exact
    # pair of calls `runWithMonitorShim` makes on `childEnv`'s result.
    var unrepaired = newStringTable(modeCaseInsensitive)
    unrepaired[nimName] = nimValue
    expect ValueError:
      discard encodeWindowsEnvironmentBlock(unrepaired)

    # REPAIRED — encodes, and the entry the child parses out is the ORIGINAL
    # Win32 text, byte for byte.
    let (fixedName, fixedValue) = windowsHiddenEnvEntry(nimValue)
    check fixedName == "=C:"
    check fixedValue == r"C:\some\dir"
    var repaired = newStringTable(modeCaseInsensitive)
    repaired[fixedName] = fixedValue
    repaired["REPRO_MONITOR_SESSION"] = "run-1"
    let entries = decodeEnvBlock(encodeWindowsEnvironmentBlock(repaired))
    check entries.len == 2
    check raw in entries
    check "REPRO_MONITOR_SESSION=run-1" in entries

  # ---------------------------------------------------------------------
  # The two cases below were ADDED during verification, because mutation
  # showed the three above did not hold the lines they appeared to.
  # ---------------------------------------------------------------------

  test "the rejoin splits on the FIRST `=`, so an `=` in the VALUE survives":
    # MUTATION THAT FOUND THIS: `value.find('=')` → `value.rfind('=')` passed
    # every case above, because each of their values contains exactly one `=`
    # and first == last. First-vs-last is therefore unpinned by them, and it is
    # not a distinction without a difference: a per-drive current directory may
    # legally sit in a directory whose name contains `=`.
    #
    # Splitting on the last one folds the extra `=` into the NAME, and an `=`
    # past index 0 in a name is precisely what `encodeWindowsEnvironmentBlock`
    # rejects — so the wrong split turns a REPAIRABLE entry back into the
    # `OSError` this repair exists to prevent. Both halves are asserted.
    const raw = r"=C:=C:\a=b\dir"
    let (nimName, nimValue) = envPairsSplit(raw)
    check nimName == ""
    check nimValue == r"C:=C:\a=b\dir"

    let (fixedName, fixedValue) = windowsHiddenEnvEntry(nimValue)
    check fixedName == "=C:"
    check fixedValue == r"C:\a=b\dir"

    # …and the repaired pair really does encode, where a last-`=` split
    # (name `=C:=C:\a`) would not.
    var repaired = newStringTable(modeCaseInsensitive)
    repaired[fixedName] = fixedValue
    check decodeEnvBlock(encodeWindowsEnvironmentBlock(repaired)) == @[raw]

    var lastSplit = newStringTable(modeCaseInsensitive)
    lastSplit["=C:=C:\\a"] = "b\\dir"
    expect ValueError:
      discard encodeWindowsEnvironmentBlock(lastSplit)

  test "childEnv's host-environment composition applies the rejoin":
    # MUTATION THAT FOUND THIS: unwiring `windowsHiddenEnvEntry` from the
    # composition — putting `envPairs`' empty name straight into the table —
    # reddened NOTHING, and `nim check --os:windows` stayed green too. The
    # helper was proven; its USE was not.
    #
    # It cannot be reached through `childEnv` itself from here: `envPairs()` on
    # a POSIX host never yields an empty name, and no `putEnv` can create one.
    # `addHostEnvEntry` is the per-entry seam `childEnv` loops over, so calling
    # it directly exercises the branch that only Windows reaches at runtime.
    var composed = newStringTable(modeCaseInsensitive)
    addHostEnvEntry(composed, "", r"C:=C:\some\dir")
    addHostEnvEntry(composed, "", "ExitCode=00000000")
    addHostEnvEntry(composed, "PATH", r"C:\Windows\System32")
    # The ordinary entry is passed through untouched…
    check composed["PATH"] == r"C:\Windows\System32"
    # …the hidden ones are rejoined to their real names…
    check composed["=C:"] == r"C:\some\dir"
    check composed["=ExitCode"] == "00000000"
    # …and no empty name survives, which is the property that decides whether
    # `runWithMonitorShim` can spawn at all.
    check not composed.hasKey("")
    check encodeWindowsEnvironmentBlock(composed).len > 0

    # An entry that is not a well-formed Win32 pair is dropped, not invented.
    var dropped = newStringTable(modeCaseInsensitive)
    addHostEnvEntry(dropped, "", "no-equals-here")
    check dropped.len == 0
