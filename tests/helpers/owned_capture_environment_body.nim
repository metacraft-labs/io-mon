## Actual owned-env C helpers are compiled from the complete candidate runtime,
## not reimplemented. This finite component checks borrowed entry preservation
## and returning cleanup; genuine callback-chain and full IO gates stay pending.
import std/[os, strutils, unittest]
import io_mon/hooks/linux_preload_runtime

proc value(env: cstringArray; name: string): string =
  var index = 0
  while env[index] != nil:
    let text = $env[index]
    if text.startsWith(name & "="):
      return text[(name.len + 1)..^1]
    inc index

let names = ["REPRO_MONITOR_FRAGMENT_DIR", "REPRO_MONITOR_SESSION",
  "REPRO_MONITOR_SHIM_LIB", "REPRO_MONITOR_INTEREST",
  "REPRO_MONITOR_EVIDENCE", "REPRO_MONITOR_DEP_SHM"]
let values = ["relative-original-route", "actual-session-1", "/actual/shim.so",
  "read", "full", "/actual/segment.shard0"]
for index, name in names:
  putEnv(name, values[index])
setPreloadShimEnvVar("REPRO_MONITOR_SHIM_LIB")
var original = [cstring("PATH=/actual/fixture/bin"), cstring(nil)]
let originalPointer = cast[cstringArray](addr original[0])

suite "actual owned environment helpers":
  test "missing child route copies actual parent values and frees only owned entries":
    for iteration in 0..<1000:
      let prepared = envWithPreload(originalPointer)
      check prepared != originalPointer
      for index, name in names:
        check value(prepared, name) == values[index]
      check value(prepared, "PATH") == "/actual/fixture/bin"
      freeOwnedEnv(prepared, originalPointer)
      check $original[0] == "PATH=/actual/fixture/bin"
  test "actual exec generation composes route and retains borrowed input":
    let prepared = envWithExecGen(originalPointer, 7)
    check value(prepared, "REPRO_MONITOR_EXEC_GEN") == "7"
    for index, name in names:
      check value(prepared, name) == values[index]
    freeOwnedEnv(prepared, originalPointer)
    check $original[0] == "PATH=/actual/fixture/bin"
  test "already-loaded shim still receives missing route controls":
    var child = [cstring("LD_PRELOAD=/actual/shim.so"), cstring(nil)]
    let childPointer = cast[cstringArray](addr child[0])
    let prepared = envWithPreload(childPointer)
    check prepared != childPointer
    check value(prepared, "LD_PRELOAD") == "/actual/shim.so"
    check value(prepared, names[0]) == values[0]
    freeOwnedEnv(prepared, childPointer)
    check $child[0] == "LD_PRELOAD=/actual/shim.so"
  test "borrowed unchanged result is never interpreted as owned header":
    setPreloadShimEnvVar("")
    let unchanged = envWithPreload(originalPointer)
    check unchanged == originalPointer
    freeOwnedEnv(unchanged, originalPointer)
    check $original[0] == "PATH=/actual/fixture/bin"
