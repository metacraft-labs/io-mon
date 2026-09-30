## Fixture DLL for ``tests/windows/test_io_mon_windows_spawn_abandoned_injection.nim``.
##
## Loading it is SLOW: its module initialiser, which the Nim runtime runs
## from ``DllMain(DLL_PROCESS_ATTACH)`` and therefore inside the child's
## ``LoadLibraryW``, sleeps for ``IO_MON_TEST_SLOW_LOAD_MS``
## milliseconds. That makes the borrowed ``LoadLibraryW`` a real, slow call
## in a real child, which is the situation an I/O-starved build host
## produced by accident: a healthy child whose injection takes longer than
## the injector used to be willing to wait.
##
## The value is read from the CHILD's environment, which it inherits from
## the test, so each test case picks its own delay.
##
## Win32 is called directly rather than through ``std/os`` so that the
## fixture does as little as possible under the loader lock.

when not defined(windows):
  {.error: "slow_load_lib is a Windows fixture".}

proc GetEnvironmentVariableW(name: ptr uint16; buf: ptr uint16;
                             size: uint32): uint32
  {.importc, stdcall, dynlib: "kernel32".}
proc Sleep(ms: uint32) {.importc, stdcall, dynlib: "kernel32".}

proc slowLoadMs(): uint32 =
  const name = "IO_MON_TEST_SLOW_LOAD_MS"
  var nameW: array[name.len + 1, uint16]
  for i, c in name:
    nameW[i] = uint16(c)
  var buf: array[32, uint16]
  let n = GetEnvironmentVariableW(addr nameW[0], addr buf[0],
    uint32(buf.len))
  if n == 0 or n >= uint32(buf.len):
    return 0
  for i in 0 ..< int(n):
    let d = buf[i]
    if d < uint16('0') or d > uint16('9'):
      return 0
    result = result * 10 + uint32(d - uint16('0'))

let delay = slowLoadMs()
if delay > 0:
  Sleep(delay)

proc slow_load_lib_marker(): int32 {.exportc, dynlib, stdcall.} =
  ## Present so the image has an export table like a real shim's; unused.
  42
