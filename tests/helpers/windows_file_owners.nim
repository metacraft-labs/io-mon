## Diagnostic only: ask the real Windows Restart Manager which processes use
## an image that a fixture could not delete. No mocks, shutdown or restart calls.
## https://learn.microsoft.com/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist
when defined(windows):
  import std/[os, strutils, widestrs]

  type
    DiagRmProcess = object
      pid: uint32
      startLow, startHigh: uint32
    DiagRmInfo = object
      process: DiagRmProcess
      appName: array[256, uint16]
      serviceName: array[64, uint16]
      appType, status, session: uint32
      restartable: int32

  static: doAssert sizeof(DiagRmInfo) == 668

  proc diagRmStart(session: ptr uint32; flags: uint32; key: ptr uint16): uint32
    {.stdcall, dynlib: "rstrtmgr", importc: "RmStartSession".}
  proc diagRmRegister(session, count: uint32; files: ptr pointer;
      appCount: uint32; apps: pointer; serviceCount: uint32;
      services: pointer): uint32
    {.stdcall, dynlib: "rstrtmgr", importc: "RmRegisterResources".}
  proc diagRmList(session: uint32; needed, count: ptr uint32;
      apps: ptr DiagRmInfo; reboot: ptr uint32): uint32
    {.stdcall, dynlib: "rstrtmgr", importc: "RmGetList".}
  proc diagRmEnd(session: uint32): uint32
    {.stdcall, dynlib: "rstrtmgr", importc: "RmEndSession".}
  proc diagOpenProcess(access: uint32; inherit: int32; pid: uint32): pointer
    {.stdcall, dynlib: "kernel32", importc: "OpenProcess".}
  proc diagQueryImage(process: pointer; flags: uint32; name: ptr uint16;
      length: ptr uint32): int32
    {.stdcall, dynlib: "kernel32", importc: "QueryFullProcessImageNameW".}
  proc diagCloseHandle(handle: pointer): int32
    {.stdcall, dynlib: "kernel32", importc: "CloseHandle".}

  proc diagAttributes(path: WideCString): uint32
    {.stdcall, dynlib: "kernel32", importc: "GetFileAttributesW".}

  proc diagOwnerImage(pid: uint32): string =
    let handle = diagOpenProcess(0x1000, 0, pid)
    if handle == nil: return "<unavailable>"
    defer: discard diagCloseHandle(handle)
    var buffer: array[32768, uint16]
    var size = uint32(buffer.len)
    if diagQueryImage(handle, 0, addr buffer[0], addr size) != 0:
      result = $cast[WideCString](addr buffer[0])

  proc diagOwners(path: string): seq[uint32] =
    let attributes = diagAttributes(newWideCString(path))
    echo "DIAGNOSTIC attributes path=", path, " value=", attributes,
      " readonly=", (attributes and 1) != 0
    var session: uint32
    var key: array[33, uint16]
    let started = diagRmStart(addr session, 0, addr key[0])
    if started != 0:
      raise newException(OSError, "RmStartSession: " & $started)
    defer: discard diagRmEnd(session)
    let wide = newWideCString(path)
    var filePointer = cast[pointer](unsafeAddr wide[0])
    let registered = diagRmRegister(session, 1, addr filePointer, 0, nil, 0, nil)
    if registered != 0:
      raise newException(OSError, "RmRegisterResources: " & $registered)
    var needed, count, reboot: uint32
    var code = diagRmList(session, addr needed, addr count, nil, addr reboot)
    var owners: seq[DiagRmInfo]
    for attempt in 0 ..< 4:
      if code != 234: break
      if needed > 4096: raise newException(OSError, "Implausible owner count")
      owners.setLen(int(needed))
      count = needed
      code = diagRmList(session, addr needed, addr count,
        (if owners.len == 0: nil else: addr owners[0]), addr reboot)
    echo "DIAGNOSTIC owners path=", path, " query=", code,
      " count=", count, " reboot=", reboot
    if code != 0: raise newException(OSError, "RmGetList: " & $code)
    for i in 0 ..< int(count):
      let owner = owners[i]
      result.add(owner.process.pid)
      echo "DIAGNOSTIC owner pid=", owner.process.pid,
        " image=", diagOwnerImage(owner.process.pid), " start=",
        owner.process.startHigh, ":", owner.process.startLow,
        " type=", owner.appType, " status=", owner.status

  proc diagnosticCleanupOwners*(root: string) =
    # Positive control: this executable is mapped into this live process.
    let ownOwners = diagOwners(getAppFilename())
    let controlValid = uint32(getCurrentProcessId()) in ownOwners
    echo "DIAGNOSTIC owner-query-control pid=", getCurrentProcessId(),
      " valid=", controlValid
    if not controlValid:
      raise newException(OSError, "Restart Manager missed this running image")
    var count = 0
    for path in walkDirRec(root):
      if path.toLowerAscii.endsWith(".exe") or
          path.toLowerAscii.endsWith(".bin") or path.toLowerAscii.endsWith(".dll"):
        discard diagOwners(path)
        inc count
        if count >= 32: break
    echo "DIAGNOSTIC cleanup image count=", count
