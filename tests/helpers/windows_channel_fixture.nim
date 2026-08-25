## Win32 channel exercises shared by the M5 live tests.
##
## The M5 capabilities -- IPC-connect, external content, non-determinism -- can
## only be tested by RUNNING a program that actually uses each channel under
## the monitor, because the defect class they close is "the call happened and
## nothing recorded it". A source-shape assertion cannot see that, and neither
## can a synthetic-fragment test: the writer is not where these records come
## from.
##
## Each mode returns 0 when the channel was genuinely exercised and a distinct
## non-zero code otherwise. That distinction is load-bearing. Without it a
## fixture that silently failed to open its pipe would produce a run with no
## IPC record, and a test asserting on records would call that a pass -- the
## same shape as the monitoring failure the whole milestone is about.
##
## All the Win32 entry points are declared `dynlib` rather than imported from
## `winlean` on purpose: that is the dispatch mechanism a real toolchain uses
## (a cached function pointer, not an IAT slot), so it exercises the inline
## detour at the function body rather than the IAT fallback. The calls are made
## from THIS module, which is linked into the fixture's main executable, so the
## shim's caller attribution sees them as the program's own.

when not defined(windows):
  {.error: "windows-only helper".}

import std/[os, strutils]

type
  H* = pointer
  DW* = uint32
  BL* = int32

proc BCryptGenRandom(hAlgorithm: H; pbBuffer: pointer; cbBuffer: DW;
                     dwFlags: DW): int32
  {.importc, stdcall, dynlib: "bcrypt".}
proc SystemFunction036(buf: pointer; len: DW): uint8
  {.importc, stdcall, dynlib: "advapi32".}
proc QueryPerformanceCounter(p: ptr int64): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetSystemTimeAsFileTime(p: pointer)
  {.importc, stdcall, dynlib: "kernel32".}
proc GetTickCount64(): uint64 {.importc, stdcall, dynlib: "kernel32".}
proc CreatePipe(r, w: ptr H; sa: pointer; n: DW): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc WriteFile(h: H; buf: pointer; n: DW; wrote: ptr DW; ov: pointer): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc ReadFile(h: H; buf: pointer; n: DW; got: ptr DW; ov: pointer): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: H): BL {.importc, stdcall, dynlib: "kernel32".}
proc CreateFileW(name: ptr uint16; access, share: DW; sa: pointer;
                 disp, flags: DW; tmpl: H): H
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateNamedPipeW(name: ptr uint16; openMode, pipeMode, maxInst,
                      outBuf, inBuf, timeout: DW; sa: pointer): H
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateFileMappingW(hFile: H; sa: pointer; prot, hi, lo: DW;
                        name: ptr uint16): H
  {.importc, stdcall, dynlib: "kernel32".}
proc OpenFileMappingW(access: DW; inherit: BL; name: ptr uint16): H
  {.importc, stdcall, dynlib: "kernel32".}
proc MapViewOfFile(hMap: H; access, hi, lo: DW; n: uint): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc UnmapViewOfFile(p: pointer): BL {.importc, stdcall, dynlib: "kernel32".}
proc GetLastError(): DW {.importc, stdcall, dynlib: "kernel32".}

# Winsock, for the socket arm of ipc-connect.
type
  SockAddrIn {.bycopy.} = object
    sinFamily: uint16
    sinPort: uint16
    sinAddr: uint32
    sinZero: array[8, byte]
  WsaData {.bycopy.} = object
    wVersion: uint16
    wHighVersion: uint16
    raw: array[400, byte]

proc WSAStartup(v: uint16; d: ptr WsaData): int32
  {.importc, stdcall, dynlib: "ws2_32".}
proc socketRaw(af, styp, protocol: int32): uint
  {.importc: "socket", stdcall, dynlib: "ws2_32".}
proc connectRaw(s: uint; name: pointer; namelen: int32): int32
  {.importc: "connect", stdcall, dynlib: "ws2_32".}
proc closesocket(s: uint): int32 {.importc, stdcall, dynlib: "ws2_32".}
proc htonsRaw(x: uint16): uint16
  {.importc: "htons", stdcall, dynlib: "ws2_32".}
proc WSAGetLastError(): int32 {.importc, stdcall, dynlib: "ws2_32".}
proc ioctlsocket(s: uint; cmd: int32; argp: ptr uint32): int32
  {.importc, stdcall, dynlib: "ws2_32".}

# NtCreateFile, for the NT-layer arm of the named-pipe classification. Called
# DIRECTLY rather than through CreateFileW, which is the whole point: it is the
# only way to reach `snoopNtCreateFile`'s classification without the kernel32
# arm firing first and producing the same record for a different reason.
#
# The structures are declared as ordinary Nim objects so the compiler lays them
# out for the TARGET bitness. A hand-computed offset would be the same defect
# the shim's own `objectAttributesToString` has (it reads ObjectName at the x64
# offset 16 unconditionally, which is 8 on 32-bit).
type
  UnicodeStringT {.bycopy.} = object
    length: uint16
    maximumLength: uint16
    buffer: ptr uint16
  ObjectAttributesT {.bycopy.} = object
    length: uint32
    rootDirectory: H
    objectName: ptr UnicodeStringT
    attributes: uint32
    securityDescriptor: pointer
    securityQualityOfService: pointer
  IoStatusBlockT {.bycopy.} = object
    statusOrPointer: pointer
    information: uint

# CreateProcessW, for the INHERITED-pipe case. Nim's `osproc` gives no way to
# mark a handle inheritable and pass it down, and that inheritance is the whole
# point: an anonymous pipe's create and its read then happen in DIFFERENT
# processes, which is the only arrangement in which the pairing key's
# process-independence is actually tested.
type
  SecurityAttributesT {.bycopy.} = object
    nLength: uint32
    lpSecurityDescriptor: pointer
    bInheritHandle: BL
  StartupInfoT {.bycopy.} = object
    cb: uint32
    lpReserved: ptr uint16
    lpDesktop: ptr uint16
    lpTitle: ptr uint16
    dwX, dwY, dwXSize, dwYSize: uint32
    dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags: uint32
    wShowWindow, cbReserved2: uint16
    lpReserved2: pointer
    hStdInput, hStdOutput, hStdError: H
  ProcessInformationT {.bycopy.} = object
    hProcess: H
    hThread: H
    dwProcessId: uint32
    dwThreadId: uint32

proc CreateProcessW(applicationName: ptr uint16; commandLine: ptr uint16;
                    processAttributes, threadAttributes: pointer;
                    inheritHandles: BL; creationFlags: DW;
                    environment: pointer; currentDirectory: ptr uint16;
                    startupInfo: ptr StartupInfoT;
                    processInformation: ptr ProcessInformationT): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(h: H; ms: DW): DW
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess(h: H; code: ptr DW): BL
  {.importc, stdcall, dynlib: "kernel32".}
proc SetHandleInformation(h: H; mask, flags: DW): BL
  {.importc, stdcall, dynlib: "kernel32".}

proc NtCreateFile(fileHandle: ptr H; desiredAccess: DW;
                  objectAttributes: ptr ObjectAttributesT;
                  ioStatusBlock: ptr IoStatusBlockT;
                  allocationSize: ptr int64;
                  fileAttributes, shareAccess, createDisposition,
                  createOptions: DW;
                  eaBuffer: pointer; eaLength: DW): int32
  {.importc, stdcall, dynlib: "ntdll".}

const
  GenericRead = 0x80000000'u32
  GenericWrite = 0x40000000'u32
  OpenExisting = 3'u32
  CreateAlways = 2'u32
  FileMapRead = 0x0004'u32
  PageReadonly = 0x02'u32
  PageReadwrite = 0x04'u32
  PipeAccessDuplex = 0x00000003'u32
  WsaEConnRefused = 10061'i32
  WsaEWouldBlock = 10035'i32
  Fionbio = 0x8004667E'i32
  # NtCreateFile constants.
  NtSynchronize = 0x00100000'u32
  NtFileOpen = 1'u32                 # CreateDisposition: fail if absent
  NtFileShareReadWrite = 0x00000003'u32
  NtFileSynchronousIoNonAlert = 0x00000020'u32
  NtObjCaseInsensitive = 0x00000040'u32
  # The size the out-of-tree owner and the monitored attacher must agree on for
  # `CreateFileMapping` to JOIN rather than fail.
  SharedSectionBytes = 4096'u32
  HandleFlagInherit = 0x00000001'u32
  InfiniteWait = 0xFFFFFFFF'u32

let Invalid: H = cast[H](cast[uint](0'i64 - 1'i64))

proc wide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0'u16

proc namedPipeServer*(name: string): H =
  ## Open a one-instance named-pipe SERVER. Used by a test process that stays
  ## OUT of the monitored tree, so the monitored client's peer is provably not
  ## a monitored process -- the breakaway-daemon shape.
  var w = wide(name)
  CreateNamedPipeW(addr w[0], PipeAccessDuplex, 0'u32, 4'u32,
    4096'u32, 4096'u32, 0'u32, nil)

proc namedSection*(name: string): H =
  ## Create a named pagefile-backed section, likewise from out of tree.
  var w = wide(name)
  CreateFileMappingW(Invalid, nil, PageReadwrite, 0'u32, SharedSectionBytes,
    addr w[0])

proc closeH*(h: H) =
  if h != nil and h != Invalid:
    discard CloseHandle(h)

# --- The fixture modes ------------------------------------------------------

const ChannelFixtureFlag* = "--io-mon-channel-fixture"
  ## Declared here rather than beside `runChannelFixtureIfRequested` because
  ## `anon-pipe-inherit` re-invokes the fixture binary itself to get a SECOND
  ## monitored process on the far end of a pipe.

proc fxEntropy(rounds: int): int =
  var buf: array[32, byte]
  for _ in 0 ..< rounds:
    if BCryptGenRandom(nil, addr buf[0], 32'u32, 2'u32) < 0:
      return 21
    if SystemFunction036(addr buf[0], 32'u32) == 0'u8:
      return 22
  0

proc fxTime(rounds: int): int =
  for _ in 0 ..< rounds:
    var qpc: int64 = 0
    if QueryPerformanceCounter(addr qpc) == 0:
      return 23
    var ft: array[2, uint32]
    GetSystemTimeAsFileTime(addr ft[0])
    if GetTickCount64() == 0'u64:
      return 24
  0

proc fxInProcNamedPipe(name: string): int =
  let srv = namedPipeServer(name)
  if srv == Invalid:
    return 31
  var w = wide(name)
  let cli = CreateFileW(addr w[0], GenericRead, 0'u32, nil, OpenExisting,
    0'u32, nil)
  let err = GetLastError()
  closeH(srv)
  if cli == Invalid:
    stderr.writeLine "in-proc pipe client failed err=" & $err
    return 32
  closeH(cli)
  0

proc fxPipeClient(name: string): int =
  var w = wide(name)
  let cli = CreateFileW(addr w[0], GenericRead, 0'u32, nil, OpenExisting,
    0'u32, nil)
  if cli == Invalid:
    stderr.writeLine "pipe client failed err=" & $GetLastError()
    return 33
  closeH(cli)
  0

proc fxSocketConnect(port: int): int =
  var d: WsaData
  if WSAStartup(0x0202'u16, addr d) != 0:
    return 41
  let s = socketRaw(2'i32, 1'i32, 6'i32)      # AF_INET, SOCK_STREAM, TCP
  if s == high(uint):
    return 42
  var sa = SockAddrIn(sinFamily: 2'u16, sinPort: htonsRaw(uint16(port)),
    sinAddr: 0x0100007F'u32)                  # 127.0.0.1, network order
  let rc = connectRaw(s, addr sa, int32(sizeof(SockAddrIn)))
  discard closesocket(s)
  if rc != 0:
    stderr.writeLine "connect failed"
    return 43
  0

proc fxSocketConnectRefused(port: int): int =
  ## Connect to a port with NOTHING listening and require the REFUSAL.
  ##
  ## This is the case the live-listener mode cannot reach. A build host runs
  ## these constantly -- "is the daemon already up?", sccache and
  ## language-server discovery, every retry loop -- and each one ends in
  ## WSAECONNREFUSED having reached no peer at all. If the shim records it as an
  ## ipc-connect to an unknown peer, the merge downgrades the whole capture over
  ## a connection that never happened.
  ##
  ## The refusal is ASSERTED rather than assumed: a mode that silently
  ## connected (a port that turned out to be live) would produce a run whose
  ## missing-record assertion passes for the wrong reason.
  var d: WsaData
  if WSAStartup(0x0202'u16, addr d) != 0:
    return 44
  let s = socketRaw(2'i32, 1'i32, 6'i32)      # AF_INET, SOCK_STREAM, TCP
  if s == high(uint):
    return 45
  var sa = SockAddrIn(sinFamily: 2'u16, sinPort: htonsRaw(uint16(port)),
    sinAddr: 0x0100007F'u32)                  # 127.0.0.1, network order
  let rc = connectRaw(s, addr sa, int32(sizeof(SockAddrIn)))
  let err = WSAGetLastError()
  discard closesocket(s)
  if rc == 0:
    stderr.writeLine "connect to a closed port SUCCEEDED; port " & $port &
      " is not closed"
    return 46
  if err != WsaEConnRefused:
    stderr.writeLine "connect to a closed port failed with wsaerr=" & $err &
      ", expected WSAECONNREFUSED (" & $WsaEConnRefused & ")"
    return 47
  0

proc fxPipeClientMissing(name: string): int =
  ## Open a named pipe that DOES NOT EXIST, and require the failure.
  ##
  ## The pipe-arm counterpart of `socket-connect-refused`. A failed open
  ## consumed nothing and reached no peer, so classifying it would record a
  ## connection to an unknown peer and downgrade the capture over a connection
  ## that never happened. `classifyOpenedPath` states the rule; this is what
  ## makes it a tested one.
  var w = wide(name)
  let cli = CreateFileW(addr w[0], GenericRead, 0'u32, nil, OpenExisting,
    0'u32, nil)
  if cli != Invalid:
    closeH(cli)
    stderr.writeLine "the pipe " & name & " unexpectedly EXISTS; this run " &
      "does not test the failed-open path"
    return 36
  0

proc fxSocketConnectNonBlocking(port: int): int =
  ## A NON-BLOCKING connect to a live listener: the in-flight case.
  ##
  ## `connect` returns SOCKET_ERROR with WSAEWOULDBLOCK and the connection
  ## completes asynchronously -- the ordinary shape of an async client talking
  ## to a daemon. It is not a failure and the peer IS reached, so the shim must
  ## record it; a guard that only accepted `rc == 0` would go silent over a real
  ## out-of-tree peer, which is a false `mcComplete`.
  ##
  ## The outcome is asserted, not assumed: an immediate completion would make a
  ## record assertion pass for the `rc == 0` reason instead.
  var d: WsaData
  if WSAStartup(0x0202'u16, addr d) != 0:
    return 48
  let s = socketRaw(2'i32, 1'i32, 6'i32)      # AF_INET, SOCK_STREAM, TCP
  if s == high(uint):
    return 49
  var nonBlocking: uint32 = 1
  if ioctlsocket(s, Fionbio, addr nonBlocking) != 0:
    discard closesocket(s)
    return 50
  var sa = SockAddrIn(sinFamily: 2'u16, sinPort: htonsRaw(uint16(port)),
    sinAddr: 0x0100007F'u32)                  # 127.0.0.1, network order
  let rc = connectRaw(s, addr sa, int32(sizeof(SockAddrIn)))
  let err = WSAGetLastError()
  discard closesocket(s)
  if rc == 0:
    stderr.writeLine "non-blocking connect completed IMMEDIATELY; this run " &
      "does not exercise the in-flight case"
    return 51
  if err != WsaEWouldBlock:
    stderr.writeLine "non-blocking connect failed with wsaerr=" & $err &
      ", expected WSAEWOULDBLOCK (" & $WsaEWouldBlock & ")"
    return 52
  0

proc fxNtPipeClient(name: string): int =
  ## Open a named pipe by calling `NtCreateFile` DIRECTLY.
  ##
  ## `name` is the Win32 spelling (`\\.\pipe\<x>`); this converts it to the NT
  ## object form `\??\pipe\<x>`, which is what a client that skips kernel32
  ## actually passes. The shim's NT arm has to classify on THAT spelling: the
  ## path it records has had `\??\` stripped and is then byte-for-byte a
  ## relative `pipe\<x>`, which the classifier must reject. Dropping the raw
  ## ObjectName therefore loses the pipe silently, and no CreateFileW-based
  ## fixture can see it because the kernel32 arm produces the record first.
  if not name.startsWith(r"\\.\pipe" & "\\"):
    return 34
  let ntPath = r"\??\pipe" & "\\" & name[len(r"\\.\pipe" & "\\") .. ^1]
  var w = wide(ntPath)
  var us = UnicodeStringT(
    length: uint16((w.len - 1) * 2),
    maximumLength: uint16(w.len * 2),
    buffer: addr w[0])
  var oa = ObjectAttributesT(
    length: uint32(sizeof(ObjectAttributesT)),
    rootDirectory: nil,
    objectName: addr us,
    attributes: NtObjCaseInsensitive,
    securityDescriptor: nil,
    securityQualityOfService: nil)
  var iosb: IoStatusBlockT
  var h: H = nil
  let status = NtCreateFile(addr h, GenericRead or NtSynchronize, addr oa,
    addr iosb, nil, 0'u32, NtFileShareReadWrite, NtFileOpen,
    NtFileSynchronousIoNonAlert, nil, 0'u32)
  if status < 0 or h == nil or h == Invalid:
    stderr.writeLine "NtCreateFile on " & ntPath & " failed status=0x" &
      toHex(uint32(status), 8)
    return 35
  closeH(h)
  0

proc fxShmCreateExisting(name: string): int =
  ## Call `CreateFileMapping` over a name SOMEBODY ELSE already owns.
  ##
  ## `CreateFileMapping` does not fail on an existing name -- it OPENS the
  ## existing section and sets ERROR_ALREADY_EXISTS. So the same call is both
  ## the producer and the consumer of a shared-memory channel, and only the
  ## last-error distinguishes them. Recording this as `role=create` would let an
  ## OUT-OF-TREE producer's section be paired against the monitored process's
  ## own record, and the capture would grade `mcComplete` over bytes that came
  ## from a process it never saw.
  ##
  ## The size and protection must match the owner's, or the join fails with
  ## ERROR_ACCESS_DENIED / ERROR_INVALID_PARAMETER instead of succeeding.
  var w = wide(name)
  let hm = CreateFileMappingW(Invalid, nil, PageReadwrite, 0'u32,
    SharedSectionBytes, addr w[0])
  if hm == nil:
    stderr.writeLine "CreateFileMapping over an existing name failed err=" &
      $GetLastError()
    return 64
  let err = GetLastError()
  closeH(hm)
  if err != 183'u32:                          # ERROR_ALREADY_EXISTS
    stderr.writeLine "CreateFileMapping did not report ERROR_ALREADY_EXISTS " &
      "(err=" & $err & "); the section was NOT pre-owned, so this run cannot " &
      "test the attach arm"
    return 65
  0

proc fxMapFile(path: string): int =
  var w = wide(path)
  let hf = CreateFileW(addr w[0], GenericRead, 1'u32, nil, OpenExisting,
    0'u32, nil)
  if hf == Invalid:
    return 51
  let hm = CreateFileMappingW(hf, nil, PageReadonly, 0'u32, 0'u32, nil)
  if hm == nil:
    closeH(hf)
    return 52
  let view = MapViewOfFile(hm, FileMapRead, 0'u32, 0'u32, 0'u)
  if view == nil:
    closeH(hm); closeH(hf)
    return 53
  # Touch the mapping so this is a genuine content read, not just a mapping.
  let first = cast[ptr byte](view)[]
  discard first
  discard UnmapViewOfFile(view)
  closeH(hm)
  closeH(hf)
  0

proc fxShmInProc(name: string): int =
  let hm = namedSection(name)
  if hm == nil:
    return 61
  var w = wide(name)
  let ho = OpenFileMappingW(FileMapRead, 0, addr w[0])
  closeH(hm)
  if ho == nil:
    return 62
  closeH(ho)
  0

proc fxShmOpen(name: string): int =
  var w = wide(name)
  let ho = OpenFileMappingW(FileMapRead, 0, addr w[0])
  if ho == nil:
    stderr.writeLine "OpenFileMapping failed err=" & $GetLastError()
    return 63
  closeH(ho)
  0

proc fxAnonPipe(): int =
  var hr, hw: H
  if CreatePipe(addr hr, addr hw, nil, 0'u32) == 0:
    return 71
  var payload = "anon-pipe-payload"
  var wrote: DW = 0
  if WriteFile(hw, addr payload[0], DW(payload.len), addr wrote, nil) == 0:
    closeH(hw); closeH(hr)
    return 72
  var rbuf: array[64, byte]
  var got: DW = 0
  let ok = ReadFile(hr, addr rbuf[0], wrote, addr got, nil)
  closeH(hw)
  closeH(hr)
  if ok == 0 or got == 0'u32:
    return 73
  0

proc fxAnonPipeInheritParent(): int =
  ## Create an anonymous pipe, hand the READ end to a CHILD by inheritance, and
  ## write the payload the child consumes.
  ##
  ## `fxAnonPipe` above does both ends in one process, which cannot test the
  ## property that matters: the merge pairs a create against a read by an
  ## identity string that has to be THE SAME in two different processes. An
  ## in-process fixture makes any per-process key look correct. This is the
  ## round-4 IP1 shape -- a launcher creates a pipe, clears the inherit
  ## restriction on one end, and execs a client that reads it -- with both ends
  ## in tree, so the correct answer is `mcComplete` and a PAIRED read.
  var hr, hw: H
  var sa = SecurityAttributesT(
    nLength: uint32(sizeof(SecurityAttributesT)),
    lpSecurityDescriptor: nil,
    bInheritHandle: 1)
  if CreatePipe(addr hr, addr hw, addr sa, 0'u32) == 0:
    return 74
  # Only the READ end travels; the write end stays private so the child sees
  # EOF when the parent closes it.
  if SetHandleInformation(hw, HandleFlagInherit, 0'u32) == 0:
    closeH(hr); closeH(hw)
    return 75
  var payload = "inherited-pipe-payload"
  var wrote: DW = 0
  if WriteFile(hw, addr payload[0], DW(payload.len), addr wrote, nil) == 0:
    closeH(hr); closeH(hw)
    return 76
  var cmd = "\"" & getAppFilename() & "\" " & ChannelFixtureFlag &
    " anon-pipe-child " & $cast[uint](hr)
  var cmdW = wide(cmd)
  var si = StartupInfoT(cb: uint32(sizeof(StartupInfoT)))
  var pi: ProcessInformationT
  if CreateProcessW(nil, addr cmdW[0], nil, nil, 1, 0'u32, nil, nil,
      addr si, addr pi) == 0:
    stderr.writeLine "CreateProcessW for the pipe child failed err=" &
      $GetLastError()
    closeH(hr); closeH(hw)
    return 77
  discard WaitForSingleObject(pi.hProcess, InfiniteWait)
  var childExit: DW = 0
  discard GetExitCodeProcess(pi.hProcess, addr childExit)
  closeH(pi.hThread)
  closeH(pi.hProcess)
  closeH(hr)
  closeH(hw)
  if childExit != 0'u32:
    stderr.writeLine "pipe child exited " & $childExit
    return 78
  0

proc fxAnonPipeChild(handleText: string): int =
  ## Read from a pipe handle this process never opened -- it arrived by
  ## inheritance, with the same numeric value it had in the parent. The shim
  ## sees a read from an unknown handle, which is the `chan=opaque` case.
  var raw: uint = 0
  try:
    raw = uint(parseUInt(handleText))
  except ValueError:
    return 79
  let h = cast[H](raw)
  var rbuf: array[64, byte]
  var got: DW = 0
  if ReadFile(h, addr rbuf[0], 64'u32, addr got, nil) == 0 or got == 0'u32:
    stderr.writeLine "inherited-pipe read failed err=" & $GetLastError()
    return 80
  0

proc fxOpenAsSpelled(rel: string): int =
  ## Open a path EXACTLY as given, without canonicalising it first.
  ##
  ## The spelling is the point. The shim records the path as the caller wrote
  ## it, so a relative `pipe\x.txt` and an extended-length
  ## `\\?\C:\...\pipe\x.txt` are what a named-pipe classifier actually has to
  ## reject -- an absolute `C:\...\pipe\x.txt` never even reaches it.
  var w = wide(rel)
  let h = CreateFileW(addr w[0], GenericRead, 1'u32, nil, OpenExisting,
    0'u32, nil)
  if h == Invalid:
    stderr.writeLine "relative open failed err=" & $GetLastError()
    return 91
  var rbuf: array[64, byte]
  var got: DW = 0
  discard ReadFile(h, addr rbuf[0], 8'u32, addr got, nil)
  closeH(h)
  0

proc fxAds(path: string): int =
  let stream = path & ":io-mon-m5"
  var ws = wide(stream)
  let hw2 = CreateFileW(addr ws[0], GenericWrite, 0'u32, nil, CreateAlways,
    0'u32, nil)
  if hw2 == Invalid:
    stderr.writeLine "ADS create failed err=" & $GetLastError()
    return 81
  var payload = "ads-payload"
  var wrote: DW = 0
  discard WriteFile(hw2, addr payload[0], DW(payload.len), addr wrote, nil)
  closeH(hw2)
  var ws2 = wide(stream)
  let hr2 = CreateFileW(addr ws2[0], GenericRead, 0'u32, nil, OpenExisting,
    0'u32, nil)
  if hr2 == Invalid:
    return 82
  var rbuf: array[64, byte]
  var got: DW = 0
  discard ReadFile(hr2, addr rbuf[0], 11'u32, addr got, nil)
  closeH(hr2)
  if got == 0'u32:
    return 83
  0

proc channelFixtureMain*(mode: string; arg: string): int =
  ## Run one channel exercise. Non-zero means the channel was NOT exercised.
  case mode
  of "entropy": fxEntropy(1)
  of "entropy-loop": fxEntropy(500)
  of "time": fxTime(1)
  of "time-loop": fxTime(500)
  of "inproc-named-pipe": fxInProcNamedPipe(arg)
  of "pipe-client": fxPipeClient(arg)
  of "nt-pipe-client": fxNtPipeClient(arg)
  of "pipe-client-missing": fxPipeClientMissing(arg)
  of "socket-connect": fxSocketConnect(parseInt(arg))
  of "socket-connect-refused": fxSocketConnectRefused(parseInt(arg))
  of "socket-connect-nonblocking": fxSocketConnectNonBlocking(parseInt(arg))
  of "map-file": fxMapFile(arg)
  of "shm-inproc": fxShmInProc(arg)
  of "shm-open": fxShmOpen(arg)
  of "shm-create-existing": fxShmCreateExisting(arg)
  of "anon-pipe": fxAnonPipe()
  of "anon-pipe-inherit": fxAnonPipeInheritParent()
  of "anon-pipe-child": fxAnonPipeChild(arg)
  of "open-as-spelled": fxOpenAsSpelled(arg)
  of "ads": fxAds(arg)
  else: 99

proc runChannelFixtureIfRequested*() =
  ## Fixture dispatch for a test binary that re-invokes ITSELF as the
  ## monitored program. Must be called before the suites so the monitored
  ## invocation exercises the channel and exits instead of re-running the
  ## whole test file.
  if paramCount() >= 2 and paramStr(1) == ChannelFixtureFlag:
    let arg = if paramCount() >= 3: paramStr(3) else: ""
    quit(channelFixtureMain(paramStr(2), arg))
