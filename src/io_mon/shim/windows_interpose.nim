when not defined(windows):
  {.error: "repro_monitor_shim/windows_interpose is Windows-only".}

# Windows: Reprobuild monitor shim DLL — feature-parity counterpart to
# macos_interpose.nim. On macOS the shim is injected via
# DYLD_INSERT_LIBRARIES and uses ct_interpose's function interposition.
# On Windows there is no DYLD_INSERT_LIBRARIES equivalent, so this DLL
# is injected via CreateProcess(CREATE_SUSPENDED) + CreateRemoteThread
# (the call site lives in repro_monitor_depfile/fs_snoop.nim) and uses
# IAT patching to redirect calls to CreateFileW / ReadFile / WriteFile /
# CloseHandle / GetFileAttributesExW / CreateProcessW / CreateProcessA.
#
# M26: the shim no longer wires its IAT-installed trampolines directly to
# bespoke hook bodies. Instead, each Win32 API is dispatched through
# ct_interpose's ``hook_registry`` (see windows_hook_registry.nim and
# ``codetracer-native-recorder/ct_interpose/src/ct_interpose/hook_registry.nim``).
# The monitor's snoop logic is registered as a HookCallback at priority
# ShimSnoopPriority (100). The hook chain's ``original`` callback wraps
# the captured original Win32 function pointer. Other interposers (e.g.
# the codetracer recorder when co-resident) can register against the
# same chain at their own priorities without colliding with the shim.

import std/[atomics, exitprocs, locks, os, strutils, tables]
from io_mon/paths import extendedPath

import io_mon/types
import io_mon/writer

import io_mon/shim/windows_iat_patcher
import io_mon/shim/windows_hook_registry as hr
import io_mon/shim/install_audit

# Framework's safer grandchild-injection primitive — replaces the
# bespoke INFINITE-wait inject_dll path with concurrent-injection cap
# + per-call deadline + already-mapped probe + resume-before-init.
import stackable_hooks/propagation_windows as shProp

{.push raises: [].}

# ---------------------------------------------------------------------------
# M73 — dispatch-mechanism-agnostic install backend.
#
# IAT patching catches CRT-internal forwarding (statically-linked
# ``__declspec(dllimport)`` callers like the C runtime's
# ``_wspawnvp`` → ``CreateProcessW``). It does NOT catch Nim's
# ``{.importc, dynlib: "kernel32".}`` declarations: Nim's codegen
# lowers those to ``nimGetProcAddr``-resolved function pointers cached
# in a module-global, then calls through the pointer directly. The
# IAT is bypassed entirely, so a Nim ``startProcess`` call spawns its
# grandchild without the shim seeing the spawn — and without
# propagating the shim into that grandchild for further capture. That
# bypass is unacceptable: the monitor's contract is "no bypass under
# any dispatch mechanism", and the only place a call ALWAYS converges
# is the function body in kernel32 itself.
#
# M72 introduced inline hooking for CreateProcessW/A only; M73 promotes
# every hooked Win32 API to the same install path. Mirror the
# codetracer-native-recorder's M50.2 inline-hook primitive
# (``ct_inline_hook/install_windows.c``): install a 5-byte
# ``JMP rel32`` at the start of each ``kernel32!Xxx`` function
# redirecting to the existing trampolines. IAT patching is retained
# only as the fallback for entries the inline backend rejects.
#
# The C source files live in the recorder repo's ``ct_inline_hook``
# directory. Resolve their path at compile time, anchored on
# ``currentSourcePath`` so a vendored copy under
# ``libs/repro_monitor_shim/vendor/ct_inline_hook`` would also work
# if the recorder sibling checkout is missing.

# M73 used to {.compile.} the ct_inline_hook C sources directly out of
# the codetracer-native-recorder sibling checkout. That entangled
# reprobuild's build with the recorder's source tree; with the
# stackable-hooks split the inline-detour primitive now lives in
# ``metacraft-labs/nim-stackable-hooks`` and we pull it via a Nim
# wrapper that handles the {.compile.} blocks under the hood.
import stackable_hooks/inline_hook/windows_inline_hook

const ctInlineHookAvailable = true
  ## Inline detours work in both bitnesses.
  ##
  ## They did not always: installing one means relocating the prologue bytes
  ## the detour overwrites, which means decoding their lengths, and the
  ## decoder in `inline_hook/windows/length_decoder.c` originally decoded
  ## 64-bit mode only. Run against 32-bit code it consumed 0x40-0x4F as REX
  ## prefixes where 32-bit has `INC`/`DEC reg`, so it reported lengths for
  ## instructions that were not there and the init thread faulted on commit
  ## -- killing that thread only, leaving the child running and reporting
  ## nothing but its process-start.
  ##
  ## The decoder, the rel32 fixup and the trampoline emitters now select
  ## their mode from the build target (`CT_ILD_MODE64`), which is sound
  ## because this machinery only ever rewrites code already mapped in its
  ## own process. A monitored 32-bit `cmd /c echo hi` lands all 31 detours.
  ##
  ## Still 64-bit-only: `ct_inline_hook_install_noreturn`, whose entry stub
  ## is hand-assembled against the Win64 ABI. Nothing here calls it, and the
  ## 32-bit build refuses it explicitly rather than emitting an untested
  ## translation.

template ctInlineHookInstall(target, hook: pointer;
                             outTrampoline: ptr pointer): cint =
  inlineHookInstall(target, hook, outTrampoline)

template ctInlineHookUninstall(target: pointer): cint =
  inlineHookUninstall(target)

template ctInlineHookBeginTransaction(): cint =
  inlineHookBeginTransaction()

template ctInlineHookCommitTransaction(): cint =
  inlineHookCommitTransaction()

template ctInlineHookAbortTransaction(): cint =
  inlineHookAbortTransaction()

const
  # M10 — geometry of the trampoline-side dedup table. Declared up here
  # because `EnvFastEntry` below is sized from it.
  EnvFastSlots = 1024           ## power of two
  EnvFastNameMax = 96
  EnvFastProbe = 8

# --- Win32 typedefs ---------------------------------------------------------

type
  HANDLE = pointer
  DWORD = uint32
  WORD = uint16
  BOOL = int32
  LPCSTR = cstring
  LPCWSTR = ptr uint16
  LPSTR = cstring
  LPWSTR = ptr uint16
  LPVOID = pointer
  LPCVOID = pointer
  LPSECURITY_ATTRIBUTES = pointer
  LPOVERLAPPED = pointer
  LARGE_INTEGER = int64

  STARTUPINFOA {.bycopy.} = object
    cb: DWORD
    lpReserved: LPSTR
    lpDesktop: LPSTR
    lpTitle: LPSTR
    dwX: DWORD
    dwY: DWORD
    dwXSize: DWORD
    dwYSize: DWORD
    dwXCountChars: DWORD
    dwYCountChars: DWORD
    dwFillAttribute: DWORD
    dwFlags: DWORD
    wShowWindow: WORD
    cbReserved2: WORD
    lpReserved2: ptr byte
    hStdInput: HANDLE
    hStdOutput: HANDLE
    hStdError: HANDLE

  STARTUPINFOW {.bycopy.} = object
    cb: DWORD
    lpReserved: LPWSTR
    lpDesktop: LPWSTR
    lpTitle: LPWSTR
    dwX: DWORD
    dwY: DWORD
    dwXSize: DWORD
    dwYSize: DWORD
    dwXCountChars: DWORD
    dwYCountChars: DWORD
    dwFillAttribute: DWORD
    dwFlags: DWORD
    wShowWindow: WORD
    cbReserved2: WORD
    lpReserved2: ptr byte
    hStdInput: HANDLE
    hStdOutput: HANDLE
    hStdError: HANDLE

  PROCESS_INFORMATION {.bycopy.} = object
    hProcess: HANDLE
    hThread: HANDLE
    dwProcessId: DWORD
    dwThreadId: DWORD

const
  GENERIC_WRITE = 0x40000000'u32
  GENERIC_READ = 0x80000000'u32
  CREATE_ALWAYS = 2'u32
  CREATE_NEW = 1'u32
  OPEN_ALWAYS = 4'u32
  TRUNCATE_EXISTING = 5'u32
  OPEN_EXISTING = 3'u32

# Windows: INVALID_HANDLE_VALUE is documented as (HANDLE)(-1). We can't use a
# const because Nim insists on a typed integer literal, so a `let` initialised
# from a typed expression suffices.
let INVALID_HANDLE_VALUE {.used.}: HANDLE = cast[HANDLE](cast[uint](0'i64 - 1'i64))

# --- Win32 imports ---------------------------------------------------------

proc callResultBool(raw: uint64): BOOL {.inline.} =
  ## Narrow a hook's captured return register to Windows `BOOL` semantics.
  ##
  ## `HookContext.result` is `uint64` -- the full return register. Windows
  ## `BOOL` is `int32`, and the x64 ABI does NOT require a callee to zero the
  ## upper half of RAX for a 32-bit return; callers are simply expected to
  ## ignore it. So the raw value can legitimately carry garbage above bit 31.
  ##
  ## A direct `callResultBool(ctx.result)` conversion is therefore two bugs waiting:
  ##
  ##   * it can raise `RangeDefect` when the raw value exceeds `int32.high`.
  ##     These procs are `{.raises: [].}` hook callbacks and the surrounding
  ##     `except CatchableError` does NOT catch a `Defect`, so that would take
  ##     the whole monitored process down from inside a hook. Note the shim
  ##     builds with `-d:release`, which KEEPS range checks -- only `-d:danger`
  ##     removes them, so this is live in production builds, not just debug.
  ##   * even where it does not trap, testing the full 64 bits answers a
  ##     different question from the one Windows asked.
  ##
  ## Masking answers exactly the question `BOOL` encodes, and cannot trap.
  BOOL(raw and 0xFFFF_FFFF'u64)

proc GetCurrentProcessId(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentThreadId(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetLastError(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc SetLastError(dwErrCode: DWORD): void
  {.importc, stdcall, dynlib: "kernel32".}
proc OutputDebugStringA(lpOutputString: cstring): void
  {.importc, stdcall, dynlib: "kernel32".}
proc GetEnvironmentVariableA(lpName: cstring, lpBuffer: cstring,
                              nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc WideCharToMultiByte(CodePage: DWORD, dwFlags: DWORD,
                         lpWideCharStr: LPCWSTR, cchWideChar: int32,
                         lpMultiByteStr: LPSTR, cbMultiByte: int32,
                         lpDefaultChar: LPCSTR,
                         lpUsedDefaultChar: ptr BOOL): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc lstrlenW(lpString: LPCWSTR): int32
  {.importc, stdcall, dynlib: "kernel32".}
# M10 -- used ONLY to enumerate the environment block from inside the
# whole-block snoops, and always under `withShimMuted`.
#
# These resolve to the same kernel32 bodies the shim detours, so the call
# re-enters our own trampoline. That is deliberate and bounded: the muted
# snoop returns before it records, so the re-entry costs one chain dispatch
# and cannot recurse further. The alternative -- decoding the block the call
# actually RETURNED -- would have to guess whether `GetEnvironmentStrings`
# handed back ANSI or UTF-16 bytes, and a wrong guess yields one-character
# junk variable names in the capture rather than an error.
proc GetEnvironmentStringsWRaw(): LPWSTR
  {.importc: "GetEnvironmentStringsW", stdcall, dynlib: "kernel32".}
proc FreeEnvironmentStringsW(penv: LPWSTR): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetEnvironmentStringsARaw(): LPSTR
  {.importc: "GetEnvironmentStrings", stdcall, dynlib: "kernel32".}
proc FreeEnvironmentStringsA(penv: LPSTR): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

# --- Grandchild injection: pull the shim into every CreateProcess descendant.
# Without this, descendants of a shim-loaded process spawn naked — their
# CreateFileW calls are not hooked, evidence vanishes, dev-env-edge caching
# decides "no observed inputs" and serves stale artifacts.
#
# Mirrors the top-level injector in repro_monitor_depfile/windows_injector.nim:
# spawn the child CREATE_SUSPENDED, allocate a buffer in its address space,
# write our own DLL path into it, fire LoadLibraryW via CreateRemoteThread,
# wait, free, resume the main thread (unless the caller had asked for
# CREATE_SUSPENDED itself).

const
  CREATE_SUSPENDED = 0x00000004'u32
  CREATE_UNICODE_ENVIRONMENT = 0x00000400'u32
  MEM_COMMIT = 0x00001000'u32
  MEM_RESERVE = 0x00002000'u32
  MEM_RELEASE = 0x00008000'u32
  PAGE_READWRITE = 0x04'u32
  INFINITE = 0xFFFFFFFF'u32
  GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004'u32
  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002'u32
  GET_MODULE_HANDLE_EX_FLAG_PIN = 0x00000001'u32

type SIZE_T = uint

proc GetModuleHandleExW(dwFlags: DWORD, lpModuleName: LPCWSTR,
                        phModule: ptr HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleFileNameW(hModule: HANDLE, lpFilename: LPWSTR,
                        nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleHandleW(lpModuleName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetModuleHandleA(lpModuleName: LPCSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcAddress(hModule: HANDLE, lpProcName: LPCSTR): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc EnumProcessModulesEx(hProcess: HANDLE, lphModule: ptr pointer,
                          cb: DWORD, lpcbNeeded: ptr DWORD,
                          dwFilterFlag: DWORD): BOOL
  {.importc, stdcall, dynlib: "psapi".}
proc GetCurrentProcess(): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}

# ---------------------------------------------------------------------------
# M5 — Win32 imports for the IPC-connect / external-content / non-determinism
# observation surface.
#
# `LoadLibraryW` is used to FORCE the modules those hooks live in to be mapped
# before the install pass runs. That is not a convenience: a hook can only be
# installed into a module that is loaded, and a module loaded LATER would carry
# an un-hooked entry point while the profile advertises the capability -- the
# exact shape of over-claim M4 exists to prevent. Mapping ws2_32 / bcrypt /
# advapi32 up front makes "the entry point is hooked" true for the whole
# lifetime of the process rather than only for processes that happened to
# import them statically.
proc LoadLibraryW(lpLibFileName: LPCWSTR): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
# The pipe analogue of `LOCAL_PEERPID`: it names the process on the SERVER end
# of a pipe the caller opened, which is what lets the merge prove whether a
# named-pipe peer is one of this run's monitored processes or an out-of-tree
# breakaway daemon.
proc GetNamedPipeServerProcessId(Pipe: HANDLE, ServerProcessId: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetNamedPipeClientProcessId(Pipe: HANDLE, ClientProcessId: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetFileType(hFile: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}

# `__builtin_return_address(0)` inside a trampoline yields the address the
# CALLER will return to. With an inline detour the caller's `call kernel32!Xxx`
# lands directly on the trampoline, so this is the program's own call site --
# the Windows counterpart of the macOS arm's `ct_macos_addr_in_program` caller
# attribution, and needed for the same reason: an entropy hook is not limited
# to the program's own calls, and flagging the CRT's or the loader's would make
# the observation meaningless.
proc builtinReturnAddress(level: cint): pointer
  {.importc: "__builtin_return_address", nodecl, raises: [].}

const
  FILE_TYPE_PIPE = 0x0003'u32
  AfUnixW = 1'u16
  AfInetW = 2'u16
  AfInet6W = 23'u16
  FILE_MAP_COPY = 0x0001'u32
  FILE_MAP_WRITE = 0x0002'u32
  FILE_MAP_READ = 0x0004'u32
  FILE_MAP_ALL_ACCESS = 0x000F001F'u32

# ---------------------------------------------------------------------------
# Loader notification (library-load observation)
#
# `LdrRegisterDllNotification` is the Windows counterpart of dyld's
# `_dyld_register_func_for_add_image` and of asking the Linux loader for its
# link map: the loader tells us about every image it maps, so nothing has to
# be inferred from hooked calls. It matters that this is not a hook --
# LoadLibraryW is only one of several routes into `LdrLoadDll`, and a
# statically imported DLL is mapped before any of them runs.
#
# Documented since Vista and used by the CRT and by profilers; resolved
# dynamically because it is an ntdll export with no import library.
type
  UnicodeString {.bycopy.} = object
    Length: uint16
    MaximumLength: uint16
    Buffer: LPWSTR

  LdrDllNotificationData {.bycopy.} = object
    Flags: uint32
    FullDllName: ptr UnicodeString
    BaseDllName: ptr UnicodeString
    DllBase: pointer
    SizeOfImage: uint32

  LdrDllNotificationFn = proc (reason: uint32;
                               data: ptr LdrDllNotificationData;
                               context: pointer) {.stdcall, raises: [].}
  LdrRegisterDllNotificationFn = proc (flags: uint32;
                                       callback: LdrDllNotificationFn;
                                       context: pointer;
                                       cookie: ptr pointer): int32
                                      {.stdcall, raises: [].}

const LDR_DLL_NOTIFICATION_REASON_LOADED = 1'u32
proc GetModuleBaseNameW(hProcess: HANDLE, hModule: HANDLE,
                        lpBaseName: LPWSTR, nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "psapi".}
proc VirtualAllocEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                    flAllocationType: DWORD, flProtect: DWORD): LPVOID
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
                   dwFreeType: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID,
                        lpBuffer: LPCVOID, nSize: SIZE_T,
                        lpNumberOfBytesWritten: ptr SIZE_T): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateRemoteThread(hProcess: HANDLE,
                        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                        dwStackSize: SIZE_T, lpStartAddress: pointer,
                        lpParameter: LPVOID, dwCreationFlags: DWORD,
                        lpThreadId: ptr DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc ResumeThread(hThread: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetProcessId(hProcess: HANDLE): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
# Fiber-local storage is Windows' thread-exit callback. `FlsAlloc` takes a
# destructor that the OS runs ON THE EXITING THREAD for every thread whose
# slot value is non-NULL -- the exact contract `pthread_key_create` gives the
# Linux shim, and the only one that works for threads this shim did not
# create. See `armThreadExitFlush`.
proc FlsAlloc(callback: proc(p: pointer) {.stdcall.}): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc FlsSetValue(dwFlsIndex: DWORD; lpFlsData: pointer): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

# --- Hook function pointer types (mirror the Win32 API signatures) ---------

type
  CreateFileWProc = proc(lpFileName: LPCWSTR, dwDesiredAccess: DWORD,
                         dwShareMode: DWORD,
                         lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                         dwCreationDisposition: DWORD,
                         dwFlagsAndAttributes: DWORD,
                         hTemplateFile: HANDLE): HANDLE
                         {.stdcall, raises: [].}

  CreateFileAProc = proc(lpFileName: LPCSTR, dwDesiredAccess: DWORD,
                         dwShareMode: DWORD,
                         lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                         dwCreationDisposition: DWORD,
                         dwFlagsAndAttributes: DWORD,
                         hTemplateFile: HANDLE): HANDLE
                         {.stdcall, raises: [].}

  ReadFileProc = proc(hFile: HANDLE, lpBuffer: LPVOID,
                      nNumberOfBytesToRead: DWORD,
                      lpNumberOfBytesRead: ptr DWORD,
                      lpOverlapped: LPOVERLAPPED): BOOL
                      {.stdcall, raises: [].}

  WriteFileProc = proc(hFile: HANDLE, lpBuffer: LPCVOID,
                       nNumberOfBytesToWrite: DWORD,
                       lpNumberOfBytesWritten: ptr DWORD,
                       lpOverlapped: LPOVERLAPPED): BOOL
                       {.stdcall, raises: [].}

  CloseHandleProc = proc(hObject: HANDLE): BOOL {.stdcall, raises: [].}

  GetFileAttributesExWProc = proc(lpFileName: LPCWSTR, fInfoLevelId: DWORD,
                                   lpFileInformation: LPVOID): BOOL
                                   {.stdcall, raises: [].}

  GetFileAttributesExAProc = proc(lpFileName: LPCSTR, fInfoLevelId: DWORD,
                                   lpFileInformation: LPVOID): BOOL
                                   {.stdcall, raises: [].}

  GetFileAttributesWProc = proc(lpFileName: LPCWSTR): DWORD
                                 {.stdcall, raises: [].}

  GetFileAttributesAProc = proc(lpFileName: LPCSTR): DWORD
                                 {.stdcall, raises: [].}

  CreateProcessWProc = proc(lpApplicationName: LPCWSTR,
                            lpCommandLine: LPWSTR,
                            lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                            lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                            bInheritHandles: BOOL,
                            dwCreationFlags: DWORD,
                            lpEnvironment: LPVOID,
                            lpCurrentDirectory: LPCWSTR,
                            lpStartupInfo: ptr STARTUPINFOW,
                            lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
                            {.stdcall, raises: [].}

  CreateProcessAProc = proc(lpApplicationName: LPCSTR,
                            lpCommandLine: LPSTR,
                            lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                            lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                            bInheritHandles: BOOL,
                            dwCreationFlags: DWORD,
                            lpEnvironment: LPVOID,
                            lpCurrentDirectory: LPCSTR,
                            lpStartupInfo: ptr STARTUPINFOA,
                            lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
                            {.stdcall, raises: [].}

  NtTerminateProcessProc = proc(ProcessHandle: HANDLE;
                                ExitStatus: int32): NTSTATUS
                                {.stdcall, raises: [].}

  # M73 Phase 5 — extended hook surface ----------------------------------

  DeleteFileWProc = proc(lpFileName: LPCWSTR): BOOL {.stdcall, raises: [].}
  DeleteFileAProc = proc(lpFileName: LPCSTR): BOOL {.stdcall, raises: [].}

  CreateDirectoryWProc = proc(lpPathName: LPCWSTR,
                              lpSecurityAttributes: LPSECURITY_ATTRIBUTES): BOOL
                              {.stdcall, raises: [].}
  CreateDirectoryAProc = proc(lpPathName: LPCSTR,
                              lpSecurityAttributes: LPSECURITY_ATTRIBUTES): BOOL
                              {.stdcall, raises: [].}

  # CopyFileW/A: per MSDN the signature is (lpExistingFileName,
  # lpNewFileName, bFailIfExists) -> BOOL.
  CopyFileWProc = proc(lpExistingFileName: LPCWSTR,
                       lpNewFileName: LPCWSTR,
                       bFailIfExists: BOOL): BOOL {.stdcall, raises: [].}
  CopyFileAProc = proc(lpExistingFileName: LPCSTR,
                       lpNewFileName: LPCSTR,
                       bFailIfExists: BOOL): BOOL {.stdcall, raises: [].}

  # MoveFileExW/A: per MSDN (lpExistingFileName, lpNewFileName, dwFlags) -> BOOL.
  # lpNewFileName MAY be NULL when MOVEFILE_DELAY_UNTIL_REBOOT + delete-on-reboot
  # semantics are requested.
  MoveFileExWProc = proc(lpExistingFileName: LPCWSTR,
                         lpNewFileName: LPCWSTR,
                         dwFlags: DWORD): BOOL {.stdcall, raises: [].}
  MoveFileExAProc = proc(lpExistingFileName: LPCSTR,
                         lpNewFileName: LPCSTR,
                         dwFlags: DWORD): BOOL {.stdcall, raises: [].}

  # GetFileInformationByHandleEx: (hFile, FileInformationClass,
  # lpFileInformation, dwBufferSize) -> BOOL. FILE_INFO_BY_HANDLE_CLASS
  # is an enum (int32-equivalent); we pass it through as DWORD slot.
  GetFileInformationByHandleExProc = proc(hFile: HANDLE,
                                          FileInformationClass: DWORD,
                                          lpFileInformation: LPVOID,
                                          dwBufferSize: DWORD): BOOL
                                          {.stdcall, raises: [].}

  SetCurrentDirectoryWProc = proc(lpPathName: LPCWSTR): BOOL
                                  {.stdcall, raises: [].}
  SetCurrentDirectoryAProc = proc(lpPathName: LPCSTR): BOOL
                                  {.stdcall, raises: [].}

  # NtCreateFile lives in ntdll. Signature (per MSDN /
  # phnt headers) is:
  #   NTSTATUS NtCreateFile(
  #     PHANDLE            FileHandle,
  #     ACCESS_MASK        DesiredAccess,
  #     POBJECT_ATTRIBUTES ObjectAttributes,
  #     PIO_STATUS_BLOCK   IoStatusBlock,
  #     PLARGE_INTEGER     AllocationSize,
  #     ULONG              FileAttributes,
  #     ULONG              ShareAccess,
  #     ULONG              CreateDisposition,
  #     ULONG              CreateOptions,
  #     PVOID              EaBuffer,
  #     ULONG              EaLength);
  # ACCESS_MASK is a DWORD-sized value; NTSTATUS is a 32-bit signed
  # integer; both pack into uint64 ABI slots cleanly on x64 stdcall.
  NTSTATUS = int32
  NtCreateFileProc = proc(FileHandle: ptr HANDLE,
                          DesiredAccess: DWORD,
                          ObjectAttributes: pointer,
                          IoStatusBlock: pointer,
                          AllocationSize: ptr LARGE_INTEGER,
                          FileAttributes: DWORD,
                          ShareAccess: DWORD,
                          CreateDisposition: DWORD,
                          CreateOptions: DWORD,
                          EaBuffer: pointer,
                          EaLength: DWORD): NTSTATUS
                          {.stdcall, raises: [].}

  # NtQueryAttributesFile / NtQueryFullAttributesFile catch libuv's
  # uv_fs_stat fast-path (Node.js 20+). Path lives in OBJECT_ATTRIBUTES.
  NtQueryAttributesFileProc = proc(ObjectAttributes: pointer;
                                   FileInformation: pointer): NTSTATUS
                                   {.stdcall, raises: [].}

  # NtQueryDirectoryFile catches libuv's uv_fs_scandir. The directory
  # handle was opened earlier via NtCreateFile / CreateFileW; we look
  # up its path in handlePaths for attribution.
  NtQueryDirectoryFileProc = proc(FileHandle: HANDLE;
                                  Event: HANDLE;
                                  ApcRoutine: pointer;
                                  ApcContext: pointer;
                                  IoStatusBlock: pointer;
                                  FileInformation: pointer;
                                  Length: DWORD;
                                  FileInformationClass: DWORD;
                                  ReturnSingleEntry: BOOL;
                                  FileName: pointer;
                                  RestartScan: BOOL): NTSTATUS
                                  {.stdcall, raises: [].}

  # NtQueryInformationByName — libuv 1.52's fs.statSync fast-path.
  # Path lives in ObjectAttributes (same as NtCreateFile / etc.).
  NtQueryInformationByNameProc = proc(ObjectAttributes: pointer;
                                       IoStatusBlock: pointer;
                                       FileInformation: pointer;
                                       Length: DWORD;
                                       FileInformationClass: DWORD): NTSTATUS
                                       {.stdcall, raises: [].}

  # NtQueryDirectoryFileEx — Win10 1709+ scandir API. Same handle-based
  # contract as NtQueryDirectoryFile but uses a QueryFlags bitmask
  # (SL_RESTART_SCAN = 0x01) instead of separate ReturnSingleEntry +
  # RestartScan BOOL args. 10 stdcall args (vs 11 for the original).
  NtQueryDirectoryFileExProc = proc(FileHandle: HANDLE;
                                    Event: HANDLE;
                                    ApcRoutine: pointer;
                                    ApcContext: pointer;
                                    IoStatusBlock: pointer;
                                    FileInformation: pointer;
                                    Length: DWORD;
                                    FileInformationClass: DWORD;
                                    QueryFlags: DWORD;
                                    FileName: pointer): NTSTATUS
                                    {.stdcall, raises: [].}

  # FindFirstFileW / FindFirstFileExW / FindNextFileW / FindClose —
  # kernel32 directory-enumerate surface used by libuv 1.52 / Node 24
  # for fs.readdirSync. The HANDLE returned by FindFirstFile* is the
  # SEARCH handle (distinct from the file-handle type), but we only
  # need to record the path that the search was started on, so we
  # don't track it across FindNextFileW.
  FindFirstFileWProc = proc(lpFileName: LPCWSTR;
                             lpFindFileData: pointer): HANDLE
                             {.stdcall, raises: [].}
  FindFirstFileExWProc = proc(lpFileName: LPCWSTR;
                              fInfoLevelId: DWORD;
                              lpFindFileData: pointer;
                              fSearchOp: DWORD;
                              lpSearchFilter: pointer;
                              dwAdditionalFlags: DWORD): HANDLE
                              {.stdcall, raises: [].}
  FindNextFileWProc = proc(hFindFile: HANDLE;
                            lpFindFileData: pointer): BOOL
                            {.stdcall, raises: [].}
  FindCloseProc = proc(hFindFile: HANDLE): BOOL
                  {.stdcall, raises: [].}

  # kernel32!GetProcAddress signature.
  GetProcAddressProc = proc(hModule: HANDLE;
                             lpProcName: LPCSTR): pointer
                             {.stdcall, raises: [].}

  # --- M5: IPC-connect (ws2_32.dll) --------------------------------------
  #
  # SOCKET is UINT_PTR, i.e. pointer-sized in both bitnesses; `uint` matches.
  ConnectProc = proc(s: uint; name: pointer; namelen: int32): int32
                     {.stdcall, raises: [].}
  WSAConnectProc = proc(s: uint; name: pointer; namelen: int32;
                        lpCallerData: pointer; lpCalleeData: pointer;
                        lpSQOS: pointer; lpGQOS: pointer): int32
                        {.stdcall, raises: [].}

  # --- M5: external content (kernel32.dll) --------------------------------
  CreateFileMappingWProc = proc(hFile: HANDLE;
                                lpAttributes: LPSECURITY_ATTRIBUTES;
                                flProtect: DWORD;
                                dwMaximumSizeHigh: DWORD;
                                dwMaximumSizeLow: DWORD;
                                lpName: LPCWSTR): HANDLE
                                {.stdcall, raises: [].}
  CreateFileMappingAProc = proc(hFile: HANDLE;
                                lpAttributes: LPSECURITY_ATTRIBUTES;
                                flProtect: DWORD;
                                dwMaximumSizeHigh: DWORD;
                                dwMaximumSizeLow: DWORD;
                                lpName: LPCSTR): HANDLE
                                {.stdcall, raises: [].}
  OpenFileMappingWProc = proc(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
                              lpName: LPCWSTR): HANDLE
                              {.stdcall, raises: [].}
  OpenFileMappingAProc = proc(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
                              lpName: LPCSTR): HANDLE
                              {.stdcall, raises: [].}
  MapViewOfFileProc = proc(hFileMappingObject: HANDLE; dwDesiredAccess: DWORD;
                           dwFileOffsetHigh: DWORD; dwFileOffsetLow: DWORD;
                           dwNumberOfBytesToMap: SIZE_T): LPVOID
                           {.stdcall, raises: [].}
  MapViewOfFileExProc = proc(hFileMappingObject: HANDLE;
                             dwDesiredAccess: DWORD;
                             dwFileOffsetHigh: DWORD; dwFileOffsetLow: DWORD;
                             dwNumberOfBytesToMap: SIZE_T;
                             lpBaseAddress: LPVOID): LPVOID
                             {.stdcall, raises: [].}
  CreatePipeProc = proc(hReadPipe: ptr HANDLE; hWritePipe: ptr HANDLE;
                        lpPipeAttributes: LPSECURITY_ATTRIBUTES;
                        nSize: DWORD): BOOL
                        {.stdcall, raises: [].}

  # --- M5: non-determinism -----------------------------------------------
  #
  # `SystemFunction036` (the export behind the documented `RtlGenRandom`)
  # returns BOOLEAN -- one BYTE in AL, with the rest of EAX undefined. It is
  # declared with a byte-wide result so the trampoline round-trips exactly
  # what the callee produced rather than widening undefined bits.
  BCryptGenRandomProc = proc(hAlgorithm: HANDLE; pbBuffer: pointer;
                             cbBuffer: DWORD; dwFlags: DWORD): NTSTATUS
                             {.stdcall, raises: [].}
  ProcessPrngProc = proc(pbData: pointer; cbData: SIZE_T): BOOL
                          {.stdcall, raises: [].}
  SystemFunction036Proc = proc(RandomBuffer: pointer;
                               RandomBufferLength: DWORD): uint8
                               {.stdcall, raises: [].}
  CryptGenRandomProc = proc(hProv: uint; dwLen: DWORD; pbBuffer: pointer): BOOL
                            {.stdcall, raises: [].}
  QueryPerformanceCounterProc = proc(lpPerformanceCount: ptr LARGE_INTEGER): BOOL
                                     {.stdcall, raises: [].}
  GetSystemTimeAsFileTimeProc = proc(lpSystemTimeAsFileTime: pointer)
                                     {.stdcall, raises: [].}
  GetTickCount64Proc = proc(): uint64 {.stdcall, raises: [].}

  # --- M10: observed environment -----------------------------------------
  #
  # Two families, because Windows keeps TWO copies of the environment and a
  # program reads exactly one of them:
  #
  #   * the Win32 APIs read the PEB's block directly;
  #   * a CRT's `getenv` reads the CRT's OWN snapshot, taken from that block
  #     once at startup. Hooking only the Win32 side would therefore observe
  #     nothing at all for a program built with any C runtime -- which is
  #     most of a toolchain.
  #
  # The CRT entry points are `cdecl`, not `stdcall`: they are C library
  # functions, and getting this wrong on i386 corrupts the stack on every
  # call (the callee would pop arguments the caller also pops). On x64 the
  # two conventions coincide, so a 32-bit build is where a mistake here
  # shows up.
  GetEnvironmentVariableWProc = proc(lpName: LPCWSTR; lpBuffer: LPWSTR;
                                     nSize: DWORD): DWORD
                                     {.stdcall, raises: [].}
  GetEnvironmentVariableAProc = proc(lpName: LPCSTR; lpBuffer: LPSTR;
                                     nSize: DWORD): DWORD
                                     {.stdcall, raises: [].}
  GetEnvironmentStringsWProc = proc(): LPWSTR {.stdcall, raises: [].}
  GetEnvironmentStringsAProc = proc(): LPSTR {.stdcall, raises: [].}
  CrtGetenvProc = proc(name: LPCSTR): LPSTR {.cdecl, raises: [].}
  CrtWGetenvProc = proc(name: LPCWSTR): LPWSTR {.cdecl, raises: [].}
  CrtGetenvSProc = proc(pReturnValue: ptr SIZE_T; buffer: LPSTR;
                        numberOfElements: SIZE_T; varname: LPCSTR): cint
                        {.cdecl, raises: [].}
  CrtWGetenvSProc = proc(pReturnValue: ptr SIZE_T; buffer: LPWSTR;
                         numberOfElements: SIZE_T; varname: LPCWSTR): cint
                         {.cdecl, raises: [].}
  CrtDupenvSProc = proc(buffer: ptr LPSTR; numberOfElements: ptr SIZE_T;
                        varname: LPCSTR): cint {.cdecl, raises: [].}
  CrtWDupenvSProc = proc(buffer: ptr LPWSTR; numberOfElements: ptr SIZE_T;
                         varname: LPCWSTR): cint {.cdecl, raises: [].}

  EnvFastEntry = object
    ## One already-recorded variable name, upper-cased, stored FLAT and
    ## NUL-TERMINATED.
    ##
    ## Flat rather than a `string` because this table is read from the
    ## trampoline on every environment lookup, and a `string` field would be a
    ## heap allocation to compare against and a refcounted object to race on.
    ##
    ## NUL-terminated rather than length-prefixed because it makes the
    ## comparison SELF-SUFFICIENT. An earlier version carried a `len` and
    ## compared `len` first, then the bytes -- and mutation testing showed the
    ## length check was doing no work that the byte comparison could not do
    ## itself, while being one more branch nothing could reach. Comparing
    ## through the terminator makes a strict PREFIX mismatch structurally
    ## (`"PATH"` cannot match `"PATHEXT"`: at index 4 one has NUL and the other
    ## has 'E'), which is the only way the two could ever have differed.
    used: bool
    name: array[EnvFastNameMax + 1, char]
# --- Original function pointer storage -------------------------------------

var
  origCreateFileW: CreateFileWProc
  origCreateFileA: CreateFileAProc
  origReadFile: ReadFileProc
  origWriteFile: WriteFileProc
  origCloseHandle: CloseHandleProc
  origGetFileAttributesExW: GetFileAttributesExWProc
  origGetFileAttributesExA: GetFileAttributesExAProc
  origGetFileAttributesW: GetFileAttributesWProc
  origGetFileAttributesA: GetFileAttributesAProc
  origCreateProcessW: CreateProcessWProc
  origCreateProcessA: CreateProcessAProc
  origNtTerminateProcess: NtTerminateProcessProc
  # M73 Phase 5 — extended hook surface.
  origDeleteFileW: DeleteFileWProc
  origDeleteFileA: DeleteFileAProc
  origCreateDirectoryW: CreateDirectoryWProc
  origCreateDirectoryA: CreateDirectoryAProc
  origCopyFileW: CopyFileWProc
  origCopyFileA: CopyFileAProc
  origMoveFileExW: MoveFileExWProc
  origMoveFileExA: MoveFileExAProc
  origGetFileInformationByHandleEx: GetFileInformationByHandleExProc
  origSetCurrentDirectoryW: SetCurrentDirectoryWProc
  origSetCurrentDirectoryA: SetCurrentDirectoryAProc
  origNtCreateFile: NtCreateFileProc
  origNtQueryAttributesFile: NtQueryAttributesFileProc
  origNtQueryFullAttributesFile: NtQueryAttributesFileProc
  origNtQueryDirectoryFile: NtQueryDirectoryFileProc
  origNtQueryInformationByName: NtQueryInformationByNameProc
  origNtQueryDirectoryFileEx: NtQueryDirectoryFileExProc
  origFindFirstFileW: FindFirstFileWProc
  origFindFirstFileExW: FindFirstFileExWProc
  origFindNextFileW: FindNextFileWProc
  origFindClose: FindCloseProc
  origGetProcAddress: GetProcAddressProc
  # Resolved ntdll!NtQueryDirectoryFile address. Captured lazily on
  # the first GetProcAddress("NtQueryDirectoryFile") query so the
  # wrapper has the real function to forward to.
  realNtQueryDirectoryFile: NtQueryDirectoryFileProc
  # M5 — IPC-connect / external-content / non-determinism surface.
  origConnect: ConnectProc
  origWSAConnect: WSAConnectProc
  origCreateFileMappingW: CreateFileMappingWProc
  origCreateFileMappingA: CreateFileMappingAProc
  origOpenFileMappingW: OpenFileMappingWProc
  origOpenFileMappingA: OpenFileMappingAProc
  origMapViewOfFile: MapViewOfFileProc
  origMapViewOfFileEx: MapViewOfFileExProc
  origCreatePipe: CreatePipeProc
  origBCryptGenRandom: BCryptGenRandomProc
  origProcessPrng: ProcessPrngProc
  origSystemFunction036: SystemFunction036Proc
  origCryptGenRandom: CryptGenRandomProc
  origQueryPerformanceCounter: QueryPerformanceCounterProc
  origGetSystemTimeAsFileTime: GetSystemTimeAsFileTimeProc
  origGetTickCount64: GetTickCount64Proc
  # M10 — observed environment. Win32 side, then one set per CRT: the two
  # runtimes are distinct modules with distinct snapshots in the same
  # process, so a single pointer could not serve both.
  origGetEnvironmentVariableW: GetEnvironmentVariableWProc
  origGetEnvironmentVariableA: GetEnvironmentVariableAProc
  origGetEnvironmentStringsW: GetEnvironmentStringsWProc
  origGetEnvironmentStringsA: GetEnvironmentStringsAProc
  origGetEnvironmentStrings: GetEnvironmentStringsAProc
  origUcrtGetenv: CrtGetenvProc
  origUcrtWGetenv: CrtWGetenvProc
  origUcrtGetenvS: CrtGetenvSProc
  origUcrtWGetenvS: CrtWGetenvSProc
  origUcrtDupenvS: CrtDupenvSProc
  origUcrtWDupenvS: CrtWDupenvSProc
  origMsvcrtGetenv: CrtGetenvProc
  origMsvcrtWGetenv: CrtWGetenvProc
  origMsvcrtGetenvS: CrtGetenvSProc
  origMsvcrtWGetenvS: CrtWGetenvSProc

# --- Runtime state ---------------------------------------------------------

var
  initialized = false
  locksReady = false
  initLockVar: Lock
  recordLock: Lock
  fdLock: Lock
  fragmentDir: string
  nextProcessSeq: uint64 = 0
  handlePaths = initTable[uint64, string]()
  # Grandchild injection: cache of our own DLL path (UTF-16, NUL-terminated)
  # populated lazily on the first CreateProcessW dispatch. Used as the
  # ``LoadLibraryW`` argument when re-injecting into spawned children.
  selfDllPathW: seq[uint16] = @[]
  selfDllPathReady: bool = false
  # M5 — external content: the source file behind a file-backed section, so a
  # `MapViewOfFile` can be recorded as a READ of that file. A mapped view is
  # the one content channel on Windows that NEVER passes ReadFile, so without
  # this the bytes a compiler mmaps out of a header or an archive are invisible
  # to a capture that nonetheless grades complete.
  mappingPaths = initTable[uint64, string]()
  # M5 — handles whose channel class has already been decided, so the
  # GetFileType/FileNameInfo probe on the ReadFile path runs once per handle
  # instead of once per read.
  channelClassified = initTable[uint64, bool]()
  # KNOWN RESIDUAL for both tables above (and for `handlePaths`): they are
  # pruned ONLY from the `CloseHandle` snoop. `NtClose` is not hooked, so a
  # handle closed through the NT export leaves its entry behind. The cost is
  # bounded per handle (one path string, one flag) but UNBOUNDED over the life
  # of a long-lived process that closes handles that way -- and a recycled
  # handle value could then read a stale mapping->file association, which is
  # why `forgetMappingPath` exists at all. Not fixed here: hooking `NtClose`
  # puts a detour on one of the hottest exports in the process, and the
  # measurement that would justify it has not been made.
  # M5 — non-determinism: per-source, per-caller-origin "already recorded"
  # flags. Entropy and clock entry points are called at a rate that makes a
  # per-call record both useless (the evidence is "this program consumed
  # randomness", not how often) and expensive, so each source is recorded ONCE
  # per process and every later call takes a fast path that skips the registry
  # dispatch entirely.
  ndTimeSeen: array[3, bool]
  ndEntropySeen: array[8, bool]   ## [source * 2 + (1 if caller in program)]
  # M10 — observed environment: the DISTINCT variable names this process has
  # already recorded, upper-cased. Upper-cased because Windows environment
  # lookup is case-INSENSITIVE: `getenv("path")` and `GetEnvironmentVariableW
  # (L"PATH")` name one variable with one value, and keying the dedup on the
  # spelling would record it twice. The RECORD still carries the name as the
  # caller spelled it, matching how every other Windows record keeps the
  # caller's spelling.
  #
  # A per-name dedup rather than the per-source flag the entropy hooks use:
  # the evidence a consumer needs here is WHICH variables were read (it folds
  # each one's value into the cache key), so collapsing to "some variable was
  # read" would make the capability useless. It is bounded and cleared
  # wholesale at the cap, exactly as the macOS arm's `seenObservedInputs` is.
  seenEnvNames = initTable[string, bool]()
  envLock: Lock
  # The ALLOCATION-FREE mirror of `seenEnvNames`, consulted by the trampoline
  # before it builds a hook context. See `envFastSeen` for why this exists and
  # why it is EXACT rather than a hash filter.
  envFast: array[EnvFastSlots, EnvFastEntry]
  # Whether the whole-block APIs have already been handled, per
  # [api * 2 + (1 if the caller is the main image)] -- the same shape as
  # `ndEntropySeen`, and for the same reason: it lets the trampoline take a
  # fast path that never builds a hook context.
  envBlockSeen: array[6, bool]
  # Bounds of the monitored program's OWN main image, for caller attribution.
  mainImageLo: uint = 0
  mainImageHi: uint = 0

when defined(ioMonShimSpawnEscapeTest):
  # Fault injection for the two abnormal ways out of the CreateProcess snoop
  # hooks. The hooks force ``CREATE_SUSPENDED`` into every child's creation
  # flags so they can inject before the child runs, so "did this hook resume
  # the child on the path it actually took?" is a liveness property of a real
  # process -- but neither abnormal path can be reached from outside the
  # process: one depends on ``disabled``/``initialized`` flipping mid-hook (a
  # thread-local and a teardown race), the other on a raise from inside the
  # body that the hook's own ``except`` swallows. So the test needs a way to
  # ask for them, and ``REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE``
  # ("return" / "raise"), read once at init, is it.
  #
  # COMPILE-GATED, and it has to stay that way. Taking either escape means
  # the hook emits no spawn record and injects nothing, so the whole child
  # subtree goes unobserved -- and because the record that would have named
  # the child is the same one that is missing, the run still grades
  # ``mcComplete``. An env var with that effect in a SHIPPED monitor is a
  # way to obtain a clean-looking dependency set for a build whose real
  # inputs were never watched, available to anyone who can set a variable in
  # the build environment. The shim's value is that its evidence can be
  # trusted; a switch that silently voids the evidence must not exist in the
  # artefact anyone runs. Built only by
  # ``tests/windows/test_io_mon_windows_spawn_resume_invariant.nim``, into
  # ``build/test-bin/`` so it cannot be mistaken for, or packaged next to,
  # the real shim in ``build/lib/``.
  type
    TestSpawnEscape = enum
      tseNone
      tseEarlyReturn  ## leave through the post-CreateProcess early `return`
      tseRaise        ## leave through the swallowing `except CatchableError`

  var testSpawnEscape: TestSpawnEscape = tseNone

var disabled {.threadvar.}: int

template withShimMuted(body: untyped) =
  inc disabled
  try:
    body
  except CatchableError:
    discard
  dec disabled

# --- Helpers ---------------------------------------------------------------

proc CreateFileARaw(lpFileName: cstring, dwDesiredAccess: DWORD,
                     dwShareMode: DWORD,
                     lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                     dwCreationDisposition: DWORD,
                     dwFlagsAndAttributes: DWORD,
                     hTemplateFile: HANDLE): HANDLE
  {.importc: "CreateFileA", stdcall, dynlib: "kernel32".}
proc SetFilePointer(hFile: HANDLE, lDistanceToMove: int32,
                     lpDistanceToMoveHigh: ptr int32, dwMoveMethod: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc WriteFileRaw(hFile: HANDLE, lpBuffer: LPCVOID,
                   nNumberOfBytesToWrite: DWORD,
                   lpNumberOfBytesWritten: ptr DWORD,
                   lpOverlapped: LPOVERLAPPED): BOOL
  {.importc: "WriteFile", stdcall, dynlib: "kernel32".}
proc CloseHandleRaw(hObject: HANDLE): BOOL
  {.importc: "CloseHandle", stdcall, dynlib: "kernel32".}

proc dbg(msg: cstring) =
  OutputDebugStringA(msg)
  # Windows: also append to a fixed-path log so we can debug injection from
  # outside the process. Controlled by the REPRO_MONITOR_SHIM_DEBUG_LOG env
  # variable. We MUST use the raw kernel32 APIs (which themselves get hooked
  # for the IATs of *other* modules, but not of our own DLL via the loader-
  # critical module skip in windows_iat_patcher.nim) so no recursion occurs.
  var logBuf: array[1024, char]
  let n = GetEnvironmentVariableA("REPRO_MONITOR_SHIM_DEBUG_LOG",
                                  cast[cstring](addr logBuf[0]),
                                  DWORD(logBuf.len))
  if n == 0 or n >= DWORD(logBuf.len):
    return
  logBuf[int(n)] = '\0'
  const OPEN_ALWAYS = 4'u32
  const FILE_APPEND_DATA = 0x4'u32
  const FILE_SHARE_READ = 0x1'u32
  const FILE_SHARE_WRITE = 0x2'u32
  const FILE_END = 2'u32
  let h = CreateFileARaw(cast[cstring](addr logBuf[0]),
    FILE_APPEND_DATA,
    FILE_SHARE_READ or FILE_SHARE_WRITE,
    nil, OPEN_ALWAYS, 0'u32, nil)
  if h == nil:
    return
  if cast[uint](h) == high(uint):  # INVALID_HANDLE_VALUE
    return
  discard SetFilePointer(h, 0, nil, FILE_END)
  var written: DWORD = 0
  var msgLen: int32 = 0
  while msg[msgLen] != '\0':
    inc msgLen
  discard WriteFileRaw(h, msg, DWORD(msgLen), addr written, nil)
  discard CloseHandleRaw(h)

proc widePtrToString(ws: LPCWSTR): string =
  ## Convert a NUL-terminated UTF-16 path to UTF-8 string.
  if ws == nil:
    return ""
  let wlen = lstrlenW(ws)
  if wlen <= 0:
    return ""
  let needed = WideCharToMultiByte(65001'u32, 0'u32, ws, wlen,
                                   nil, 0'i32, nil, nil)
  if needed <= 0:
    return ""
  result = newString(needed)
  discard WideCharToMultiByte(65001'u32, 0'u32, ws, wlen,
                              cast[LPSTR](addr result[0]), needed, nil, nil)

proc unicodeStringToString(uniPtr: pointer): string =
  ## Extract a Nim string from a Windows UNICODE_STRING.
  ## Layout (x64): USHORT Length; USHORT MaxLen; PWSTR Buffer (offset 8).
  if uniPtr == nil:
    return ""
  let lengthBytes = cast[ptr uint16](uniPtr)[]
  if lengthBytes == 0:
    return ""
  let bufferPtr = cast[ptr ptr uint16](
    cast[ByteAddress](uniPtr) + 8)[]
  if bufferPtr == nil:
    return ""
  let codeUnits = int32(lengthBytes div 2)
  let needed = WideCharToMultiByte(65001'u32, 0'u32,
    cast[LPCWSTR](bufferPtr), codeUnits, nil, 0'i32, nil, nil)
  if needed <= 0:
    return ""
  result = newString(needed)
  discard WideCharToMultiByte(65001'u32, 0'u32,
    cast[LPCWSTR](bufferPtr), codeUnits,
    cast[LPSTR](addr result[0]), needed, nil, nil)

proc objectAttributesRawName(oaPtr: pointer): string =
  ## The ObjectName of a Windows OBJECT_ATTRIBUTES, EXACTLY as the caller
  ## supplied it (field at offset 16 on x64).
  ##
  ## Kept separate from the prefix-stripped form because the two cannot be
  ## told apart afterwards and the difference decides whether a path is an IPC
  ## peer. `NtCreateFile` accepts a name RELATIVE to `RootDirectory`, so an
  ## ordinary open of `pipe\x.txt` from a directory containing `pipe` arrives
  ## with ObjectName `pipe\x.txt` -- byte-for-byte what `\??\pipe\x` becomes
  ## once the NT prefix is stripped. Classifying on the stripped form would
  ## report that file open as a connection to an unknown peer and downgrade
  ## the capture over it.
  if oaPtr == nil:
    return ""
  let objectName = cast[ptr pointer](
    cast[ByteAddress](oaPtr) + 16)[]
  if objectName == nil:
    return ""
  unicodeStringToString(objectName)

proc objectAttributesToString(oaPtr: pointer): string =
  ## Extract the path from a Windows OBJECT_ATTRIBUTES.
  ## ObjectName field at offset 16 (x64). Strips NT-style prefixes
  ## (\??\, \DosDevices\) so downstream record consumers see the same
  ## form GetFileAttributesExW records.
  let raw = objectAttributesRawName(oaPtr)
  if raw.len >= 4 and raw[0 .. 3] == "\\??\\":
    return raw[4 .. ^1]
  if raw.len >= 12 and raw[0 .. 11] == "\\DosDevices\\":
    return raw[12 .. ^1]
  raw

proc handleKey(h: HANDLE): uint64 {.inline.} =
  cast[uint64](h)

proc rememberHandlePath(h: HANDLE, path: string) =
  if h == nil or h == INVALID_HANDLE_VALUE or path.len == 0:
    return
  acquire(fdLock)
  handlePaths[handleKey(h)] = path
  release(fdLock)

proc forgetHandlePath(h: HANDLE) =
  if h == nil or h == INVALID_HANDLE_VALUE:
    return
  acquire(fdLock)
  handlePaths.del(handleKey(h))
  release(fdLock)

proc pathForHandle(h: HANDLE): string =
  if h == nil or h == INVALID_HANDLE_VALUE:
    return ""
  acquire(fdLock)
  result = handlePaths.getOrDefault(handleKey(h), "")
  release(fdLock)

proc processSeq(): uint64 =
  acquire(recordLock)
  inc nextProcessSeq
  result = nextProcessSeq
  release(recordLock)

proc currentParentOsPid(): uint64 =
  ## Windows: parent pid lookup is non-trivial (requires NtQueryInformationProcess
  ## or toolhelp snapshot). For the monitor depfile we set parent to 0 — the
  ## fragment merge already groups by osPid so parentless leaves are fine.
  0'u64

proc baseRecord(kind: MonitorRecordKind;
                observationKind: MonitorObservationKind): MonitorRecord =
  MonitorRecord(
    kind: kind,
    observationKind: observationKind,
    seq: processSeq(),
    osPid: uint64(GetCurrentProcessId()),
    parentOsPid: currentParentOsPid(),
    threadId: uint64(GetCurrentThreadId()),
    probeResult: prUnknown)

# ---------------------------------------------------------------------------
# THREAD-EXIT FLUSH -- the Windows half of DEP-FLUSH-3
# ---------------------------------------------------------------------------
#
# Each recording thread owns a `fragmentSlot` THREADVAR and registers its
# ADDRESS in a process-global registry, so a process-exit sweep can reach
# every thread's buffered tail. On Linux a `pthread_key_create` destructor
# flushes and UNREGISTERS a thread's slot when that thread exits, which is
# what makes the registry safe to walk: `flushAllRegisteredSlots` says in as
# many words that "a slot whose owning thread already exited ... is no longer
# registered".
#
# On Windows there was no such destructor, so that sentence was FALSE HERE.
# An exited thread's entry kept pointing into TLS the OS had already freed,
# and the first sweep to walk it read a `File` out of released memory and
# took the process down mid-exit. MEASURED: an injected `grep.exe` whose
# injector init thread had exited entered the sweep with `batchLen=917` and
# never came out of it -- no completion, no exception, nothing after that
# line.
#
# `FlsAlloc` is the Windows equivalent and works for foreign threads (the
# Cygwin main thread, a CRT worker, the injector's remote init thread), which
# `DllMain(DLL_THREAD_DETACH)` would also do but only for a DLL that owns its
# entry point. The slot value is arbitrary and non-NULL: it exists purely so
# the OS calls the destructor for this thread.

var
  fragmentFlsIndex {.global.}: Atomic[uint32]
    ## `FlsAlloc` index + 1, so zero means "not allocated". Set once at init.
  threadExitFlushArmed {.threadvar.}: bool

proc fragmentSlotThreadExit(p: pointer) {.stdcall.} =
  ## Runs ON THE EXITING THREAD, before its TLS is released.
  discard p
  try:
    threadExitFlushSlot()
  except CatchableError, IOError, OSError:
    discard

proc armThreadExitFlush() {.inline, raises: [].} =
  ## Give THIS thread a thread-exit flush. One `FlsSetValue` per thread, then
  ## a threadvar test on every later record.
  if threadExitFlushArmed:
    return
  let idx = fragmentFlsIndex.load()
  if idx == 0:
    return
  threadExitFlushArmed = true
  discard FlsSetValue(idx - 1, cast[pointer](1))

proc emitRecord(record: MonitorRecord) {.raises: [].} =
  if not initialized or fragmentDir.len == 0 or disabled > 0:
    return
  armThreadExitFlush()
  withShimMuted:
    try:
      appendFragmentRecord(fragmentDir, record)
    except CatchableError:
      discard

proc emitLibraryLoad(path: string) {.raises: [].} =
  ## Record a mapped image as a content dependency.
  ##
  ## `observationKind = moFileRead` on purpose, matching the macOS and Linux
  ## arms: an existing read-dependency consumer then fingerprints the DLL's
  ## BYTES, which is what closes the stale-cache hole. An in-place upgrade of
  ## a toolchain DLL behind an unchanged path must invalidate a cached action,
  ## and it can only do that if the bytes were recorded as an input. The
  ## distinct `mrLibraryLoad` kind keeps the observation identifiable for
  ## inspection without changing how it is consumed.
  if path.len == 0:
    return
  var record = baseRecord(mrLibraryLoad, moFileRead)
  record.path = path
  record.detail = "library-load"
  emitRecord(record)

proc emitAlreadyLoadedModules() {.raises: [].} =
  ## Emit a record for every image already mapped when the shim initialises.
  ##
  ## Needed because the loader notification only reports images mapped AFTER
  ## registration, and by then the process's entire static import closure --
  ## typically the majority of what it will ever load, and all of the
  ## toolchain DLLs that matter for cache invalidation -- is already in.
  var mods: array[1024, HANDLE]
  var needed: DWORD = 0
  if EnumProcessModulesEx(GetCurrentProcess(),
      cast[ptr pointer](addr mods[0]), DWORD(sizeof(mods)), addr needed,
      0x3'u32) == 0:
    return
  let count = min(int(needed) div sizeof(HANDLE), mods.len)
  for i in 0 ..< count:
    var buf: array[32768, uint16]
    let n = GetModuleFileNameW(mods[i], cast[LPWSTR](addr buf[0]),
      DWORD(buf.len))
    if n == 0:
      continue
    var path = newStringOfCap(int(n))
    for j in 0 ..< int(n):
      path.add(chr(int(buf[j]) and 0xFF))
    emitLibraryLoad(path)

proc dllNotificationCallback(reason: uint32;
                             data: ptr LdrDllNotificationData;
                             context: pointer) {.stdcall, raises: [].} =
  ## Loader callback for images mapped after initialisation (the LoadLibrary /
  ## delay-load / COM-activation arm).
  ##
  ## SAFETY: this runs with the loader lock held. `emitRecord` appends through
  ## kernel32 entry points the shim has already resolved, and runs under
  ## `withShimMuted`, so it neither re-enters our own hooks nor triggers a
  ## fresh image load that would re-enter the loader. This mirrors the macOS
  ## arm, which records from inside dyld's add-image callback under dyld's
  ## loader lock for the same reason: the loader is the only party that sees
  ## every load.
  discard context
  if reason != LDR_DLL_NOTIFICATION_REASON_LOADED:
    return
  if data == nil or data.FullDllName == nil or data.FullDllName.Buffer == nil:
    return
  let chars = int(data.FullDllName.Length) div 2
  if chars <= 0:
    return
  var path = newStringOfCap(chars)
  let buf = cast[ptr UncheckedArray[uint16]](data.FullDllName.Buffer)
  for i in 0 ..< chars:
    path.add(chr(int(buf[i]) and 0xFF))
  emitLibraryLoad(path)

var dllNotificationCookie: pointer = nil

proc registerDllNotification() {.raises: [].} =
  ## Subscribe to loader notifications. Failure is not fatal but it IS a
  ## capability loss: without it, images mapped after init go unobserved while
  ## the profile advertises library-load coverage. The caller reports that.
  # Built inline as UTF-16 for the same reason the injector's kernel32 lookup
  # is: this runs before any convenience helper is safe to rely on, and the
  # name is pure ASCII.
  var ntdllName = [uint16(ord('n')), uint16(ord('t')), uint16(ord('d')),
    uint16(ord('l')), uint16(ord('l')), uint16(ord('.')),
    uint16(ord('d')), uint16(ord('l')), uint16(ord('l')), 0'u16]
  let ntdll = GetModuleHandleW(cast[LPCWSTR](addr ntdllName[0]))
  if ntdll == nil:
    return
  let fn = cast[LdrRegisterDllNotificationFn](
    GetProcAddress(ntdll, "LdrRegisterDllNotification"))
  if fn == nil:
    return
  discard fn(0'u32, dllNotificationCallback, nil, addr dllNotificationCookie)

proc observationForCreateFile(desiredAccess, creationDisposition: DWORD):
    MonitorObservationKind =
  # Windows: classify as write if GENERIC_WRITE bit is set or the disposition
  # creates/truncates the file. Otherwise treat as a plain open.
  if (desiredAccess and GENERIC_WRITE) != 0 or
      creationDisposition == CREATE_ALWAYS or
      creationDisposition == CREATE_NEW or
      creationDisposition == OPEN_ALWAYS or
      creationDisposition == TRUNCATE_EXISTING:
    moFileWrite
  else:
    moFileOpen

proc probeFromBool(callResult: BOOL): ProbeResult =
  if callResult != 0:
    prExistingOther
  else:
    prAbsent

# ---------------------------------------------------------------------------
# M5 — IPC-connect, external-content and non-determinism helpers
# ---------------------------------------------------------------------------

proc initMainImageRange() {.raises: [].} =
  ## Cache [base, base+SizeOfImage) of the process's main executable.
  ##
  ## Used to attribute an entropy call to the monitored PROGRAM rather than to
  ## the CRT or the loader. Parsed from the PE header rather than asked of the
  ## loader per call because it sits on a hot path: `SizeOfImage` is at offset
  ## 56 of the optional header in BOTH PE32 and PE32+ (the 32-bit-only
  ## `BaseOfData` field and the widened `ImageBase` cancel out), so one
  ## expression covers both bitnesses.
  let base = GetModuleHandleW(nil)
  if base == nil:
    return
  let b = cast[uint](base)
  if cast[ptr uint16](b)[] != 0x5A4D'u16:        # 'MZ'
    return
  let lfanew = cast[ptr uint32](b + 0x3C'u)[]
  if lfanew == 0'u32 or lfanew > 0x1000'u32:
    return
  let nt = b + uint(lfanew)
  if cast[ptr uint32](nt)[] != 0x00004550'u32:   # 'PE\0\0'
    return
  let sizeOfImage = cast[ptr uint32](nt + 24'u + 56'u)[]
  if sizeOfImage == 0'u32:
    return
  mainImageLo = b
  mainImageHi = b + uint(sizeOfImage)

proc callerInProgram(retAddr: pointer): bool {.inline, raises: [].} =
  ## True when `retAddr` lies inside the MAIN EXECUTABLE IMAGE.
  ##
  ## READ THE NAME LITERALLY. The test is `retAddr in [mainImageBase,
  ## +SizeOfImage)`, which is "main EXE image vs everything else", NOT "program
  ## vs system". Both directions are lossy and neither is a rounding error:
  ##
  ##   * A program whose randomness arrives through a BUNDLED DLL -- libcrypto,
  ##     a compiler plugin, a Python native extension, any interpreter host --
  ##     reports `caller=system`, indistinguishable from ntdll's baseline. The
  ##     per-(source, origin) dedup then collapses even the count, so there is
  ##     no residual signal to notice it by.
  ##   * With a STATICALLY LINKED mingw CRT the CRT's own startup randomness
  ##     sits inside the main image and reports `caller=program`.
  ##
  ## CONSEQUENCE FOR A CONSUMER (M6's entropy blessing): `caller=program` may be
  ## treated as "definitely the main image", but `caller=system` must NOT be
  ## treated as "no program randomness". Doing so would grade an unblessed
  ## program deterministic when its randomness came through its own DLL --
  ## precisely the false-complete this machinery exists to prevent.
  ##
  ## The unknown-range case below returns false, which is safe only under the
  ## first reading and NOT under the second: it under-reports the main image,
  ## and a consumer that reads `caller=system` as "no program randomness" turns
  ## that under-report into a false blessing. This is stated here rather than
  ## claimed as a fail-closed property, because it is not one.
  if mainImageHi == 0'u or retAddr == nil:
    return false
  let a = cast[uint](retAddr)
  a >= mainImageLo and a < mainImageHi

proc normalizedPathKey(path: string): string {.raises: [].} =
  ## Lowercased, forward-slashes-folded copy, for prefix tests only.
  result = newStringOfCap(path.len)
  for c in path:
    if c == '/':
      result.add('\\')
    elif c >= 'A' and c <= 'Z':
      result.add(chr(ord(c) + 32))
    else:
      result.add(c)

proc isNamedPipePath(path: string): bool {.raises: [].} =
  ## True for a named-pipe CLIENT path.
  ##
  ## A Windows pipe client does not call a socket API at all -- it OPENS
  ## `\\.\pipe\<name>`, which the shim's CreateFileW/A and NtCreateFile hooks
  ## already see. So the named-pipe arm of `mcapIpcConnect` is a
  ## CLASSIFICATION of paths those hooks already carry, not a new entry point.
  ##
  ## Every accepted spelling is ANCHORED, never found by searching for `\pipe\`
  ## anywhere in the path, and the caller must pass the path as the program
  ## SPELLED it (for the NT layer, `objectAttributesRawName`, not the
  ## prefix-stripped form). Both restrictions exist for one reason: an
  ## unknown-peer IPC record DOWNGRADES the capture, so a rule that fired on an
  ## ordinary path would make every build with a `pipe` directory a permanent
  ## conservative re-run -- a false re-run produced by the machinery that
  ## exists to prevent false completes.
  ##
  ## `C:\src\pipe\x.c` is the obvious decoy. The one that actually gets through
  ## is the RELATIVE `pipe\x.c`: it is byte-for-byte the `\??\pipe\<name>` NT
  ## form after the prefix strip, and NtCreateFile really does receive it that
  ## way, because a relative Win32 open reaches the NT layer as an ObjectName
  ## relative to `RootDirectory` rather than canonicalised.
  if path.len < 6:
    return false
  let n = normalizedPathKey(path)
  if n.startsWith("\\device\\namedpipe"):
    return true
  if n.startsWith("\\??\\pipe\\"):
    return true
  if n.len > 2 and n[0] == '\\' and n[1] == '\\':
    let hostEnd = n.find('\\', 2)
    if hostEnd > 2 and n.len >= hostEnd + 6 and
        n[hostEnd + 1 .. hostEnd + 5] == "pipe\\":
      return true
  false

proc adsStreamOf(path: string): string {.raises: [].} =
  ## Return the `:stream[:type]` suffix of an NTFS alternate-data-stream path,
  ## or "" when the path names no stream.
  ##
  ## `CreateFileW` already SEES `file:stream`; nothing classified it, so the
  ## channel was uncovered. The stream is part of the recorded path, so its
  ## bytes are fingerprinted by the ordinary read record -- this classification
  ## makes the channel identifiable, it is not what makes the content a
  ## dependency.
  var i = 0
  if path.len >= 4 and path[0] == '\\' and path[1] == '\\' and
      (path[2] == '?' or path[2] == '.') and path[3] == '\\':
    i = 4
  if path.len >= i + 2 and path[i + 1] == ':':
    i += 2                                   # skip the drive-letter colon
  while i < path.len:
    if path[i] == ':':
      return path[i .. ^1]
    inc i
  ""

proc namedPipeServerPid(h: HANDLE): uint64 {.raises: [].} =
  ## Pid of the process serving the pipe `h` was opened on; 0 when unknown.
  if h == nil or h == INVALID_HANDLE_VALUE:
    return 0'u64
  var pid: DWORD = 0
  if GetNamedPipeServerProcessId(h, addr pid) == 0:
    return 0'u64
  uint64(pid)

proc pipePairIdentity(h: HANDLE; otherPid: var uint64): string {.raises: [].} =
  ## A process-independent identity for an anonymous pipe, plus the pid on the
  ## OTHER end of it.
  ##
  ## The obvious key -- the kernel object's name -- does not exist. On Win11,
  ## `CreatePipe` makes an UNNAMED pipe pair: `GetFileInformationByHandleEx`
  ## with `FileNameInfo` succeeds with a zero-length name and
  ## `NtQueryObject(ObjectNameInformation)` answers
  ## `STATUS_OBJECT_PATH_INVALID`, so there is nothing to key on the way the
  ## POSIX arms key on `dev:ino` (measured on this host, not assumed).
  ##
  ## What the kernel WILL name is the pair of processes holding the two ends,
  ## and it names them consistently: `GetNamedPipeServerProcessId` and
  ## `GetNamedPipeClientProcessId` both answer on an anonymous pipe, from
  ## EITHER end, with the same two pids. `pipe:<server>:<client>` is therefore
  ## the same string in the producer and in the consumer -- which is exactly
  ## what the merge needs to pair an in-tree `create` against a later `read`.
  ##
  ## The pid pair also supplies the IM-4 producer identity directly: the end
  ## that is not us is the process on the other side.
  otherPid = 0'u64
  if h == nil or h == INVALID_HANDLE_VALUE:
    return ""
  var serverPid: DWORD = 0
  var clientPid: DWORD = 0
  if GetNamedPipeServerProcessId(h, addr serverPid) == 0:
    return ""
  if GetNamedPipeClientProcessId(h, addr clientPid) == 0:
    return ""
  let self = GetCurrentProcessId()
  otherPid = if serverPid == self: uint64(clientPid) else: uint64(serverPid)
  "pipe:" & $serverPid & ":" & $clientPid

proc sockaddrDestination(name: pointer; namelen: int32;
                         family: var uint16): string {.raises: [].} =
  ## Render a `sockaddr` as the destination string the merge keys on.
  ## Returns "" (and leaves `family` 0) for families that cannot carry a
  ## file-serving peer, so they are never recorded and never downgrade.
  family = 0'u16
  if name == nil or namelen < 4:
    return ""
  let fam = cast[ptr uint16](name)[]
  let bytes = cast[ptr UncheckedArray[byte]](name)
  case fam
  of AfInetW:
    if namelen < 8:
      return ""
    let port = (uint16(bytes[2]) shl 8) or uint16(bytes[3])
    family = fam
    return $bytes[4] & "." & $bytes[5] & "." & $bytes[6] & "." & $bytes[7] &
      ":" & $port
  of AfInet6W:
    if namelen < 24:
      return ""
    let port = (uint16(bytes[2]) shl 8) or uint16(bytes[3])
    family = fam
    var hex = ""
    for i in 0 ..< 8:
      if i > 0:
        hex.add ':'
      hex.add toHex(int((uint16(bytes[8 + i * 2]) shl 8) or
        uint16(bytes[9 + i * 2])), 4)
    return "[" & hex.toLowerAscii & "]:" & $port
  of AfUnixW:
    # Win10 1803+ supports AF_UNIX; the path is a NUL-terminated char[108].
    family = fam
    var p = ""
    var i = 2
    while i < namelen and i < 110 and bytes[i] != 0'u8:
      p.add chr(int(bytes[i]))
      inc i
    return p
  else:
    return ""

proc emitIpcConnect(dest: string; peerPid: uint64; family: uint16;
                    callResult: int64; kind: string) {.raises: [].} =
  ## Record a connection to a peer, with the peer's pid when the OS names one.
  ##
  ## This is what lets the merge (`writer.unmonitoredSubtreeLossCount` case (c))
  ## tell an in-tree process from an OUT-OF-TREE breakaway daemon. Without it a
  ## build tool could take its inputs from a persistent daemon -- an sccache
  ## server, a language server, a build daemon -- that opens and reads files on
  ## its behalf, and the capture would contain neither the reads nor any
  ## evidence that they happened, while grading complete.
  ##
  ## `childOsPid` carries the peer pid because that is the field the merge
  ## already reads for the macOS `LOCAL_PEERPID` arm; a Windows named pipe can
  ## fill it from `GetNamedPipeServerProcessId`, a socket generally cannot.
  ## NO `peerstart=` token is stamped: Windows `mrProcessStart` records carry no
  ## start-time token either, so an identity match would never succeed and would
  ## turn every in-tree peer into a false downgrade. The merge therefore falls
  ## back to bare-pid membership, which is exactly right for a record set whose
  ## process identities are bare pids. Residual, stated rather than papered
  ## over: a peer pid RECYCLED within one capture could match a stale monitored
  ## process, which fails toward mcComplete.
  if dest.len == 0:
    return
  var record = baseRecord(mrIpcConnect, moIpcConnect)
  record.result = callResult
  record.flags = uint32(family)
  record.childOsPid = peerPid
  record.path = dest
  record.detail = "connect " & kind &
    (if peerPid != 0'u64: " peer=" & $peerPid else: " peer=unknown")
  emitRecord(record)

proc emitExternalContent(chan, role, identity: string; producerPid: uint64;
                         callResult: int64) {.raises: [].} =
  ## Describe one side of a content channel.
  ##
  ## The provenance decision is deliberately NOT made here: whether a consume
  ## is an invisible input depends on whether some MONITORED process produced
  ## it, which only the cross-process merge can know. The shim states the facts
  ## (`chan=`/`role=`/identity/producer) and `writer.externalContentLossCount`
  ## pairs them -- the same division of labour as the macOS arm, and the reason
  ## an entirely in-tree pipeline does not downgrade.
  if identity.len == 0:
    return
  var record = baseRecord(mrExternalContent, moExternalContent)
  record.path = identity
  record.childOsPid = producerPid
  record.result = callResult
  record.detail = "chan=" & chan & " role=" & role
  emitRecord(record)

proc emitNonDeterministic(source: string; inProgram: bool) {.raises: [].} =
  ## Record that the process read from an entropy source.
  ##
  ## Evidence, not loss: `writer.nonDeterminismObservationCount` counts these
  ## and nothing downgrades on them, because io-mon DID observe the read. The
  ## caller decides what it means -- which is the half of the entropy-blessing
  ## design (M6) that did not exist on Windows at all before this.
  var record = baseRecord(mrNonDeterministic, moNonDeterministic)
  record.path = source
  record.detail = "entropy source=" & source &
    (if inProgram: " caller=program" else: " caller=system")
  emitRecord(record)

proc emitTimeRead(source: string) {.raises: [].} =
  ## Record that the process read a clock. Marker only -- almost every program
  ## times something, so downgrading on it would re-run everything.
  var record = baseRecord(mrTimeRead, moTimeRead)
  record.path = source
  record.detail = "time source=" & source
  emitRecord(record)

# ---------------------------------------------------------------------------
# M10 -- observed environment (mcapObservedEnv)
# ---------------------------------------------------------------------------
#
# THE CONTRACT, and it is deliberately the SAME one the POSIX arms implement,
# because consumers compare captures across platforms: an environment read is
# an OBSERVED DECLARED INPUT. `mrEnvRead`/`moEnvRead` carries the variable
# NAME in `path`; nothing downgrades on it; the CONSUMER folds that variable's
# VALUE (or its absence) into the action's cache key. That is BuildXL's
# observed-environment model, and it is what makes a build that reads
# SOURCE_DATE_EPOCH or CFLAGS re-run when the value changes and NOT re-run
# when it does not.
#
# It is also the only Windows capability whose absence could produce a false
# `mcComplete` over an unseen INPUT: a build reads a variable, nothing records
# it, the capture grades complete, and the action cache serves a stale result
# the next time the variable changes. Every other Windows gap costs detail.

const
  # The shim's / engine's OWN control variables are NOT build inputs. They are
  # set per-run (a session id, a fragment directory under a temp path), so
  # folding them into a consumer's cache key would change the key on EVERY
  # run -- a monitor that makes every action uncacheable, which is the
  # cardinal sin arriving through the consumer instead of through a missed
  # read. The macOS arm denylists the same class (`ObservedEnvDenylistPrefixes`
  # there); this list is its Windows counterpart, with the POSIX-only injection
  # variable replaced by nothing, because Windows injects by
  # `CreateRemoteThread` and has no `DYLD_INSERT_LIBRARIES` analogue to leak.
  ObservedEnvDenylistPrefixes = [
    "REPRO_MONITOR_", "IO_MON_", "CT_SANDBOX_TOOLS_DIR"]
  ObservedEnvCacheCap = 4096
    ## Bound on the dedup set. Cleared wholesale at the cap, like the macOS
    ## arm: past a few thousand DISTINCT names a process is generating names
    ## rather than reading configuration, and the cost of remembering them is
    ## worse than re-recording a repeat.

proc envDedupKey(name: string): string {.raises: [].} =
  ## Upper-case ASCII fold. Windows environment lookup is case-insensitive, so
  ## `Path` and `PATH` are ONE variable and must dedup to one record.
  result = newStringOfCap(name.len)
  for c in name:
    if c >= 'a' and c <= 'z':
      result.add(chr(ord(c) - 32))
    else:
      result.add(c)

proc isDenylistedEnvName(name: string): bool {.raises: [].} =
  let key = envDedupKey(name)
  for prefix in ObservedEnvDenylistPrefixes:
    if key.startsWith(prefix):
      return true
  false

# --- The trampoline-side dedup ---------------------------------------------
#
# WHY THIS EXISTS. `getenv` is called at a rate no file API approaches: a build
# re-reads PATH and its toolchain variables thousands of times per process, and
# a shell's configure loop can do hundreds of thousands. Measured on this host,
# routing every one of those through the registry -- a per-call `seq`
# allocation for the hook context, a string-keyed chain lookup, then a Nim
# string built from the caller's pointer -- cost 1.5 us per call, which is
# 75 ms per 50 000 reads and 17 % on a monitored `cmd /c ver`.
#
# The entropy and clock trampolines solve the same problem with a boolean per
# source, but they can: their "source" is a fixed entry point. Here the source
# is a variable NAME, known only once the argument has been read.
#
# WHY IT IS EXACT AND NOT A HASH FILTER. The obvious cheap version stores
# 64-bit hashes and skips on a hit. A hash COLLISION would then silently drop
# the first read of a real variable -- an input missing from a capture that
# still grades `mcComplete`, which is precisely the failure this whole
# capability exists to prevent. Improbable is not the same as impossible, and
# "improbable" is not a property a correctness claim can rest on. So the table
# stores the NAMES and compares them, and the hash is only used to pick a slot.
#
# The two ways a name can miss the fast path -- longer than `EnvFastNameMax`,
# or its probe window full -- both fail SAFE: the call takes the slow path,
# which records or dedups correctly and merely costs what it cost before.

proc envFastHash(buf: array[EnvFastNameMax + 1, char]; n: int32): uint64
    {.inline, raises: [].} =
  ## FNV-1a over the upper-cased name. Used only to pick a slot.
  result = 0xcbf29ce484222325'u64
  for i in 0 ..< int(n):
    result = result xor uint64(uint8(buf[i]))
    result = result * 0x100000001b3'u64

proc envFastKeyFromCstr(p: LPCSTR;
                        buf: var array[EnvFastNameMax + 1, char]): int32
    {.raises: [].} =
  ## Upper-case ASCII copy of a NUL-terminated narrow name into `buf`.
  ## Returns -1 when the name cannot be keyed (nil, empty, or too long), which
  ## sends the caller to the slow path.
  if p == nil:
    return -1
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < EnvFastNameMax:
    let c = src[i]
    if c == '\0':
      return (if i == 0: -1'i32 else: int32(i))
    buf[i] = (if c >= 'a' and c <= 'z': chr(ord(c) - 32) else: c)
    inc i
  -1

proc envFastKeyFromWide(p: LPCWSTR;
                        buf: var array[EnvFastNameMax + 1, char]): int32
    {.raises: [].} =
  ## The same for a UTF-16 name. A non-ASCII code unit returns -1 rather than
  ## being folded: the slow path handles it, and inventing a byte for it here
  ## could make two DIFFERENT names compare equal, which would drop a read.
  if p == nil:
    return -1
  let src = cast[ptr UncheckedArray[uint16]](p)
  var i = 0
  while i < EnvFastNameMax:
    let u = src[i]
    if u == 0'u16:
      return (if i == 0: -1'i32 else: int32(i))
    if u > 0x7F'u16:
      return -1
    let c = chr(int(u))
    buf[i] = (if c >= 'a' and c <= 'z': chr(ord(c) - 32) else: c)
    inc i
  -1

proc envFastLookupLocked(buf: array[EnvFastNameMax + 1, char]; n: int32): int
    {.raises: [].} =
  ## Slot index of `buf[0..<n]` if present, else -1. Caller holds `envLock`.
  ##
  ## The comparison runs THROUGH the terminator (`0 .. n`, not `0 ..< n`), so
  ## a stored name that merely starts with `buf` cannot match: at index `n` the
  ## probe has NUL and the stored name has its next character. That is what
  ## makes this lookup exact without a separate length field.
  if n <= 0:
    return -1
  var idx = int(envFastHash(buf, n) and uint64(EnvFastSlots - 1))
  for _ in 0 ..< EnvFastProbe:
    if not envFast[idx].used:
      return -1
    var same = true
    for i in 0 .. int(n):
      if envFast[idx].name[i] != buf[i]:
        same = false
        break
    if same:
      return idx
    idx = (idx + 1) and (EnvFastSlots - 1)
  -1

proc envFastInsertLocked(buf: array[EnvFastNameMax + 1, char]; n: int32)
    {.raises: [].} =
  ## Caller holds `envLock`. A full probe window is simply not inserted: the
  ## name then always takes the slow path, which is correct and only slower.
  if n <= 0:
    return
  var idx = int(envFastHash(buf, n) and uint64(EnvFastSlots - 1))
  for _ in 0 ..< EnvFastProbe:
    if not envFast[idx].used:
      # Copy the terminator too. A slot reused after a wholesale clear would
      # otherwise keep a longer previous name's bytes past `n`, and the
      # through-the-terminator comparison above would read one of them.
      for i in 0 .. int(n):
        envFast[idx].name[i] = buf[i]
      envFast[idx].used = true
      return
    idx = (idx + 1) and (EnvFastSlots - 1)

proc envFastClearLocked() {.raises: [].} =
  for i in 0 ..< EnvFastSlots:
    envFast[i].used = false

proc envFastSeenCstr(p: LPCSTR): bool {.raises: [].} =
  ## Has this narrow name already been recorded? Takes `envLock`, which is a
  ## few tens of nanoseconds uncontended -- two orders below the hook-context
  ## allocation it saves.
  ##
  ## The buffer is zero-initialised by Nim, so `buf[n]` is the NUL the
  ## comparison in `envFastLookupLocked` relies on.
  var buf: array[EnvFastNameMax + 1, char]
  let n = envFastKeyFromCstr(p, buf)
  if n <= 0:
    return false
  acquire(envLock)
  result = envFastLookupLocked(buf, n) >= 0
  release(envLock)

proc envFastSeenWide(p: LPCWSTR): bool {.raises: [].} =
  var buf: array[EnvFastNameMax + 1, char]
  let n = envFastKeyFromWide(p, buf)
  if n <= 0:
    return false
  acquire(envLock)
  result = envFastLookupLocked(buf, n) >= 0
  release(envLock)

proc emitEnvRead(name, source, scope: string) {.raises: [].} =
  ## Record one environment variable as an observed declared input.
  ##
  ## `path` is the name AS THE CALLER SPELLED IT. `detail` names the entry
  ## point it came through and, for a name that arrived from a whole-block
  ## read, says `scope=block` -- so a consumer can tell "the program asked for
  ## this variable" from "the program read the entire block, and this variable
  ## was in it". Both are dependencies; only the first is evidence the program
  ## cared.
  if name.len == 0:
    return
  var record = baseRecord(mrEnvRead, moEnvRead)
  record.path = name
  record.detail = "env-read source=" & source & " scope=" & scope
  emitRecord(record)

proc recordEnvRead(name, source: string; scope = "name") {.raises: [].} =
  ## Dedup then emit. The dedup lookup is done OUTSIDE `emitRecord` so the
  ## emit's own muting cannot interfere with it, matching the macOS arm.
  if name.len == 0:
    return
  if not initialized or fragmentDir.len == 0 or disabled > 0:
    return
  if isDenylistedEnvName(name):
    return
  let key = envDedupKey(name)
  # The flat mirror is filled from the SAME critical section as the
  # authoritative table, so the two can never disagree about a name having
  # been recorded -- which is what lets the trampoline trust it.
  var fastBuf: array[EnvFastNameMax + 1, char]
  var fastLen = -1'i32
  if key.len <= EnvFastNameMax:
    var ok = true
    for i, c in key:
      if ord(c) > 0x7F:
        ok = false
        break
      fastBuf[i] = c
    if ok and key.len > 0:
      fastLen = int32(key.len)
  var fresh = false
  acquire(envLock)
  if not seenEnvNames.getOrDefault(key, false):
    if seenEnvNames.len >= ObservedEnvCacheCap:
      seenEnvNames.clear()
      envFastClearLocked()
    seenEnvNames[key] = true
    fresh = true
    envFastInsertLocked(fastBuf, fastLen)
  release(envLock)
  if not fresh:
    return
  emitEnvRead(name, source, scope)

proc recordEnvBlockRead(source: string) {.raises: [].} =
  ## A whole-block read: record EVERY variable in the block as an observed
  ## input.
  ##
  ## The alternative -- a single marker meaning "the whole environment is an
  ## input" -- would need a new token every consumer had to learn, and would
  ## be invisible to the per-name machinery the POSIX arms already feed. So
  ## the block is expanded into the SAME per-name records a named read
  ## produces, which means the denylist applies to it (the per-run control
  ## variables do not enter anybody's cache key) and a cross-platform consumer
  ## needs no Windows-specific case.
  ##
  ## It over-approximates on purpose: the program received all of these names
  ## and we cannot see which of them it went on to use. Over-approximating an
  ## input costs a re-run that was not needed; under-approximating it serves a
  ## stale result, and only one of those is a correctness bug.
  if not initialized or fragmentDir.len == 0 or disabled > 0:
    return
  var block0: LPWSTR = nil
  withShimMuted:
    block0 = GetEnvironmentStringsWRaw()
  if block0 == nil:
    return
  var names: seq[string] = @[]
  let p = cast[ptr UncheckedArray[uint16]](block0)
  # A hard bound on the walk. The block is double-NUL terminated and kernel32
  # produced it, so this cannot trip on a well-formed block; it is here so a
  # corrupted one costs a truncated record set rather than a walk off the end
  # of the mapping inside a hook the whole process is calling through.
  const MaxBlockCodeUnits = 1 shl 20
  var i = 0
  while i < MaxBlockCodeUnits:
    if p[i] == 0'u16:                      # empty entry ends the block
      break
    var entryLen = 0
    while i + entryLen < MaxBlockCodeUnits and p[i + entryLen] != 0'u16:
      inc entryLen
    # `=` at index 0 marks a hidden per-drive variable (`=C:`, `=ExitCode`).
    # They are process bookkeeping, not configuration, and Windows will not
    # let a program set them through the documented API -- recording them
    # would put the shell's last exit code into every cache key.
    var eq = -1
    for j in 1 ..< entryLen:
      if p[i + j] == uint16(ord('=')):
        eq = j
        break
    if eq > 0:
      var n = newStringOfCap(eq)
      for j in 0 ..< eq:
        # The names in the block are ASCII in every practical environment; a
        # non-ASCII code unit is folded to its low byte rather than dropped,
        # so the variable is still SEEN even if its name renders oddly.
        n.add(chr(int(p[i + j]) and 0xFF))
      names.add n
    i += entryLen + 1
  withShimMuted:
    discard FreeEnvironmentStringsW(block0)
  for n in names:
    recordEnvRead(n, source, "block")

proc rememberMappingPath(h: HANDLE; path: string) {.raises: [].} =
  if h == nil or h == INVALID_HANDLE_VALUE or path.len == 0:
    return
  acquire(fdLock)
  mappingPaths[handleKey(h)] = path
  release(fdLock)

proc pathForMapping(h: HANDLE): string {.raises: [].} =
  if h == nil or h == INVALID_HANDLE_VALUE:
    return ""
  acquire(fdLock)
  result = mappingPaths.getOrDefault(handleKey(h), "")
  release(fdLock)

proc forgetMappingPath(h: HANDLE) {.raises: [].} =
  if h == nil or h == INVALID_HANDLE_VALUE:
    return
  acquire(fdLock)
  mappingPaths.del(handleKey(h))
  release(fdLock)

proc markHandleChannelClassified(h: HANDLE): bool {.raises: [].} =
  ## Mark `h` as channel-classified and report whether it ALREADY was.
  if h == nil or h == INVALID_HANDLE_VALUE:
    return true
  acquire(fdLock)
  result = channelClassified.getOrDefault(handleKey(h), false)
  channelClassified[handleKey(h)] = true
  release(fdLock)

proc forgetHandleChannelClass(h: HANDLE) {.raises: [].} =
  if h == nil or h == INVALID_HANDLE_VALUE:
    return
  acquire(fdLock)
  channelClassified.del(handleKey(h))
  release(fdLock)

proc mayBeNamedPipe(path: string): bool {.inline, raises: [].} =
  ## Cheap pre-filter for `isNamedPipePath`, which allocates.
  ##
  ## Every open goes through here, so the full test must not run for an
  ## ordinary `C:\...` path. Every named-pipe spelling starts with a separator
  ## or with the bare `pipe\` the NT prefix strip leaves behind. This is a
  ## PERFORMANCE filter only -- correctness lives in `isNamedPipePath`, which
  ## must reject everything this lets through that is not a pipe.
  path.len >= 6 and (path[0] == '\\' or path[0] == '/' or
                     path[0] == 'p' or path[0] == 'P')

proc classifyOpenedPath(path: string; h: HANDLE; desiredAccess: DWORD;
                        spelledPath = "") {.raises: [].} =
  ## M5 — classify what an open actually reached, on top of the file record the
  ## caller already emitted.
  ##
  ## Only SUCCESSFUL opens are classified. A failed pipe open consumed nothing,
  ## and recording it as an IPC connect to an unknown peer would downgrade the
  ## capture over a connection that never happened -- a false re-run, which is
  ## the failure direction this machinery is supposed to avoid.
  if path.len == 0 or h == nil or h == INVALID_HANDLE_VALUE:
    return
  # The pipe test runs against the spelling the PROGRAM used, which the NT arm
  # supplies separately because the recorded path there has had its `\??\`
  # prefix stripped and is then indistinguishable from a relative path.
  let asSpelled = if spelledPath.len > 0: spelledPath else: path
  if mayBeNamedPipe(asSpelled) and isNamedPipePath(asSpelled):
    emitIpcConnect(path, namedPipeServerPid(h), 0'u16,
      int64(cast[int](h)), "named-pipe")
    return
  let stream = adsStreamOf(path)
  if stream.len > 0:
    let role = if (desiredAccess and GENERIC_WRITE) != 0: "write" else: "read"
    # `chan=ads` is deliberately NOT one of the roles
    # `writer.externalContentLossCount` downgrades on: the stream is part of
    # the path the read record already carries, so its bytes ARE fingerprinted.
    # What was missing was that the channel could not be identified at all.
    emitExternalContent("ads", role, path, 0'u64, 0'i64)

proc readEnvString(name: cstring): string =
  var buf: array[32768, char]
  let n = GetEnvironmentVariableA(name, cast[cstring](addr buf[0]),
                                  DWORD(buf.len))
  if n == 0 or n >= DWORD(buf.len):
    return ""
  result = newString(int(n))
  for i in 0 ..< int(n):
    result[i] = buf[i]

proc ensureFragmentDir() =
  if fragmentDir.len == 0:
    return
  try:
    createDir(extendedPath(fragmentDir))
  except OSError:
    discard
  except IOError:
    discard
  except ValueError:
    discard

proc recordProcessStart() =
  var record = baseRecord(mrProcessStart, moProcessStart)
  record.detail = "shim-loaded"
  emitRecord(record)
  # Flush immediately: this record is written from a thread that is about to
  # disappear.
  #
  # Fragment frames are batched per (osPid, threadId) and flushed on a key
  # change, an explicit flush, or a 100 ms age bound. On Windows the shim is
  # initialised by the injector via CreateRemoteThread -> repro_runtime_init,
  # so recordProcessStart runs on a remote thread whose ONLY record is this
  # one, and which then exits: no key change, no explicit flush, and gone long
  # before the age bound. The record was therefore lost for every injected
  # process -- which is every process, root and children alike.
  #
  # The consequence was not a missing diagnostic but an uncacheable build.
  # processStartIdentities builds its monitored-process set purely from
  # mrProcessStart records, so with none surviving, childIsMonitored answered
  # false for every spawn and the writer synthesised "spawn child missing
  # process-start" for children that were in fact fully monitored. That is an
  # unknown-scope loss, which makes the evidence mcIncomplete, which makes the
  # consumer skip action-cache publication for the entire session.
  # Same swallow-and-continue posture as emitRecord: a failed flush costs a
  # record, never the host process.
  withShimMuted:
    try:
      flushFragmentBatch()
    except CatchableError:
      discard

proc emitSpawnRecordDurably(record: MonitorRecord) =
  ## Emit an ``mrProcessSpawn`` record AND force it to disk immediately.
  ##
  ## THE RECORD THAT NAMES A SUBTREE MUST OUTLIVE THE PROCESS THAT NAMED IT.
  ## Fragment frames are batched per (osPid, threadId) and reach the file only
  ## on a key change, an explicit flush, or the 100 ms age bound. A spawn
  ## record is the ONLY evidence that a child existed: the merge pairs it
  ## against the child's ``mrProcessStart`` and, finding none, synthesises the
  ## "unmonitored subtree/peer" event-loss that grades the run
  ## unknown-scope-incomplete. Lose the spawn record and the loss it describes
  ## becomes SILENT -- the merge has nothing to fail to pair, and the run is
  ## graded on the reads that happened to survive.
  ##
  ## That is not hypothetical. An MSYS2/Cygwin ``sh -c "<one command>"`` execs
  ## within a few milliseconds of startup, and the Cygwin ``exec`` tears the
  ## calling process down without running our exit proc, so the whole batch
  ## -- spawn record included -- is lost inside the age bound. Measured on
  ## Git-for-Windows' ``sh.exe``: 42 records, not one of them the
  ## ``CreateProcessW`` that produced the ``bash`` that did all the work.
  ##
  ## `recordProcessStart` already flushes for the same reason, one record
  ## earlier in the same causal chain; this is the other half of that pair.
  ## Same swallow-and-continue posture: a failed flush costs a record, never
  ## the host process.
  emitRecord(record)
  withShimMuted:
    try:
      flushFragmentBatch()
    except CatchableError:
      discard

proc recordHookInstallLoss(unhooked: int; names: string) =
  ## Report entry points that landed no hook at all, so the run is graded on
  ## what was actually observable rather than on what happened to be emitted.
  ##
  ## Without this the failure is invisible in the only direction that matters.
  ## A child whose hooks did not install still emits its process-start (that
  ## record is written before the install pass), so it looks monitored: the
  ## merge finds the pid it expected, no spawn goes unmatched, and the run
  ## grades mcComplete over a record set that contains no file reads because
  ## nothing was watching for them. A consumer then publishes an action-cache
  ## entry keyed on inputs it never saw, and the next build gets a hit it has
  ## not earned -- strictly worse than the uncacheable build this whole
  ## investigation started from, because it is wrong rather than slow.
  ##
  ## mrEventLoss with an unquantified scope is the honest grade: we know
  ## observation was incomplete and cannot bound what was missed.
  ## `names` matters as much as the count. The two ways to arrive here are
  ## not equally alarming and the reader cannot tell them apart otherwise:
  ## an entry point no loaded module imports has no IAT slot to patch and is
  ## simply out of the IAT backend's reach (calls resolved through
  ## GetProcAddress, which is why inline detours exist), whereas a name that
  ## IS imported and still failed to patch points at a defect. Naming them
  ## keeps that distinction available without a rebuild.
  var record = baseRecord(mrEventLoss, moEventLoss)
  record.detail = "no hook installed for " & $unhooked &
    " entry point(s) [" & names & "]; calls through them were not observed"
  emitRecord(record)
  withShimMuted:
    try:
      flushFragmentBatch()
    except CatchableError:
      discard

# --- Hook chain context layout ---------------------------------------------
#
# Win32 trampolines pack their stdcall arguments into HookContext.args as
# uint64s, in source-order. The "original" callback unpacks them back into
# the typed Win32 ABI to invoke the captured origXxx pointer; the monitor's
# snoop callback unpacks the args it cares about (the path, the access
# flags) plus ctx.result for the post-call observation.
#
# Argument slot conventions (per hook name):
#
#   CreateFileW / CreateFileA:
#     args[0]: lpFileName            (LPCWSTR/LPCSTR)
#     args[1]: dwDesiredAccess       (DWORD)
#     args[2]: dwShareMode           (DWORD)
#     args[3]: lpSecurityAttributes  (LPSECURITY_ATTRIBUTES)
#     args[4]: dwCreationDisposition (DWORD)
#     args[5]: dwFlagsAndAttributes  (DWORD)
#     args[6]: hTemplateFile         (HANDLE)
#
#   ReadFile / WriteFile: hFile, lpBuffer, nBytes, lpBytesXfer, lpOverlapped
#   CloseHandle: hObject
#   GetFileAttributesExW/A: lpFileName, fInfoLevelId, lpFileInformation
#   GetFileAttributesW/A: lpFileName
#   CreateProcessW/A: 10 args matching the Win32 signature

# --- Original-callback wrappers --------------------------------------------
#
# Each original wrapper unpacks the HookContext.args back into the typed
# Win32 ABI, calls the captured origXxx pointer, and stores the result
# back into ctx.result. These are registered as the chain's ``original``
# via setOriginalCallback so that the snoop callback's callNext eventually
# reaches the real Win32 API.

proc originalCreateFileW(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateFileW == nil:
    ctx.result = cast[uint64](INVALID_HANDLE_VALUE)
    return
  let lpFileName        = cast[LPCWSTR](ctx.args[0])
  let dwDesiredAccess   = DWORD(ctx.args[1])
  let dwShareMode       = DWORD(ctx.args[2])
  let lpSecAttr         = cast[LPSECURITY_ATTRIBUTES](ctx.args[3])
  let dwCreationDisp    = DWORD(ctx.args[4])
  let dwFlagsAndAttrs   = DWORD(ctx.args[5])
  let hTemplateFile     = cast[HANDLE](ctx.args[6])
  let r = origCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                          lpSecAttr, dwCreationDisp, dwFlagsAndAttrs,
                          hTemplateFile)
  ctx.result = cast[uint64](r)

proc originalCreateFileA(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateFileA == nil:
    ctx.result = cast[uint64](INVALID_HANDLE_VALUE)
    return
  let lpFileName        = cast[LPCSTR](ctx.args[0])
  let dwDesiredAccess   = DWORD(ctx.args[1])
  let dwShareMode       = DWORD(ctx.args[2])
  let lpSecAttr         = cast[LPSECURITY_ATTRIBUTES](ctx.args[3])
  let dwCreationDisp    = DWORD(ctx.args[4])
  let dwFlagsAndAttrs   = DWORD(ctx.args[5])
  let hTemplateFile     = cast[HANDLE](ctx.args[6])
  let r = origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                          lpSecAttr, dwCreationDisp, dwFlagsAndAttrs,
                          hTemplateFile)
  ctx.result = cast[uint64](r)

proc originalReadFile(ctx: var hr.HookContext) {.raises: [].} =
  if origReadFile == nil:
    ctx.result = 0
    return
  let hFile         = cast[HANDLE](ctx.args[0])
  let lpBuffer      = cast[LPVOID](ctx.args[1])
  let nBytes        = DWORD(ctx.args[2])
  let lpBytesRead   = cast[ptr DWORD](ctx.args[3])
  let lpOverlapped  = cast[LPOVERLAPPED](ctx.args[4])
  let r = origReadFile(hFile, lpBuffer, nBytes, lpBytesRead, lpOverlapped)
  ctx.result = uint64(uint32(r))

proc originalWriteFile(ctx: var hr.HookContext) {.raises: [].} =
  if origWriteFile == nil:
    ctx.result = 0
    return
  let hFile          = cast[HANDLE](ctx.args[0])
  let lpBuffer       = cast[LPCVOID](ctx.args[1])
  let nBytes         = DWORD(ctx.args[2])
  let lpBytesWritten = cast[ptr DWORD](ctx.args[3])
  let lpOverlapped   = cast[LPOVERLAPPED](ctx.args[4])
  let r = origWriteFile(hFile, lpBuffer, nBytes, lpBytesWritten, lpOverlapped)
  ctx.result = uint64(uint32(r))

proc originalCloseHandle(ctx: var hr.HookContext) {.raises: [].} =
  if origCloseHandle == nil:
    ctx.result = 0
    return
  let hObject = cast[HANDLE](ctx.args[0])
  let r = origCloseHandle(hObject)
  ctx.result = uint64(uint32(r))

proc originalNtTerminateProcess(ctx: var hr.HookContext) {.raises: [].} =
  if origNtTerminateProcess == nil:
    ctx.result = uint64(uint32(0xC0000001'i32))
    return
  let h = cast[HANDLE](ctx.args[0])
  let status = int32(uint32(ctx.args[1] and 0xFFFFFFFF'u64))
  ctx.result = uint64(uint32(origNtTerminateProcess(h, status)))

proc originalGetFileAttributesExW(ctx: var hr.HookContext) {.raises: [].} =
  if origGetFileAttributesExW == nil:
    ctx.result = 0
    return
  let lpFileName        = cast[LPCWSTR](ctx.args[0])
  let fInfoLevelId      = DWORD(ctx.args[1])
  let lpFileInformation = cast[LPVOID](ctx.args[2])
  let r = origGetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation)
  ctx.result = uint64(uint32(r))

proc originalGetFileAttributesExA(ctx: var hr.HookContext) {.raises: [].} =
  if origGetFileAttributesExA == nil:
    ctx.result = 0
    return
  let lpFileName        = cast[LPCSTR](ctx.args[0])
  let fInfoLevelId      = DWORD(ctx.args[1])
  let lpFileInformation = cast[LPVOID](ctx.args[2])
  let r = origGetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation)
  ctx.result = uint64(uint32(r))

proc originalGetFileAttributesW(ctx: var hr.HookContext) {.raises: [].} =
  if origGetFileAttributesW == nil:
    ctx.result = 0xFFFFFFFF'u64
    return
  let lpFileName = cast[LPCWSTR](ctx.args[0])
  let r = origGetFileAttributesW(lpFileName)
  ctx.result = uint64(r)

proc originalGetFileAttributesA(ctx: var hr.HookContext) {.raises: [].} =
  if origGetFileAttributesA == nil:
    ctx.result = 0xFFFFFFFF'u64
    return
  let lpFileName = cast[LPCSTR](ctx.args[0])
  let r = origGetFileAttributesA(lpFileName)
  ctx.result = uint64(r)

proc originalCreateProcessW(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateProcessW == nil:
    ctx.result = 0
    return
  let lpApplicationName  = cast[LPCWSTR](ctx.args[0])
  let lpCommandLine      = cast[LPWSTR](ctx.args[1])
  let lpProcAttr         = cast[LPSECURITY_ATTRIBUTES](ctx.args[2])
  let lpThreadAttr       = cast[LPSECURITY_ATTRIBUTES](ctx.args[3])
  let bInheritHandles    = BOOL(ctx.args[4])
  let dwCreationFlags    = DWORD(ctx.args[5])
  let lpEnvironment      = cast[LPVOID](ctx.args[6])
  let lpCurrentDirectory = cast[LPCWSTR](ctx.args[7])
  let lpStartupInfo      = cast[ptr STARTUPINFOW](ctx.args[8])
  let lpProcessInfo      = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  let r = origCreateProcessW(lpApplicationName, lpCommandLine,
                              lpProcAttr, lpThreadAttr, bInheritHandles,
                              dwCreationFlags, lpEnvironment,
                              lpCurrentDirectory, lpStartupInfo,
                              lpProcessInfo)
  ctx.result = uint64(uint32(r))

proc originalCreateProcessA(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateProcessA == nil:
    ctx.result = 0
    return
  let lpApplicationName  = cast[LPCSTR](ctx.args[0])
  let lpCommandLine      = cast[LPSTR](ctx.args[1])
  let lpProcAttr         = cast[LPSECURITY_ATTRIBUTES](ctx.args[2])
  let lpThreadAttr       = cast[LPSECURITY_ATTRIBUTES](ctx.args[3])
  let bInheritHandles    = BOOL(ctx.args[4])
  let dwCreationFlags    = DWORD(ctx.args[5])
  let lpEnvironment      = cast[LPVOID](ctx.args[6])
  let lpCurrentDirectory = cast[LPCSTR](ctx.args[7])
  let lpStartupInfo      = cast[ptr STARTUPINFOA](ctx.args[8])
  let lpProcessInfo      = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  let r = origCreateProcessA(lpApplicationName, lpCommandLine,
                              lpProcAttr, lpThreadAttr, bInheritHandles,
                              dwCreationFlags, lpEnvironment,
                              lpCurrentDirectory, lpStartupInfo,
                              lpProcessInfo)
  ctx.result = uint64(uint32(r))

# --- M73 Phase 5: original-callback wrappers for the extended hook surface.

proc originalDeleteFileW(ctx: var hr.HookContext) {.raises: [].} =
  if origDeleteFileW == nil:
    ctx.result = 0
    return
  let lpFileName = cast[LPCWSTR](ctx.args[0])
  let r = origDeleteFileW(lpFileName)
  ctx.result = uint64(uint32(r))

proc originalDeleteFileA(ctx: var hr.HookContext) {.raises: [].} =
  if origDeleteFileA == nil:
    ctx.result = 0
    return
  let lpFileName = cast[LPCSTR](ctx.args[0])
  let r = origDeleteFileA(lpFileName)
  ctx.result = uint64(uint32(r))

proc originalCreateDirectoryW(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateDirectoryW == nil:
    ctx.result = 0
    return
  let lpPathName = cast[LPCWSTR](ctx.args[0])
  let lpSecAttr = cast[LPSECURITY_ATTRIBUTES](ctx.args[1])
  let r = origCreateDirectoryW(lpPathName, lpSecAttr)
  ctx.result = uint64(uint32(r))

proc originalCreateDirectoryA(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateDirectoryA == nil:
    ctx.result = 0
    return
  let lpPathName = cast[LPCSTR](ctx.args[0])
  let lpSecAttr = cast[LPSECURITY_ATTRIBUTES](ctx.args[1])
  let r = origCreateDirectoryA(lpPathName, lpSecAttr)
  ctx.result = uint64(uint32(r))

proc originalCopyFileW(ctx: var hr.HookContext) {.raises: [].} =
  if origCopyFileW == nil:
    ctx.result = 0
    return
  let lpExisting = cast[LPCWSTR](ctx.args[0])
  let lpNew      = cast[LPCWSTR](ctx.args[1])
  let bFail      = BOOL(ctx.args[2])
  let r = origCopyFileW(lpExisting, lpNew, bFail)
  ctx.result = uint64(uint32(r))

proc originalCopyFileA(ctx: var hr.HookContext) {.raises: [].} =
  if origCopyFileA == nil:
    ctx.result = 0
    return
  let lpExisting = cast[LPCSTR](ctx.args[0])
  let lpNew      = cast[LPCSTR](ctx.args[1])
  let bFail      = BOOL(ctx.args[2])
  let r = origCopyFileA(lpExisting, lpNew, bFail)
  ctx.result = uint64(uint32(r))

proc originalMoveFileExW(ctx: var hr.HookContext) {.raises: [].} =
  if origMoveFileExW == nil:
    ctx.result = 0
    return
  let lpExisting = cast[LPCWSTR](ctx.args[0])
  let lpNew      = cast[LPCWSTR](ctx.args[1])
  let dwFlags    = DWORD(ctx.args[2])
  let r = origMoveFileExW(lpExisting, lpNew, dwFlags)
  ctx.result = uint64(uint32(r))

proc originalMoveFileExA(ctx: var hr.HookContext) {.raises: [].} =
  if origMoveFileExA == nil:
    ctx.result = 0
    return
  let lpExisting = cast[LPCSTR](ctx.args[0])
  let lpNew      = cast[LPCSTR](ctx.args[1])
  let dwFlags    = DWORD(ctx.args[2])
  let r = origMoveFileExA(lpExisting, lpNew, dwFlags)
  ctx.result = uint64(uint32(r))

proc originalGetFileInformationByHandleEx(ctx: var hr.HookContext)
    {.raises: [].} =
  if origGetFileInformationByHandleEx == nil:
    ctx.result = 0
    return
  let hFile             = cast[HANDLE](ctx.args[0])
  let infoClass         = DWORD(ctx.args[1])
  let lpFileInformation = cast[LPVOID](ctx.args[2])
  let dwBufferSize      = DWORD(ctx.args[3])
  let r = origGetFileInformationByHandleEx(hFile, infoClass,
                                            lpFileInformation, dwBufferSize)
  ctx.result = uint64(uint32(r))

proc originalSetCurrentDirectoryW(ctx: var hr.HookContext) {.raises: [].} =
  if origSetCurrentDirectoryW == nil:
    ctx.result = 0
    return
  let lpPathName = cast[LPCWSTR](ctx.args[0])
  let r = origSetCurrentDirectoryW(lpPathName)
  ctx.result = uint64(uint32(r))

proc originalSetCurrentDirectoryA(ctx: var hr.HookContext) {.raises: [].} =
  if origSetCurrentDirectoryA == nil:
    ctx.result = 0
    return
  let lpPathName = cast[LPCSTR](ctx.args[0])
  let r = origSetCurrentDirectoryA(lpPathName)
  ctx.result = uint64(uint32(r))

proc originalNtCreateFile(ctx: var hr.HookContext) {.raises: [].} =
  if origNtCreateFile == nil:
    # STATUS_UNSUCCESSFUL (0xC0000001) — caller sees an NTSTATUS failure
    # rather than a silent 0 (which is STATUS_SUCCESS!) when the
    # original was never captured.
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let FileHandle        = cast[ptr HANDLE](ctx.args[0])
  let DesiredAccess     = DWORD(ctx.args[1])
  let ObjectAttributes  = cast[pointer](ctx.args[2])
  let IoStatusBlock     = cast[pointer](ctx.args[3])
  let AllocationSize    = cast[ptr LARGE_INTEGER](ctx.args[4])
  let FileAttributes    = DWORD(ctx.args[5])
  let ShareAccess       = DWORD(ctx.args[6])
  let CreateDisposition = DWORD(ctx.args[7])
  let CreateOptions     = DWORD(ctx.args[8])
  let EaBuffer          = cast[pointer](ctx.args[9])
  let EaLength          = DWORD(ctx.args[10])
  let r = origNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                            IoStatusBlock, AllocationSize, FileAttributes,
                            ShareAccess, CreateDisposition, CreateOptions,
                            EaBuffer, EaLength)
  # NTSTATUS is signed 32-bit; pack as unsigned for the uint64 slot and
  # let the trampoline reinterpret on the way out.
  ctx.result = uint64(uint32(r))

proc originalNtQueryAttributesFile(ctx: var hr.HookContext) {.raises: [].} =
  if origNtQueryAttributesFile == nil:
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let ObjectAttributes = cast[pointer](ctx.args[0])
  let FileInformation  = cast[pointer](ctx.args[1])
  let r = origNtQueryAttributesFile(ObjectAttributes, FileInformation)
  ctx.result = uint64(uint32(r))

proc originalNtQueryFullAttributesFile(ctx: var hr.HookContext) {.raises: [].} =
  if origNtQueryFullAttributesFile == nil:
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let ObjectAttributes = cast[pointer](ctx.args[0])
  let FileInformation  = cast[pointer](ctx.args[1])
  let r = origNtQueryFullAttributesFile(ObjectAttributes, FileInformation)
  ctx.result = uint64(uint32(r))

proc originalNtQueryDirectoryFileEx(ctx: var hr.HookContext) {.raises: [].} =
  if origNtQueryDirectoryFileEx == nil:
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let FileHandle           = cast[HANDLE](ctx.args[0])
  let Event                = cast[HANDLE](ctx.args[1])
  let ApcRoutine           = cast[pointer](ctx.args[2])
  let ApcContext           = cast[pointer](ctx.args[3])
  let IoStatusBlock        = cast[pointer](ctx.args[4])
  let FileInformation      = cast[pointer](ctx.args[5])
  let Length               = DWORD(ctx.args[6])
  let FileInformationClass = DWORD(ctx.args[7])
  let QueryFlags           = DWORD(ctx.args[8])
  let FileName             = cast[pointer](ctx.args[9])
  let r = origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FileInformation, Length,
                                     FileInformationClass, QueryFlags, FileName)
  ctx.result = uint64(uint32(r))

proc originalFindFirstFileW(ctx: var hr.HookContext) {.raises: [].} =
  if origFindFirstFileW == nil:
    ctx.result = cast[uint64](INVALID_HANDLE_VALUE)
    return
  let lpFileName    = cast[LPCWSTR](ctx.args[0])
  let lpFindFileData = cast[pointer](ctx.args[1])
  let r = origFindFirstFileW(lpFileName, lpFindFileData)
  ctx.result = cast[uint64](r)

proc originalFindFirstFileExW(ctx: var hr.HookContext) {.raises: [].} =
  if origFindFirstFileExW == nil:
    ctx.result = cast[uint64](INVALID_HANDLE_VALUE)
    return
  let lpFileName       = cast[LPCWSTR](ctx.args[0])
  let fInfoLevelId     = DWORD(ctx.args[1])
  let lpFindFileData   = cast[pointer](ctx.args[2])
  let fSearchOp        = DWORD(ctx.args[3])
  let lpSearchFilter   = cast[pointer](ctx.args[4])
  let dwAdditionalFlags = DWORD(ctx.args[5])
  let r = origFindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData,
                                fSearchOp, lpSearchFilter, dwAdditionalFlags)
  ctx.result = cast[uint64](r)

proc originalFindNextFileW(ctx: var hr.HookContext) {.raises: [].} =
  if origFindNextFileW == nil:
    ctx.result = uint64(0'u32)
    return
  let hFindFile       = cast[HANDLE](ctx.args[0])
  let lpFindFileData  = cast[pointer](ctx.args[1])
  let r = origFindNextFileW(hFindFile, lpFindFileData)
  ctx.result = uint64(uint32(r))

proc originalFindClose(ctx: var hr.HookContext) {.raises: [].} =
  if origFindClose == nil:
    ctx.result = uint64(0'u32)
    return
  let hFindFile = cast[HANDLE](ctx.args[0])
  let r = origFindClose(hFindFile)
  ctx.result = uint64(uint32(r))

proc originalGetProcAddress(ctx: var hr.HookContext) {.raises: [].} =
  if origGetProcAddress == nil:
    ctx.result = uint64(0'u64)
    return
  let hModule    = cast[HANDLE](ctx.args[0])
  let lpProcName = cast[LPCSTR](ctx.args[1])
  let r = origGetProcAddress(hModule, lpProcName)
  ctx.result = cast[uint64](r)

proc shimNtQueryDirectoryFile(FileHandle: HANDLE; Event: HANDLE;
                               ApcRoutine: pointer; ApcContext: pointer;
                               IoStatusBlock: pointer;
                               FileInformation: pointer; Length: DWORD;
                               FileInformationClass: DWORD;
                               ReturnSingleEntry: BOOL;
                               FileName: pointer;
                               RestartScan: BOOL): NTSTATUS
                               {.stdcall, raises: [].} =
  ## Wrapper substituted for ntdll!NtQueryDirectoryFile via our hooked
  ## GetProcAddress. Records mrDirectoryEnumerate on the first call
  ## per handle (or whenever RestartScan=TRUE), then forwards to the
  ## REAL ntdll function captured at install time.
  if realNtQueryDirectoryFile == nil:
    return NTSTATUS(0xC0000001'i32)
  let r = realNtQueryDirectoryFile(FileHandle, Event, ApcRoutine,
                                   ApcContext, IoStatusBlock,
                                   FileInformation, Length,
                                   FileInformationClass, ReturnSingleEntry,
                                   FileName, RestartScan)
  if disabled == 0 and initialized:
    try:
      # Inline gate: emit ONE mrDirectoryEnumerate record per readdir
      # session. RestartScan=TRUE opens a fresh enumeration; FALSE
      # iterates the chunk we already counted. Look up the directory's
      # remembered path from handlePaths.
      let isFirstCall = RestartScan != 0
      var dirPath = ""
      acquire(fdLock)
      try:
        let key = handleKey(FileHandle)
        if handlePaths.hasKey(key):
          try:
            dirPath = handlePaths[key]
          except KeyError:
            dirPath = ""
      finally:
        release(fdLock)
      if isFirstCall and dirPath.len > 0:
        var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
        record.path = dirPath
        record.result = int64(r)
        record.detail = "NtQueryDirectoryFile"
        emitRecord(record)
    except CatchableError:
      discard
  r

proc snoopGetProcAddress(ctx: var hr.HookContext) {.raises: [].} =
  ## Forwards GetProcAddress to the real kernel32 entry, then if the
  ## resolved name is "NtQueryDirectoryFile" from ntdll, swaps the
  ## returned pointer for our wrapper. Caches the real address in
  ## ``realNtQueryDirectoryFile`` for the wrapper to forward through.
  hr.callNext(ctx)
  if disabled > 0 or not initialized:
    return
  try:
    let lpProcName = cast[LPCSTR](ctx.args[1])
    if lpProcName == nil:
      return
    # Procname can be an integer ordinal (low 16 bits set) or a real
    # cstring pointer. Skip the ordinal case quickly.
    if (cast[uint](lpProcName) shr 16) == 0'u:
      return
    let name = $lpProcName
    if name == "NtQueryDirectoryFile":
      let resolved = cast[NtQueryDirectoryFileProc](ctx.result)
      if resolved != nil:
        realNtQueryDirectoryFile = resolved
        ctx.result = cast[uint64](shimNtQueryDirectoryFile)
  except CatchableError:
    discard

proc originalNtQueryInformationByName(ctx: var hr.HookContext) {.raises: [].} =
  if origNtQueryInformationByName == nil:
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let ObjectAttributes     = cast[pointer](ctx.args[0])
  let IoStatusBlock        = cast[pointer](ctx.args[1])
  let FileInformation      = cast[pointer](ctx.args[2])
  let Length               = DWORD(ctx.args[3])
  let FileInformationClass = DWORD(ctx.args[4])
  let r = origNtQueryInformationByName(ObjectAttributes, IoStatusBlock,
                                       FileInformation, Length,
                                       FileInformationClass)
  ctx.result = uint64(uint32(r))

proc originalNtQueryDirectoryFile(ctx: var hr.HookContext) {.raises: [].} =
  if origNtQueryDirectoryFile == nil:
    ctx.result = uint64(uint32(0xC0000001'u32))
    return
  let FileHandle           = cast[HANDLE](ctx.args[0])
  let Event                = cast[HANDLE](ctx.args[1])
  let ApcRoutine           = cast[pointer](ctx.args[2])
  let ApcContext           = cast[pointer](ctx.args[3])
  let IoStatusBlock        = cast[pointer](ctx.args[4])
  let FileInformation      = cast[pointer](ctx.args[5])
  let Length               = DWORD(ctx.args[6])
  let FileInformationClass = DWORD(ctx.args[7])
  let ReturnSingleEntry    = BOOL(ctx.args[8])
  let FileName             = cast[pointer](ctx.args[9])
  let RestartScan          = BOOL(ctx.args[10])
  let r = origNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                   IoStatusBlock, FileInformation, Length,
                                   FileInformationClass, ReturnSingleEntry,
                                   FileName, RestartScan)
  ctx.result = uint64(uint32(r))

# --- Snoop callbacks (registered against the chain at ShimSnoopPriority) ---
#
# Each snoop callback follows the same pattern:
#   1. callNext(ctx)         — runs the rest of the chain, ultimately the
#                              real Win32 API (which sets LastError).
#   2. Save LastError        — Nim allocator + Lock ops can clobber it.
#   3. Bookkeeping           — read ctx.args / ctx.result, build a
#                              MonitorRecord, append to the fragment.
#   4. Restore LastError     — caller sees what the kernel actually set.
#
# M11.7 outstanding follow-up: the Save/Restore dance can be retired once
# the IAT fallback path is removed entirely (M73 Phase 6). Today the
# trampoline (inline or IAT) still allocates inside the snoop body so
# the dance is load-bearing regardless of which install path landed.

proc snoopCreateFileW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let dwDesiredAccess = DWORD(ctx.args[1])
    let dwCreationDisp = DWORD(ctx.args[4])
    let path = widePtrToString(lpFileName)
    let h = cast[HANDLE](ctx.result)
    if h != INVALID_HANDLE_VALUE:
      rememberHandlePath(h, path)
    var record = baseRecord(mrFileOpen,
      observationForCreateFile(dwDesiredAccess, dwCreationDisp))
    record.result = int64(cast[int](h))
    record.flags = uint32(dwDesiredAccess)
    record.path = path
    record.detail = "CreateFileW"
    emitRecord(record)
    # M5 — a Windows pipe CLIENT and an NTFS alternate data stream both arrive
    # here, as opens; neither was classified before, so a named-pipe peer was
    # indistinguishable from an in-tree process and a stream read looked like a
    # plain file read.
    classifyOpenedPath(path, h, dwDesiredAccess)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCreateFileA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCSTR](ctx.args[0])
    let dwDesiredAccess = DWORD(ctx.args[1])
    let dwCreationDisp = DWORD(ctx.args[4])
    var path = ""
    if lpFileName != nil:
      path = $lpFileName
    let h = cast[HANDLE](ctx.result)
    if h != INVALID_HANDLE_VALUE:
      rememberHandlePath(h, path)
    var record = baseRecord(mrFileOpen,
      observationForCreateFile(dwDesiredAccess, dwCreationDisp))
    record.result = int64(cast[int](h))
    record.flags = uint32(dwDesiredAccess)
    record.path = path
    record.detail = "CreateFileA"
    emitRecord(record)
    classifyOpenedPath(path, h, dwDesiredAccess)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopReadFile(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  # ReadFile preservation is load-bearing. Without it, cargo's
  # std::process::Command::spawn panics with
  # `Os { code: 183, kind: AlreadyExists }` on the rust-binary-with-build-rs
  # fixture. (See M11 audit notes.)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let hFile = cast[HANDLE](ctx.args[0])
    let lpBytesRead = cast[ptr DWORD](ctx.args[3])
    let callOk = callResultBool(ctx.result) != 0
    let path = pathForHandle(hFile)
    # M5 — external content: a read from a handle the shim never saw opened is
    # the Windows shape of the inherited-pipe channel (`chan=opaque`). The
    # bytes are a real INPUT and there is no file path anywhere in the capture
    # to fingerprint, so the merge has to decide provenance -- and it can,
    # because a Windows pipe object carries a name both ends agree on.
    #
    # The classification runs ONLY for an unknown handle and the fact that it
    # ran is recorded in `channelClassified` (NOT in `handlePaths`, which holds
    # paths and is left empty for exactly these handles), so the
    # GetFileType/FileNameInfo pair costs one call per handle rather than one
    # per read. ReadFile is the hottest hook in the table; an unconditional
    # probe here would undo S4's batching win on its own.
    if callOk and path.len == 0 and not markHandleChannelClassified(hFile):
      if GetFileType(hFile) == FILE_TYPE_PIPE:
        var producer = 0'u64
        let identity = pipePairIdentity(hFile, producer)
        # An identity the kernel would not supply (the far end has already
        # gone, or the handle is a socket rather than a pipe) yields an EMPTY
        # key, which the merge deliberately never downgrades on: a possible
        # missed dependency is the safe direction, a false re-run of every
        # normal build is not.
        emitExternalContent("opaque", "read", identity, producer, 0'i64)
    var record = baseRecord(mrFileRead, moFileRead)
    record.path = path
    if callOk and lpBytesRead != nil:
      record.result = int64(lpBytesRead[])
    else:
      record.result = -1
    record.detail = "ReadFile"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopWriteFile(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let hFile = cast[HANDLE](ctx.args[0])
    let lpBytesWritten = cast[ptr DWORD](ctx.args[3])
    let callOk = callResultBool(ctx.result) != 0
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = pathForHandle(hFile)
    if callOk and lpBytesWritten != nil:
      record.result = int64(lpBytesWritten[])
    else:
      record.result = -1
    record.detail = "WriteFile"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCloseHandle(ctx: var hr.HookContext) {.raises: [].} =
  # Windows: CloseHandle is invoked far more frequently than the file
  # operations we care about. We do the bookkeeping BEFORE callNext so
  # any allocator activity inside forgetHandlePath cannot clobber the
  # LastError that the real CloseHandle will set.
  if disabled > 0 or not initialized:
    hr.callNext(ctx)
    return
  inc disabled
  try:
    let hObject = cast[HANDLE](ctx.args[0])
    forgetHandlePath(hObject)
    # M5 — a section handle is closed through the same call; drop its
    # mapping->file association so a recycled handle value cannot attribute a
    # later view to the wrong file.
    forgetMappingPath(hObject)
    forgetHandleChannelClass(hObject)
  except CatchableError:
    discard
  hr.callNext(ctx)
  dec disabled

proc snoopGetFileAttributesExW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()  # ERROR_FILE_NOT_FOUND on absent path
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrPathProbe, moPathProbe)
    record.path = widePtrToString(lpFileName)
    record.result = int64(r)
    record.probeResult = probeFromBool(r)
    record.detail = "GetFileAttributesExW"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopGetFileAttributesExA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrPathProbe, moPathProbe)
    if lpFileName != nil:
      record.path = $lpFileName
    record.result = int64(r)
    record.probeResult = probeFromBool(r)
    record.detail = "GetFileAttributesExA"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopGetFileAttributesW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let r = DWORD(ctx.result)
    var record = baseRecord(mrPathProbe, moPathProbe)
    record.path = widePtrToString(lpFileName)
    record.result = int64(r)
    record.probeResult =
      if r == 0xFFFFFFFF'u32: prAbsent else: prExistingOther
    record.detail = "GetFileAttributesW"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopGetFileAttributesA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCSTR](ctx.args[0])
    let r = DWORD(ctx.result)
    var record = baseRecord(mrPathProbe, moPathProbe)
    if lpFileName != nil:
      record.path = $lpFileName
    record.result = int64(r)
    record.probeResult =
      if r == 0xFFFFFFFF'u32: prAbsent else: prExistingOther
    record.detail = "GetFileAttributesA"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

# Lazily populate the shim's own DLL path so we can re-inject it into
# CreateProcess descendants. ``GetModuleHandleExW`` with
# ``FROM_ADDRESS`` flag locates the module containing the address of
# ``snoopCreateProcessW`` itself; that's our own DLL by definition. We
# then read its file path with ``GetModuleFileNameW``. The
# ``UNCHANGED_REFCOUNT`` flag avoids artificially bumping our own load
# count.
proc ensureSelfDllPath() =
  if selfDllPathReady:
    return
  var hSelf: HANDLE = nil
  # Cast through ``ByteAddress`` (Nim's ``int``-sized integer alias)
  # so the C codegen emits ``(NU16*)(long)x`` instead of
  # ``(NU16*)x``. Going through an integer breaks gcc's
  # ``-Wincompatible-pointer-types`` warn-as-error path that fires on
  # function-pointer → data-pointer direct conversions; the runtime
  # bit pattern is the literal address of our own ``ensureSelfDllPath``
  # function, which is the probe value ``GetModuleHandleExW`` needs.
  let selfProbe = cast[ByteAddress](ensureSelfDllPath)
  if GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS or
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      cast[LPCWSTR](selfProbe),
      addr hSelf) == 0 or hSelf == nil:
    selfDllPathReady = true
    return
  var buf: array[1024, uint16]
  let n = GetModuleFileNameW(hSelf, cast[LPWSTR](addr buf[0]),
    DWORD(buf.len))
  if n == 0'u32 or n >= DWORD(buf.len):
    selfDllPathReady = true
    return
  selfDllPathW = newSeq[uint16](int(n) + 1)
  for i in 0 ..< int(n):
    selfDllPathW[i] = buf[i]
  selfDllPathW[int(n)] = 0'u16
  selfDllPathReady = true

proc selfDllPath(): string {.raises: [].} =
  ## Narrow string form of ``selfDllPathW`` for callers that need a
  ## native ``string`` (e.g. the stackable-hooks framework's
  ## ``injectShimIntoChild`` takes the library path as a UTF-8 string
  ## and re-widens it internally). The shim DLL path is always plain
  ## ASCII so the ``[i] and 0xFF`` low-byte extract is lossless.
  let last = selfDllPathW.len - 1
  if last <= 0:
    return ""
  result = newString(last)
  for i in 0 ..< last:
    result[i] = char(selfDllPathW[i] and 0xFF)

# Inject the shim DLL into ``hProcess`` by allocating a buffer in the
# remote address space, writing our own DLL path into it, and firing
# LoadLibraryW via CreateRemoteThread. LoadLibraryW's entry-point
# address is identical in the child because kernel32 maps at the same
# base across processes for the lifetime of the OS boot session.
#
# Returns true on success. Failures are swallowed silently — child
# might still run with degraded (but correct) monitoring evidence,
# which beats crashing the child or killing the parent.
#
# **Legacy code path**: This proc is retained for backwards compat
# with non-snoop callers that still reach for the bespoke injector.
# The snoop hooks now route through
# ``stackable_hooks/propagation_windows`` which adds the four safety
# knobs documented in that module (maxInFlight semaphore, deadline
# replacing INFINITE wait, EnumProcessModulesEx skip,
# resume-before-init ordering). For new call sites, prefer the
# framework's ``injectShimIntoChild(hProcess, libraryPath,
# initSymbol)``.
proc injectShimIntoChild(hProcess: HANDLE): bool {.raises: [].} =
  if selfDllPathW.len == 0:
    return false
  let bufSize = SIZE_T(selfDllPathW.len * sizeof(uint16))
  let remoteBuf = VirtualAllocEx(hProcess, nil, bufSize,
    MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteBuf == nil:
    return false
  defer: discard VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE)
  var written: SIZE_T = 0
  if WriteProcessMemory(hProcess, remoteBuf, addr selfDllPathW[0],
      bufSize, addr written) == 0:
    return false
  var kernel32Name = [uint16(ord('k')), uint16(ord('e')), uint16(ord('r')),
    uint16(ord('n')), uint16(ord('e')), uint16(ord('l')),
    uint16(ord('3')), uint16(ord('2')), uint16(ord('.')),
    uint16(ord('d')), uint16(ord('l')), uint16(ord('l')), 0'u16]
  let kernel32 = GetModuleHandleW(cast[LPCWSTR](addr kernel32Name[0]))
  if kernel32 == nil:
    return false
  let loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW")
  if loadLibraryW == nil:
    return false
  let hThread = CreateRemoteThread(hProcess, nil, 0, loadLibraryW,
    remoteBuf, 0, nil)
  if hThread == nil:
    return false
  discard WaitForSingleObject(hThread, INFINITE)
  discard CloseHandle(hThread)
  # The shim DLL is now mapped into the child but its
  # ``repro_monitor_shim_init`` has NOT run — Nim doesn't expose
  # user-code on DLL_PROCESS_ATTACH, so an explicit second
  # CreateRemoteThread call against the init proc is required to
  # actually arm the IAT + inline detours in the child. Mirror the
  # production fs-snoop injector (``windows_injector.nim``): enumerate
  # the child's loaded modules to find our shim DLL's child-side base,
  # compute the init proc's RVA from our own copy, then
  # CreateRemoteThread at (childBase + RVA).
  var ourSelf: HANDLE = nil
  if GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS or
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      cast[LPCWSTR](cast[ByteAddress](ensureSelfDllPath)),
      addr ourSelf) == 0 or ourSelf == nil:
    return true  # DLL loaded but init won't run; degraded but not fatal
  let ourInit = GetProcAddress(ourSelf, "repro_runtime_init")
  if ourInit == nil:
    return true
  let ourBase = cast[uint](ourSelf)
  let rva = cast[uint](ourInit) - ourBase
  # Find the matching module in the child by basename.
  var wantBaseName = newString(0)
  block computeBaseName:
    var i = selfDllPathW.len - 2  # skip terminating NUL
    while i >= 0 and selfDllPathW[i] != 0'u16 and
        char(selfDllPathW[i] and 0xFF) != '\\' and
        char(selfDllPathW[i] and 0xFF) != '/':
      dec i
    inc i
    while i < selfDllPathW.len and selfDllPathW[i] != 0'u16:
      wantBaseName.add(char(selfDllPathW[i] and 0xFF))
      inc i
  if wantBaseName.len == 0:
    return true
  var childMods: array[1024, HANDLE]
  var modCb: DWORD = 0
  if EnumProcessModulesEx(hProcess, cast[ptr pointer](addr childMods[0]),
      DWORD(sizeof(childMods)), addr modCb, 0x3'u32) == 0:
    return true
  let modCount = int(modCb) div sizeof(HANDLE)
  var foundShim: HANDLE = nil
  for i in 0 ..< min(modCount, 1024):
    var nameBuf: array[1024, uint16]
    let nameLen = GetModuleBaseNameW(hProcess, childMods[i],
      cast[LPWSTR](addr nameBuf[0]), DWORD(nameBuf.len))
    if nameLen == 0:
      continue
    var got = newString(int(nameLen))
    for j in 0 ..< int(nameLen):
      got[j] = char(nameBuf[j] and 0xFF)
    if got.cmpIgnoreCase(wantBaseName) == 0:
      foundShim = childMods[i]
      break
  if foundShim == nil:
    return true
  let childInit = cast[pointer](cast[uint](foundShim) + rva)
  let initThread = CreateRemoteThread(hProcess, nil, 0, childInit,
    nil, 0, nil)
  if initThread != nil:
    discard WaitForSingleObject(initThread, INFINITE)
    discard CloseHandle(initThread)
  true

# ---------------------------------------------------------------------------
# THE LAST CHANCE TO MAKE RECORDS DURABLE
# ---------------------------------------------------------------------------
#
# Records are batched per thread and reach the fragment file on a key change,
# an explicit flush, or a 100 ms age bound. Whatever is still in a batch when
# the process ends is lost, and the merge accounts each unretired read-tail
# marker as a `kill-before-flush` event-loss -- an honest grade, but an empty
# one: the reads it describes are gone.
#
# The shim registered an `addExitProc` handler for exactly this. MEASURED on
# this host: IT NEVER RUNS IN AN MSYS2/CYGWIN PROCESS. A probe wired to the
# first statement of that handler produced no line for `bash` and none for the
# `grep` it exec'd, while both processes ended normally -- because a Cygwin
# runtime does not leave through the CRT's `exit`, and the DLL_PROCESS_DETACH
# that would drive our atexit chain is not delivered on that path. Everything
# those two processes did on any thread other than the injector's init thread
# was therefore dropped: for the injected `grep`, that was every file open and
# every read it performed.
#
# `NtTerminateProcess` is where all of those paths meet. `ExitProcess`
# (`RtlExitUserProcess`), `TerminateProcess`, and a runtime that terminates
# itself directly all reach it, and the FIRST call `RtlExitUserProcess` makes
# -- the one with a NULL handle, meaning "stop every OTHER thread" -- arrives
# while the whole process is still alive and every lock is still owned by a
# thread that can release it. That is the last instant at which a cross-thread
# sweep is safe, and it is the instant this hook uses.
#
# ONE SHOT, AND ONLY FOR OUR OWN PROCESS. A second sweep would run after those
# other threads are gone, when the registry lock may be held by a thread that
# will never release it -- a deadlock inside the exit path, which is strictly
# worse than the lost batch it would be trying to save. A `TerminateProcess`
# aimed at a DIFFERENT process says nothing about ours and is passed straight
# through.
#
# WHAT THIS DOES NOT DO. It does not retire another thread's read-tail
# sentinel -- only the owning thread can, and it is not running. So a batch
# rescued here still shows up as a kill-before-flush loss, and the run still
# grades incomplete. That is deliberate: this change puts strictly more
# evidence on disk and cannot improve a grade, which is the only direction a
# change to the capture path is allowed to move.

var terminateFlushDone {.global.}: Atomic[bool]

proc snoopNtTerminateProcess(ctx: var hr.HookContext) {.raises: [].} =
  let target = cast[HANDLE](ctx.args[0])
  # NULL  == "every other thread of the current process" (RtlExitUserProcess's
  #          first call, and the one we want)
  # -1    == GetCurrentProcess()
  # other == a handle we cannot cheaply attribute; GetProcessId tells us.
  let isSelf =
    target == nil or cast[uint](target) == high(uint) or
    (GetProcessId(target) == GetCurrentProcessId())
  if isSelf and initialized and not terminateFlushDone.exchange(true):
    withShimMuted:
      try:
        flushAllRegisteredSlots()
      except CatchableError, IOError, OSError:
        discard
  hr.callNext(ctx)

# ---------------------------------------------------------------------------
# CARRYING THE MONITORING CONFIGURATION INTO AN EXPLICIT CHILD ENVIRONMENT
# ---------------------------------------------------------------------------
#
# THE HOLE THIS CLOSES. The shim reads where to write its records from the
# child's WINDOWS ENVIRONMENT BLOCK (`REPRO_MONITOR_FRAGMENT_DIR`). A child
# spawned with `lpEnvironment = NULL` inherits ours and therefore has it. A
# child spawned with an EXPLICIT block has whatever the spawner put there --
# and a spawner that builds its own block does not know about us.
#
# The failure is silent in the worst way: injection SUCCEEDS (the DLL maps,
# `repro_runtime_init` runs and returns 0), `fragmentDir` comes back empty,
# and every record the child produces is dropped on the floor. The spawn hook
# reports `ioInjected`, the writer never sees an `mrProcessStart` from the
# child, and the subtree is graded as an unmonitored loss whose stated cause
# ("un-injectable spawn child") is not what happened.
#
# MEASURED, on this host, `bash -c "grep foo <file>"` under the monitor:
# `grep.exe` was injected and its init ran and returned 0 -- with
# `fragEnvLen=0`. Cygwin is the spawner that makes this the common case
# rather than a corner one: it hands a Cygwin child a MINIMAL Windows block
# on purpose, because the real POSIX environment travels to that child
# through its own `child_info` shared block rather than through Win32. Every
# MSYS-to-MSYS `exec` lands here.
#
# WHAT IS COPIED. The `REPRO_MONITOR_*` / `IO_MON_*` variables THIS process
# was configured with, snapshotted once at init from our own block, and only
# those the caller's block does not already define -- a spawner that sets one
# of them deliberately keeps its value. Nothing else about the caller's
# environment is touched: this ADDS entries, it never edits or removes one.

const monitorEnvPrefixes = ["REPRO_MONITOR_", "IO_MON_"]

var
  monitorEnvSnapshotW {.global.}: seq[uint16] = @[]
    ## Our own `REPRO_MONITOR_*` / `IO_MON_*` entries, each NUL-terminated,
    ## with no block terminator -- ready to splice into a caller's block.
  monitorEnvSnapshotA {.global.}: string = ""
    ## The same set as the OS itself renders it in an ANSI block. Taken from
    ## `GetEnvironmentStringsA` rather than converted from the wide form, so
    ## no code-page decision is made here.
  monitorEnvSnapshotReady {.global.}: bool = false

proc hasMonitorEnvPrefix(name: string): bool =
  for prefix in monitorEnvPrefixes:
    if name.len >= prefix.len:
      var match = true
      for i in 0 ..< prefix.len:
        if name[i] != prefix[i]:
          match = false
          break
      if match:
        return true
  false

proc captureMonitorEnvSnapshot() =
  ## Snapshot the monitoring configuration out of our own environment block.
  ## Called once from `repro_monitor_shim_init`, i.e. before any hook can
  ## fire, so the spawn path never has to call the (hooked) environment APIs
  ## itself.
  if monitorEnvSnapshotReady:
    return
  monitorEnvSnapshotReady = true
  const MaxBlockCodeUnits = 1 shl 20
  var blockW: LPWSTR = nil
  withShimMuted:
    blockW = GetEnvironmentStringsWRaw()
  if blockW != nil:
    let p = cast[ptr UncheckedArray[uint16]](blockW)
    var i = 0
    while i < MaxBlockCodeUnits and p[i] != 0'u16:
      var entryLen = 0
      while i + entryLen < MaxBlockCodeUnits and p[i + entryLen] != 0'u16:
        inc entryLen
      var eq = -1
      for j in 1 ..< entryLen:
        if p[i + j] == uint16(ord('=')):
          eq = j
          break
      if eq > 0:
        var n = newStringOfCap(eq)
        for j in 0 ..< eq:
          n.add(chr(int(p[i + j]) and 0xFF))
        if hasMonitorEnvPrefix(n):
          for j in 0 ..< entryLen:
            monitorEnvSnapshotW.add(p[i + j])
          monitorEnvSnapshotW.add(0'u16)
      i += entryLen + 1
    withShimMuted:
      discard FreeEnvironmentStringsW(blockW)
  var blockA: LPSTR = nil
  withShimMuted:
    blockA = GetEnvironmentStringsARaw()
  if blockA != nil:
    let p = cast[ptr UncheckedArray[char]](blockA)
    var i = 0
    while i < MaxBlockCodeUnits and p[i] != char(0):
      var entryLen = 0
      while i + entryLen < MaxBlockCodeUnits and p[i + entryLen] != char(0):
        inc entryLen
      var eq = -1
      for j in 1 ..< entryLen:
        if p[i + j] == '=':
          eq = j
          break
      if eq > 0:
        var n = newStringOfCap(eq)
        for j in 0 ..< eq:
          n.add(p[i + j])
        if hasMonitorEnvPrefix(n):
          for j in 0 ..< entryLen:
            monitorEnvSnapshotA.add(p[i + j])
          monitorEnvSnapshotA.add(char(0))
      i += entryLen + 1
    withShimMuted:
      discard FreeEnvironmentStringsA(blockA)

proc envBlockLenW(src: ptr UncheckedArray[uint16]; limit: int): int =
  ## Length in code units of a double-NUL-terminated wide block, excluding
  ## the final terminator. `limit` bounds a corrupted block to a truncation
  ## rather than a walk off the end of the mapping.
  result = 0
  while result < limit and src[result] != 0'u16:
    var entryLen = 0
    while result + entryLen < limit and src[result + entryLen] != 0'u16:
      inc entryLen
    result += entryLen + 1

proc entryNameDefinedW(blk: ptr UncheckedArray[uint16]; limit: int;
                       snapshotStart, nameLen: int): bool =
  ## Is the name of our snapshot entry at `snapshotStart` already defined in
  ## the caller's wide block? Compared case-insensitively, which is what the
  ## Windows environment itself is.
  var i = 0
  while i < limit and blk[i] != 0'u16:
    var entryLen = 0
    while i + entryLen < limit and blk[i + entryLen] != 0'u16:
      inc entryLen
    var eq = -1
    for j in 1 ..< entryLen:
      if blk[i + j] == uint16(ord('=')):
        eq = j
        break
    if eq == nameLen:
      var same = true
      for j in 0 ..< eq:
        var a = blk[i + j]
        var b = monitorEnvSnapshotW[snapshotStart + j]
        if a >= uint16(ord('a')) and a <= uint16(ord('z')): a = a - 32'u16
        if b >= uint16(ord('a')) and b <= uint16(ord('z')): b = b - 32'u16
        if a != b:
          same = false
          break
      if same:
        return true
    i += entryLen + 1
  false

proc environmentWithMonitorConfigW(lpEnvironment: LPVOID;
                                   buf: var seq[uint16]): LPVOID =
  ## Return a wide block equal to the caller's plus whichever monitoring
  ## entries it is missing, held in `buf`, or `nil` when nothing needs
  ## adding. `buf` must outlive the `CreateProcess` call.
  if lpEnvironment == nil or monitorEnvSnapshotW.len == 0:
    return nil
  const MaxBlockCodeUnits = 1 shl 20
  let src = cast[ptr UncheckedArray[uint16]](lpEnvironment)
  let srcLen = envBlockLenW(src, MaxBlockCodeUnits)
  if srcLen >= MaxBlockCodeUnits:
    return nil
  var missing: seq[int] = @[]
  var k = 0
  while k < monitorEnvSnapshotW.len:
    var entryLen = 0
    while k + entryLen < monitorEnvSnapshotW.len and
        monitorEnvSnapshotW[k + entryLen] != 0'u16:
      inc entryLen
    var eq = 0
    while eq < entryLen and monitorEnvSnapshotW[k + eq] != uint16(ord('=')):
      inc eq
    if eq > 0 and eq < entryLen and
        not entryNameDefinedW(src, srcLen, k, eq):
      missing.add(k)
    k += entryLen + 1
  if missing.len == 0:
    return nil
  buf = newSeqOfCap[uint16](srcLen + monitorEnvSnapshotW.len + 2)
  for i in 0 ..< srcLen:
    buf.add(src[i])
  for start in missing:
    var j = start
    while j < monitorEnvSnapshotW.len and monitorEnvSnapshotW[j] != 0'u16:
      buf.add(monitorEnvSnapshotW[j])
      inc j
    buf.add(0'u16)
  buf.add(0'u16)
  cast[LPVOID](addr buf[0])

proc envBlockLenA(src: ptr UncheckedArray[char]; limit: int): int =
  result = 0
  while result < limit and src[result] != char(0):
    var entryLen = 0
    while result + entryLen < limit and src[result + entryLen] != char(0):
      inc entryLen
    result += entryLen + 1

proc entryNameDefinedA(blk: ptr UncheckedArray[char]; limit: int;
                       snapshotStart, nameLen: int): bool =
  var i = 0
  while i < limit and blk[i] != char(0):
    var entryLen = 0
    while i + entryLen < limit and blk[i + entryLen] != char(0):
      inc entryLen
    var eq = -1
    for j in 1 ..< entryLen:
      if blk[i + j] == '=':
        eq = j
        break
    if eq == nameLen:
      var same = true
      for j in 0 ..< eq:
        var a = blk[i + j]
        var b = monitorEnvSnapshotA[snapshotStart + j]
        if a >= 'a' and a <= 'z': a = chr(ord(a) - 32)
        if b >= 'a' and b <= 'z': b = chr(ord(b) - 32)
        if a != b:
          same = false
          break
      if same:
        return true
    i += entryLen + 1
  false

proc environmentWithMonitorConfigA(lpEnvironment: LPVOID;
                                   buf: var string): LPVOID =
  ## ANSI counterpart of `environmentWithMonitorConfigW`, for a caller that
  ## passed a block without `CREATE_UNICODE_ENVIRONMENT`.
  if lpEnvironment == nil or monitorEnvSnapshotA.len == 0:
    return nil
  const MaxBlockBytes = 1 shl 20
  let src = cast[ptr UncheckedArray[char]](lpEnvironment)
  let srcLen = envBlockLenA(src, MaxBlockBytes)
  if srcLen >= MaxBlockBytes:
    return nil
  var missing: seq[int] = @[]
  var k = 0
  while k < monitorEnvSnapshotA.len:
    var entryLen = 0
    while k + entryLen < monitorEnvSnapshotA.len and
        monitorEnvSnapshotA[k + entryLen] != char(0):
      inc entryLen
    var eq = 0
    while eq < entryLen and monitorEnvSnapshotA[k + eq] != '=':
      inc eq
    if eq > 0 and eq < entryLen and
        not entryNameDefinedA(src, srcLen, k, eq):
      missing.add(k)
    k += entryLen + 1
  if missing.len == 0:
    return nil
  buf = newStringOfCap(srcLen + monitorEnvSnapshotA.len + 2)
  for i in 0 ..< srcLen:
    buf.add(src[i])
  for start in missing:
    var j = start
    while j < monitorEnvSnapshotA.len and monitorEnvSnapshotA[j] != char(0):
      buf.add(monitorEnvSnapshotA[j])
      inc j
    buf.add(char(0))
  buf.add(char(0))
  cast[LPVOID](addr buf[0])

proc snoopCreateProcessW(ctx: var hr.HookContext) {.raises: [].} =
  # Grandchild injection (Windows fs-snoop): force CREATE_SUSPENDED into
  # the child's creation flags BEFORE the real CreateProcessW runs, so
  # the child is suspended on its initial thread when control returns.
  # We then inject our own DLL via CreateRemoteThread(LoadLibraryW),
  # wait for LoadLibraryW to return inside the child, and resume the
  # main thread — unless the original caller already asked for
  # CREATE_SUSPENDED themselves, in which case we leave the suspension
  # exactly as they requested.
  # RESUME OWNERSHIP IS AN INVARIANT, NOT A HAPPY PATH. If we forced the
  # suspension, the child NEVER runs unless we resume it: every exit path
  # out of this hook owes that resume, including the ones that give up on
  # the snooping (re-entrancy `disabled`, a torn-down `initialized`, an
  # exception out of record building or injection). Nothing else in the
  # system knows the child is suspended, so a missed resume is not a lost
  # record -- it is a caller waiting forever on a process that will never
  # run a single instruction.
  #
  # The earlier shape had a bare `return` between the force and the
  # resume, so a hook re-entered during `callNext` handed the caller a
  # child frozen forever. Hence: ONE decision variable
  # (`shimForcedSuspend`), no `return` after the force, and the resume in
  # a `finally`. The proc keeps growing exit paths; the `finally` is what
  # makes the next one safe by construction rather than by review.
  #
  # The symmetric hazard is a DOUBLE resume, which is why the force is
  # skipped entirely when the caller already asked for CREATE_SUSPENDED --
  # then their own later ResumeThread is the only one.
  let callerCreationFlags = DWORD(ctx.args[5])
  let callerAskedForSuspended =
    (callerCreationFlags and CREATE_SUSPENDED) != 0
  # `shimForcedSuspend` is this hook's debt. It is true only when the
  # suspension the child is born with is one WE introduced, and from the
  # moment it is set, EVERY path out of this proc owes that child a
  # `ResumeThread` -- the test escapes below, a raise the `except` swallows,
  # and the ordinary end alike. That is what the `finally` at the bottom
  # exists for; nothing else in this proc may resume, or the debt is paid
  # twice.
  #
  # It stays false when the caller asked for CREATE_SUSPENDED themselves.
  # Suspend counts are counted, not boolean: an extra ResumeThread on a
  # caller-suspended child drops the count to zero and starts it running
  # before the caller meant it to, which cannot be taken back.
  var shimForcedSuspend = false
  # Keep-alive for a rewritten environment block. It is handed to the real
  # `CreateProcessW` as `lpEnvironment`, so it must outlive `callNext` --
  # hence proc scope, not the `if` below.
  var childEnvW: seq[uint16] = @[]
  var childEnvA: string = ""
  if initialized and disabled == 0:
    ensureSelfDllPath()
    if selfDllPathW.len > 0 and not callerAskedForSuspended:
      ctx.args[5] = uint64(callerCreationFlags or CREATE_SUSPENDED)
      shimForcedSuspend = true
    # A caller that builds its own environment block does not know about our
    # configuration, and a shim that cannot read `REPRO_MONITOR_FRAGMENT_DIR`
    # drops every record it makes. See the note above
    # `captureMonitorEnvSnapshot`.
    let callerEnv = cast[LPVOID](ctx.args[6])
    if callerEnv != nil:
      let newEnv =
        if (callerCreationFlags and CREATE_UNICODE_ENVIRONMENT) != 0:
          environmentWithMonitorConfigW(callerEnv, childEnvW)
        else:
          environmentWithMonitorConfigA(callerEnv, childEnvA)
      if newEnv != nil:
        ctx.args[6] = cast[uint64](newEnv)
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  # Resolve the thread to resume BEFORE any branch that can leave. `disabled`
  # and `initialized` are read again below and may have flipped underneath us
  # (the exit handler races this hook); the child, however, is already alive
  # and already suspended, so the debt is fixed at this point and must not
  # depend on state that can still change.
  let lpProcessInfo = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  # `ctx.result` is compared as the raw register value; the narrowing
  # `BOOL(...)` conversion is only done inside the `try`, where the record
  # actually needs the BOOL-typed value.
  # Windows BOOL is 32-bit and the x64 ABI lets a callee leave garbage in
  # the upper half of RAX, so mask before testing: a FAILED CreateProcess
  # whose high bits happen to be set would otherwise read as created, and
  # we would ResumeThread an unset hThread and inject into a garbage
  # handle. Masking keeps BOOL semantics without a narrowing conversion,
  # which in a `raises: []` proc could raise RangeDefect and take the
  # process down inside a hook.
  let created = (ctx.result and 0xFFFF_FFFF'u64) != 0'u64 and
    lpProcessInfo != nil
  # Non-nil ONLY when WE suspended a child that actually got created; the
  # `finally` below then resumes it unconditionally.
  var childMainThread: HANDLE = nil
  if created and shimForcedSuspend:
    childMainThread = lpProcessInfo[].hThread
  try:
    when defined(ioMonShimSpawnEscapeTest):
      if testSpawnEscape == tseEarlyReturn:
        return
    if initialized and disabled == 0:
      when defined(ioMonShimSpawnEscapeTest):
        if testSpawnEscape == tseRaise:
          raise newException(ValueError,
            "REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE=raise")
      let lpApplicationName = cast[LPCWSTR](ctx.args[0])
      let lpCommandLine = cast[LPWSTR](ctx.args[1])
      let r = callResultBool(ctx.result)
      var childForkRuntime = ""
      var record = baseRecord(mrProcessSpawn, moExecute)
      if created:
        record.childOsPid = uint64(lpProcessInfo[].dwProcessId)
        childForkRuntime =
          shProp.windowsForkRuntimeForProcess(lpProcessInfo[].hProcess)
      record.result = int64(r)
      var path = ""
      if lpApplicationName != nil:
        path = widePtrToString(lpApplicationName)
      elif lpCommandLine != nil:
        path = widePtrToString(cast[LPCWSTR](lpCommandLine))
      record.path = path
      record.detail = "CreateProcessW"
      if childForkRuntime.len > 0:
        record.detail.add(" fork-runtime=" & childForkRuntime)
      # Inject BEFORE emitting so the spawn record can say whether the child
      # was actually instrumented.
      #
      # The outcome used to be discarded. A failed injection then surfaced
      # only downstream, as the writer synthesising "spawn child missing
      # process-start" for a child that never reported -- which says the
      # subtree was lost but not why, and "injection failed", "the in-flight
      # cap was saturated" and "LoadLibraryW timed out" are a bug, a tuning
      # knob and a hung child respectively. Record which one it was.
      #
      # A pre-main remote thread deadlocks MSYS2/Cygwin fork runtimes. That
      # used to be handled HERE, by refusing to inject any child that has a
      # fork runtime next to its image -- which left every MSYS/Cygwin child
      # uninstrumented, `grep.exe` under `bash -c` included, and made the
      # whole subtree an unknown-scope loss.
      #
      # It is handled INSIDE `injectShimIntoChild` now. That proc parks the
      # child's main thread at its image entry point so the loader
      # initialises on the thread the OS would have used, then borrows that
      # same thread to map the shim; a child it cannot park AND that carries
      # a fork runtime is still refused, with `ioSkippedForkRuntime`. So the
      # blanket guard here was a filesystem heuristic standing in for a
      # thread-scheduling problem, and it answered "skip" for children that
      # are perfectly attachable. `childForkRuntime` is still computed, but
      # only to annotate the record.
      #
      # THE PARK IS ONLY SOUND WHEN WE OWN THE SUSPENSION. It runs the
      # child's loader, and a caller who asked for CREATE_SUSPENDED
      # themselves is entitled to a child that has executed nothing --
      # Cygwin's fork() copies the parent's address space into exactly such
      # a child. `shimForcedSuspend` is true only when the suspension is
      # ours, so it is exactly the condition under which the main thread may
      # be handed over; otherwise we pass nil and `injectShimIntoChild`
      # pins itself to the legacy technique, which is byte-for-byte what
      # this call did before.
      if created and selfDllPathW.len > 0:
        let outcome = shProp.injectShimIntoChild(lpProcessInfo[].hProcess,
          selfDllPath(), "repro_runtime_init",
          hThread = (if shimForcedSuspend: lpProcessInfo[].hThread
                     else: nil))
        if outcome != shProp.ioInjected and
            outcome != shProp.ioAlreadyPresent:
          record.detail.add(" inject=" & $outcome)
      emitSpawnRecordDurably(record)
  except CatchableError:
    discard
  finally:
    # The single place the forced suspension is undone, reached from the test
    # escapes above, from the `except`, and from the ordinary end of the try.
    # `childMainThread` is non-nil only when this hook is the one that
    # suspended the child, so this can neither strand a child nor resume one
    # the caller wanted left asleep.
    if childMainThread != nil:
      discard ResumeThread(childMainThread)
    # After the resume: ResumeThread clobbers the thread's last-error value,
    # and the caller must observe the CreateProcessW one.
    SetLastError(savedLastError)

proc snoopCreateProcessA(ctx: var hr.HookContext) {.raises: [].} =
  # Byte-for-byte the same resume-ownership contract as
  # snoopCreateProcessW -- see the note there. Only the string width and
  # the record/inject ordering differ.
  let savedFlagsA = DWORD(ctx.args[5])
  let callerAskedForSuspendedA =
    (savedFlagsA and CREATE_SUSPENDED) != 0
  # Same resume-debt discipline as `snoopCreateProcessW`; see the commentary
  # there for why the flag is captured here and discharged only in `finally`.
  var shimForcedSuspend = false
  # Same environment contract as `snoopCreateProcessW`; see the note there.
  var childEnvW: seq[uint16] = @[]
  var childEnvA: string = ""
  if initialized and disabled == 0:
    ensureSelfDllPath()
    if selfDllPathW.len > 0 and not callerAskedForSuspendedA:
      ctx.args[5] = uint64(savedFlagsA or CREATE_SUSPENDED)
      shimForcedSuspend = true
    let callerEnv = cast[LPVOID](ctx.args[6])
    if callerEnv != nil:
      let newEnv =
        if (savedFlagsA and CREATE_UNICODE_ENVIRONMENT) != 0:
          environmentWithMonitorConfigW(callerEnv, childEnvW)
        else:
          environmentWithMonitorConfigA(callerEnv, childEnvA)
      if newEnv != nil:
        ctx.args[6] = cast[uint64](newEnv)
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  # Resolved before any branch that can leave, for the reason given in
  # `snoopCreateProcessW`.
  let lpProcessInfo = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  # Windows BOOL is 32-bit and the x64 ABI lets a callee leave garbage in
  # the upper half of RAX, so mask before testing: a FAILED CreateProcess
  # whose high bits happen to be set would otherwise read as created, and
  # we would ResumeThread an unset hThread and inject into a garbage
  # handle. Masking keeps BOOL semantics without a narrowing conversion,
  # which in a `raises: []` proc could raise RangeDefect and take the
  # process down inside a hook.
  let created = (ctx.result and 0xFFFF_FFFF'u64) != 0'u64 and
    lpProcessInfo != nil
  var childMainThread: HANDLE = nil
  if created and shimForcedSuspend:
    childMainThread = lpProcessInfo[].hThread
  try:
    when defined(ioMonShimSpawnEscapeTest):
      if testSpawnEscape == tseEarlyReturn:
        return
    if initialized and disabled == 0:
      when defined(ioMonShimSpawnEscapeTest):
        if testSpawnEscape == tseRaise:
          raise newException(ValueError,
            "REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE=raise")
      let lpApplicationName = cast[LPCSTR](ctx.args[0])
      let lpCommandLine = cast[LPSTR](ctx.args[1])
      let r = callResultBool(ctx.result)
      var childForkRuntime = ""
      var record = baseRecord(mrProcessSpawn, moExecute)
      if created:
        record.childOsPid = uint64(lpProcessInfo[].dwProcessId)
        childForkRuntime =
          shProp.windowsForkRuntimeForProcess(lpProcessInfo[].hProcess)
      record.result = int64(r)
      var path = ""
      if lpApplicationName != nil:
        path = $lpApplicationName
      elif lpCommandLine != nil:
        path = $cast[cstring](lpCommandLine)
      record.path = path
      record.detail = "CreateProcessA"
      if childForkRuntime.len > 0:
        record.detail.add(" fork-runtime=" & childForkRuntime)
      emitSpawnRecordDurably(record)
      # Same contract as `snoopCreateProcessW` -- see the long note there for
      # why the fork-runtime guard is gone and why the main thread may only
      # be handed over when `shimForcedSuspend` says the suspension is ours.
      if created and selfDllPathW.len > 0:
        discard shProp.injectShimIntoChild(lpProcessInfo[].hProcess,
          selfDllPath(), "repro_runtime_init",
          hThread = (if shimForcedSuspend: lpProcessInfo[].hThread
                     else: nil))
  except CatchableError:
    discard
  finally:
    if childMainThread != nil:
      discard ResumeThread(childMainThread)
    SetLastError(savedLastError)

# --- M73 Phase 5 snoop callbacks -------------------------------------------
#
# Schema decisions (no MonitorRecordKind additions — option (b) from the
# Phase 5 milestone notes):
#
#   DeleteFileW/A      -> mrFileWrite + moFileWrite, detail = "DeleteFileW"
#                          /"DeleteFileA". The record's `flags` field is left
#                          at zero; the `detail` string carries the mutation
#                          class for downstream interpretation.
#   CreateDirectoryW/A -> mrFileWrite + moFileWrite, detail =
#                          "CreateDirectoryW"/"CreateDirectoryA". Same
#                          rationale: mutation event with a directory-create
#                          discriminator in `detail`.
#   CopyFileW/A        -> TWO records per call: source (mrFileOpen +
#                          moFileRead, detail = "CopyFileW:src") and dest
#                          (mrFileWrite + moFileWrite,
#                          detail = "CopyFileW:dst"). Mirrors
#                          Monitor-Hook-Shim.md §"CopyFileW / CopyFileA |
#                          Read source and create/write destination".
#   MoveFileExW/A      -> TWO records: source (mrFileWrite + moFileWrite,
#                          detail = "MoveFileExW:src") and dest (mrFileWrite +
#                          moFileWrite, detail = "MoveFileExW:dst"). lpNewFileName
#                          MAY be NULL (delete-on-reboot); in that case only
#                          the source record is emitted with the
#                          MOVEFILE_DELAY_UNTIL_REBOOT-aware detail.
#   GetFileInformationByHandleEx -> mrPathProbe + moPathProbe with the path
#                          resolved via `pathForHandle`. detail =
#                          "GetFileInformationByHandleEx". When the handle's
#                          path is unknown (caller passed a handle the shim
#                          didn't see open), we still emit the record with
#                          path = "" so the per-call count is preserved.
#   SetCurrentDirectoryW/A -> mrFileOpen + moExecute with the new cwd in
#                          `path`, detail = "SetCurrentDirectoryW"/A. The
#                          spec calls it "update process cwd model"; the
#                          existing schema has no cwd-specific kind so we
#                          pick the closest "process-context update" pair.
#   NtCreateFile       -> mrFileOpen + moFileOpen, detail = "NtCreateFile",
#                          path = "" (extraction deferred — the path lives
#                          inside OBJECT_ATTRIBUTES.ObjectName and decoding
#                          it under the shim hot-path requires more care
#                          than Phase 5 allows; the dispatch-mechanism test
#                          only requires the snoop FIRE, not preserve the
#                          path).

proc snoopDeleteFileW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = widePtrToString(lpFileName)
    record.result = int64(r)
    record.detail = "DeleteFileW"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopDeleteFileA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileWrite, moFileWrite)
    if lpFileName != nil:
      record.path = $lpFileName
    record.result = int64(r)
    record.detail = "DeleteFileA"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCreateDirectoryW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpPathName = cast[LPCWSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = widePtrToString(lpPathName)
    record.result = int64(r)
    record.detail = "CreateDirectoryW"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCreateDirectoryA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpPathName = cast[LPCSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileWrite, moFileWrite)
    if lpPathName != nil:
      record.path = $lpPathName
    record.result = int64(r)
    record.detail = "CreateDirectoryA"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCopyFileW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpExisting = cast[LPCWSTR](ctx.args[0])
    let lpNew      = cast[LPCWSTR](ctx.args[1])
    let r = callResultBool(ctx.result)
    var src = baseRecord(mrFileOpen, moFileRead)
    src.path = widePtrToString(lpExisting)
    src.result = int64(r)
    src.detail = "CopyFileW:src"
    emitRecord(src)
    var dst = baseRecord(mrFileWrite, moFileWrite)
    dst.path = widePtrToString(lpNew)
    dst.result = int64(r)
    dst.detail = "CopyFileW:dst"
    emitRecord(dst)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCopyFileA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpExisting = cast[LPCSTR](ctx.args[0])
    let lpNew      = cast[LPCSTR](ctx.args[1])
    let r = callResultBool(ctx.result)
    var src = baseRecord(mrFileOpen, moFileRead)
    if lpExisting != nil:
      src.path = $lpExisting
    src.result = int64(r)
    src.detail = "CopyFileA:src"
    emitRecord(src)
    var dst = baseRecord(mrFileWrite, moFileWrite)
    if lpNew != nil:
      dst.path = $lpNew
    dst.result = int64(r)
    dst.detail = "CopyFileA:dst"
    emitRecord(dst)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopMoveFileExW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpExisting = cast[LPCWSTR](ctx.args[0])
    let lpNew      = cast[LPCWSTR](ctx.args[1])
    let r = callResultBool(ctx.result)
    var src = baseRecord(mrFileWrite, moFileWrite)
    src.path = widePtrToString(lpExisting)
    src.result = int64(r)
    src.detail = "MoveFileExW:src"
    emitRecord(src)
    # lpNewFileName MAY be nil when MOVEFILE_DELAY_UNTIL_REBOOT is set
    # WITHOUT a target (i.e. delete-on-reboot of the source). Emit a
    # destination record only when we actually have a target path.
    if lpNew != nil:
      var dst = baseRecord(mrFileWrite, moFileWrite)
      dst.path = widePtrToString(lpNew)
      dst.result = int64(r)
      dst.detail = "MoveFileExW:dst"
      emitRecord(dst)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopMoveFileExA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpExisting = cast[LPCSTR](ctx.args[0])
    let lpNew      = cast[LPCSTR](ctx.args[1])
    let r = callResultBool(ctx.result)
    var src = baseRecord(mrFileWrite, moFileWrite)
    if lpExisting != nil:
      src.path = $lpExisting
    src.result = int64(r)
    src.detail = "MoveFileExA:src"
    emitRecord(src)
    if lpNew != nil:
      var dst = baseRecord(mrFileWrite, moFileWrite)
      dst.path = $lpNew
      dst.result = int64(r)
      dst.detail = "MoveFileExA:dst"
      emitRecord(dst)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopGetFileInformationByHandleEx(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let hFile = cast[HANDLE](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrPathProbe, moPathProbe)
    record.path = pathForHandle(hFile)
    record.result = int64(r)
    record.probeResult = probeFromBool(r)
    record.detail = "GetFileInformationByHandleEx"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopSetCurrentDirectoryW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpPathName = cast[LPCWSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileOpen, moExecute)
    record.path = widePtrToString(lpPathName)
    record.result = int64(r)
    record.detail = "SetCurrentDirectoryW"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopSetCurrentDirectoryA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpPathName = cast[LPCSTR](ctx.args[0])
    let r = callResultBool(ctx.result)
    var record = baseRecord(mrFileOpen, moExecute)
    if lpPathName != nil:
      record.path = $lpPathName
    record.result = int64(r)
    record.detail = "SetCurrentDirectoryA"
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopNtCreateFile(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let oaPtr = cast[pointer](ctx.args[2])
    let path = objectAttributesToString(oaPtr)
    let desiredAccess = uint32(ctx.args[1] and 0xFFFFFFFF'u64)
    let createDisposition = uint32(ctx.args[7] and 0xFFFFFFFF'u64)
    # Data-access bits in ACCESS_MASK. None set ⇒ stat-class probe.
    const dataAccessBits =
      0x00000001'u32 or  # FILE_READ_DATA / FILE_LIST_DIRECTORY
      0x00000002'u32 or  # FILE_WRITE_DATA / FILE_ADD_FILE
      0x00000004'u32 or  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
      0x80000000'u32 or  # GENERIC_READ
      0x40000000'u32 or  # GENERIC_WRITE
      0x10000000'u32     # GENERIC_ALL
    let isProbe = (desiredAccess and dataAccessBits) == 0'u32
    let writeAccess =
      (desiredAccess and (0x00000002'u32 or 0x00000004'u32 or
                          0x40000000'u32)) != 0'u32
    let writeDisposition = createDisposition == 2'u32 or
                           createDisposition == 3'u32 or
                           createDisposition == 5'u32
    let isWrite = writeAccess or writeDisposition
    let nt = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))
    if isProbe:
      var record = baseRecord(mrPathProbe, moPathProbe)
      record.path = path
      record.result = int64(nt)
      record.detail = "NtCreateFile"
      emitRecord(record)
    else:
      let recKind = if isWrite: mrFileWrite else: mrFileOpen
      let recMode = if isWrite: moFileWrite else: moFileOpen
      var record = baseRecord(recKind, recMode)
      record.path = path
      record.result = int64(nt)
      record.detail = "NtCreateFile"
      emitRecord(record)
      if path.len > 0 and nt >= 0:
        let phPtr = cast[ptr HANDLE](ctx.args[0])
        if phPtr != nil:
          let h = phPtr[]
          if h != nil and h != INVALID_HANDLE_VALUE:
            rememberHandlePath(h, path)
            # M5 — the NT-layer arm of the named-pipe / ADS classification.
            # CreateFileW lowers to NtCreateFile, so a client that calls the NT
            # export directly (or whose kernel32 hook did not land) is still
            # seen. A duplicate record for the same open is harmless: the merge
            # dedups an IPC peer by (pid, destination).
            classifyOpenedPath(path, h, desiredAccess,
              spelledPath = (if mayBeNamedPipe(path):
                               objectAttributesRawName(oaPtr)
                             else: ""))
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopNtQueryAttributesFileImpl(ctx: var hr.HookContext;
                                     detail: string) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let oaPtr = cast[pointer](ctx.args[0])
    let path = objectAttributesToString(oaPtr)
    let nt = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))
    var record = baseRecord(mrPathProbe, moPathProbe)
    record.path = path
    record.result = int64(nt)
    record.detail = detail
    emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopNtQueryAttributesFile(ctx: var hr.HookContext) {.raises: [].} =
  snoopNtQueryAttributesFileImpl(ctx, "NtQueryAttributesFile")

proc snoopNtQueryFullAttributesFile(ctx: var hr.HookContext) {.raises: [].} =
  snoopNtQueryAttributesFileImpl(ctx, "NtQueryFullAttributesFile")

proc snoopNtQueryInformationByName(ctx: var hr.HookContext) {.raises: [].} =
  ## libuv's uv_fs_stat fast-path on Win11. Emits an mrPathProbe.
  snoopNtQueryAttributesFileImpl(ctx, "NtQueryInformationByName")

proc emitFindFirstRecord(searchPath: string; resultHandle: HANDLE;
                         detail: string) {.raises: [].} =
  ## Emit mrDirectoryEnumerate for a FindFirstFile*W call. The search
  ## ``lpFileName`` is typically a directory followed by ``\*`` or
  ## ``\<pattern>``; strip the trailing pattern so the path identifies
  ## the directory itself. We don't track the returned HANDLE for
  ## subsequent FindNextFileW because each readdir() typically issues
  ## ONE FindFirstFileExW plus FindNextFileW calls until end-of-list,
  ## so one mrDirectoryEnumerate per FindFirstFileExW is the right
  ## granularity.
  if searchPath.len == 0:
    return
  var dirPath = searchPath
  # Strip trailing "\*" or "\\*" or "/*"/"\*.<ext>" — keep the directory.
  let lastSep = max(dirPath.rfind('\\'), dirPath.rfind('/'))
  if lastSep > 0:
    let tail = dirPath[lastSep + 1 .. ^1]
    if tail.startsWith("*") or tail == "*.*" or tail == "*":
      dirPath = dirPath[0 ..< lastSep]
  let success =
    resultHandle != INVALID_HANDLE_VALUE and resultHandle != nil
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = dirPath
  record.result = if success: 1'i64 else: 0'i64
  record.detail = detail
  emitRecord(record)

proc snoopFindFirstFileW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let searchPath = widePtrToString(lpFileName)
    let hFind = cast[HANDLE](ctx.result)
    emitFindFirstRecord(searchPath, hFind, "FindFirstFileW")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopFindFirstFileExW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpFileName = cast[LPCWSTR](ctx.args[0])
    let searchPath = widePtrToString(lpFileName)
    let hFind = cast[HANDLE](ctx.result)
    emitFindFirstRecord(searchPath, hFind, "FindFirstFileExW")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopFindNextFileW(ctx: var hr.HookContext) {.raises: [].} =
  # FindNextFileW iterates the search handle — no per-call record is
  # emitted (the enclosing FindFirstFile already accounted for the
  # readdir). Forward through the chain unobserved.
  hr.callNext(ctx)

proc snoopFindClose(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)

proc snoopNtQueryDirectoryFileEx(ctx: var hr.HookContext) {.raises: [].} =
  ## libuv's uv_fs_scandir on Win10 1709+. The handle was opened via
  ## NtCreateFile / CreateFileW with FILE_LIST_DIRECTORY; lookup its
  ## remembered path. Multiple chunked calls per readdir() — record
  ## only the first per handle.
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    # SL_RESTART_SCAN = 0x00000001. Anything else (SL_RETURN_ON_DISK_FULL,
    # SL_QUERY_DIRECTORY_MASK, SL_INDEX_SPECIFIED, ...) is irrelevant
    # for the first-call-per-handle gate.
    let queryFlags = DWORD(ctx.args[8])
    let restartScan = (queryFlags and 0x00000001'u32) != 0'u32
    let h = cast[HANDLE](ctx.args[0])
    var shouldRecord = restartScan
    var dirPath = ""
    acquire(fdLock)
    try:
      let key = handleKey(h)
      if handlePaths.hasKey(key):
        dirPath = handlePaths[key]
        if not dirPath.startsWith("[enum]:"):
          shouldRecord = true
          handlePaths[key] = "[enum]:" & dirPath
        elif restartScan:
          shouldRecord = true
          dirPath = dirPath["[enum]:".len .. ^1]
    finally:
      release(fdLock)
    let nt = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))
    if shouldRecord and dirPath.len > 0:
      var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
      record.path = dirPath
      record.result = int64(nt)
      record.detail = "NtQueryDirectoryFileEx"
      emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopNtQueryDirectoryFile(ctx: var hr.HookContext) {.raises: [].} =
  ## libuv's uv_fs_scandir → NtQueryDirectoryFile on a handle that was
  ## opened earlier via NtCreateFile / CreateFileW. Multiple calls per
  ## readdir() typically occur (chunked enumeration); we record only
  ## the first call per handle by mutating its entry in handlePaths.
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let restartScan = BOOL(ctx.args[10])
    let h = cast[HANDLE](ctx.args[0])
    var shouldRecord = restartScan != 0
    var dirPath = ""
    acquire(fdLock)
    try:
      let key = handleKey(h)
      if handlePaths.hasKey(key):
        dirPath = handlePaths[key]
        if not dirPath.startsWith("[enum]:"):
          shouldRecord = true
          handlePaths[key] = "[enum]:" & dirPath
        elif restartScan != 0:
          shouldRecord = true
          dirPath = dirPath["[enum]:".len .. ^1]
    finally:
      release(fdLock)
    let nt = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))
    if shouldRecord and dirPath.len > 0:
      var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
      record.path = dirPath
      record.result = int64(nt)
      record.detail = "NtQueryDirectoryFile"
      emitRecord(record)
  except CatchableError:
    discard
  SetLastError(savedLastError)

# --- Win32 trampolines installed into the IAT ------------------------------
#
# Each trampoline matches the corresponding Win32 stdcall signature. Its job
# is to pack args into a HookContext, dispatch through the registry, and
# unpack ctx.result back to the Win32 return type. The registry walks the
# chain (snoop → original) for us.

proc trampolineCreateFileW(lpFileName: LPCWSTR, dwDesiredAccess: DWORD,
                            dwShareMode: DWORD,
                            lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                            dwCreationDisposition: DWORD,
                            dwFlagsAndAttributes: DWORD,
                            hTemplateFile: HANDLE): HANDLE {.stdcall.} =
  if origCreateFileW == nil:
    return INVALID_HANDLE_VALUE
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    uint64(dwDesiredAccess),
    uint64(dwShareMode),
    cast[uint64](lpSecurityAttributes),
    uint64(dwCreationDisposition),
    uint64(dwFlagsAndAttributes),
    cast[uint64](hTemplateFile)
  ])
  hr.dispatchShimHook(hr.HookCreateFileW, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineCreateFileA(lpFileName: LPCSTR, dwDesiredAccess: DWORD,
                            dwShareMode: DWORD,
                            lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                            dwCreationDisposition: DWORD,
                            dwFlagsAndAttributes: DWORD,
                            hTemplateFile: HANDLE): HANDLE {.stdcall.} =
  if origCreateFileA == nil:
    return INVALID_HANDLE_VALUE
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    uint64(dwDesiredAccess),
    uint64(dwShareMode),
    cast[uint64](lpSecurityAttributes),
    uint64(dwCreationDisposition),
    uint64(dwFlagsAndAttributes),
    cast[uint64](hTemplateFile)
  ])
  hr.dispatchShimHook(hr.HookCreateFileA, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineReadFile(hFile: HANDLE, lpBuffer: LPVOID,
                         nNumberOfBytesToRead: DWORD,
                         lpNumberOfBytesRead: ptr DWORD,
                         lpOverlapped: LPOVERLAPPED): BOOL {.stdcall.} =
  if origReadFile == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFile),
    cast[uint64](lpBuffer),
    uint64(nNumberOfBytesToRead),
    cast[uint64](lpNumberOfBytesRead),
    cast[uint64](lpOverlapped)
  ])
  hr.dispatchShimHook(hr.HookReadFile, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineWriteFile(hFile: HANDLE, lpBuffer: LPCVOID,
                          nNumberOfBytesToWrite: DWORD,
                          lpNumberOfBytesWritten: ptr DWORD,
                          lpOverlapped: LPOVERLAPPED): BOOL {.stdcall.} =
  if origWriteFile == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFile),
    cast[uint64](lpBuffer),
    uint64(nNumberOfBytesToWrite),
    cast[uint64](lpNumberOfBytesWritten),
    cast[uint64](lpOverlapped)
  ])
  hr.dispatchShimHook(hr.HookWriteFile, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCloseHandle(hObject: HANDLE): BOOL {.stdcall.} =
  if origCloseHandle == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](hObject)])
  hr.dispatchShimHook(hr.HookCloseHandle, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineNtTerminateProcess(ProcessHandle: HANDLE;
                                  ExitStatus: int32): NTSTATUS {.stdcall.} =
  if origNtTerminateProcess == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](ProcessHandle),
    uint64(uint32(ExitStatus))
  ])
  hr.dispatchShimHook(hr.HookNtTerminateProcess, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineGetFileAttributesExW(lpFileName: LPCWSTR, fInfoLevelId: DWORD,
                                     lpFileInformation: LPVOID): BOOL
                                     {.stdcall.} =
  if origGetFileAttributesExW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    uint64(fInfoLevelId),
    cast[uint64](lpFileInformation)
  ])
  hr.dispatchShimHook(hr.HookGetFileAttributesExW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineGetFileAttributesExA(lpFileName: LPCSTR, fInfoLevelId: DWORD,
                                     lpFileInformation: LPVOID): BOOL
                                     {.stdcall.} =
  if origGetFileAttributesExA == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    uint64(fInfoLevelId),
    cast[uint64](lpFileInformation)
  ])
  hr.dispatchShimHook(hr.HookGetFileAttributesExA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineGetFileAttributesW(lpFileName: LPCWSTR): DWORD {.stdcall.} =
  if origGetFileAttributesW == nil:
    return 0xFFFFFFFF'u32
  var ctx = hr.HookContext(args: @[cast[uint64](lpFileName)])
  hr.dispatchShimHook(hr.HookGetFileAttributesW, ctx)
  result = DWORD(ctx.result)

proc trampolineGetFileAttributesA(lpFileName: LPCSTR): DWORD {.stdcall.} =
  if origGetFileAttributesA == nil:
    return 0xFFFFFFFF'u32
  var ctx = hr.HookContext(args: @[cast[uint64](lpFileName)])
  hr.dispatchShimHook(hr.HookGetFileAttributesA, ctx)
  result = DWORD(ctx.result)

proc trampolineCreateProcessW(lpApplicationName: LPCWSTR,
                               lpCommandLine: LPWSTR,
                               lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                               lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                               bInheritHandles: BOOL,
                               dwCreationFlags: DWORD,
                               lpEnvironment: LPVOID,
                               lpCurrentDirectory: LPCWSTR,
                               lpStartupInfo: ptr STARTUPINFOW,
                               lpProcessInformation: ptr PROCESS_INFORMATION):
                               BOOL {.stdcall.} =
  if origCreateProcessW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpApplicationName),
    cast[uint64](lpCommandLine),
    cast[uint64](lpProcessAttributes),
    cast[uint64](lpThreadAttributes),
    uint64(uint32(bInheritHandles)),
    uint64(dwCreationFlags),
    cast[uint64](lpEnvironment),
    cast[uint64](lpCurrentDirectory),
    cast[uint64](lpStartupInfo),
    cast[uint64](lpProcessInformation)
  ])
  hr.dispatchShimHook(hr.HookCreateProcessW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCreateProcessA(lpApplicationName: LPCSTR,
                               lpCommandLine: LPSTR,
                               lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                               lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                               bInheritHandles: BOOL,
                               dwCreationFlags: DWORD,
                               lpEnvironment: LPVOID,
                               lpCurrentDirectory: LPCSTR,
                               lpStartupInfo: ptr STARTUPINFOA,
                               lpProcessInformation: ptr PROCESS_INFORMATION):
                               BOOL {.stdcall.} =
  if origCreateProcessA == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpApplicationName),
    cast[uint64](lpCommandLine),
    cast[uint64](lpProcessAttributes),
    cast[uint64](lpThreadAttributes),
    uint64(uint32(bInheritHandles)),
    uint64(dwCreationFlags),
    cast[uint64](lpEnvironment),
    cast[uint64](lpCurrentDirectory),
    cast[uint64](lpStartupInfo),
    cast[uint64](lpProcessInformation)
  ])
  hr.dispatchShimHook(hr.HookCreateProcessA, ctx)
  result = BOOL(uint32(ctx.result))

# --- M73 Phase 5 trampolines (matched stdcall signatures) ------------------

proc trampolineDeleteFileW(lpFileName: LPCWSTR): BOOL {.stdcall.} =
  if origDeleteFileW == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](lpFileName)])
  hr.dispatchShimHook(hr.HookDeleteFileW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineDeleteFileA(lpFileName: LPCSTR): BOOL {.stdcall.} =
  if origDeleteFileA == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](lpFileName)])
  hr.dispatchShimHook(hr.HookDeleteFileA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCreateDirectoryW(lpPathName: LPCWSTR,
                                 lpSecurityAttributes: LPSECURITY_ATTRIBUTES):
                                 BOOL {.stdcall.} =
  if origCreateDirectoryW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpPathName),
    cast[uint64](lpSecurityAttributes)
  ])
  hr.dispatchShimHook(hr.HookCreateDirectoryW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCreateDirectoryA(lpPathName: LPCSTR,
                                 lpSecurityAttributes: LPSECURITY_ATTRIBUTES):
                                 BOOL {.stdcall.} =
  if origCreateDirectoryA == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpPathName),
    cast[uint64](lpSecurityAttributes)
  ])
  hr.dispatchShimHook(hr.HookCreateDirectoryA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCopyFileW(lpExistingFileName: LPCWSTR,
                          lpNewFileName: LPCWSTR,
                          bFailIfExists: BOOL): BOOL {.stdcall.} =
  if origCopyFileW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpExistingFileName),
    cast[uint64](lpNewFileName),
    uint64(uint32(bFailIfExists))
  ])
  hr.dispatchShimHook(hr.HookCopyFileW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineCopyFileA(lpExistingFileName: LPCSTR,
                          lpNewFileName: LPCSTR,
                          bFailIfExists: BOOL): BOOL {.stdcall.} =
  if origCopyFileA == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpExistingFileName),
    cast[uint64](lpNewFileName),
    uint64(uint32(bFailIfExists))
  ])
  hr.dispatchShimHook(hr.HookCopyFileA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineMoveFileExW(lpExistingFileName: LPCWSTR,
                            lpNewFileName: LPCWSTR,
                            dwFlags: DWORD): BOOL {.stdcall.} =
  if origMoveFileExW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpExistingFileName),
    cast[uint64](lpNewFileName),
    uint64(dwFlags)
  ])
  hr.dispatchShimHook(hr.HookMoveFileExW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineMoveFileExA(lpExistingFileName: LPCSTR,
                            lpNewFileName: LPCSTR,
                            dwFlags: DWORD): BOOL {.stdcall.} =
  if origMoveFileExA == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpExistingFileName),
    cast[uint64](lpNewFileName),
    uint64(dwFlags)
  ])
  hr.dispatchShimHook(hr.HookMoveFileExA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineGetFileInformationByHandleEx(hFile: HANDLE,
                                              FileInformationClass: DWORD,
                                              lpFileInformation: LPVOID,
                                              dwBufferSize: DWORD): BOOL
                                              {.stdcall.} =
  if origGetFileInformationByHandleEx == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFile),
    uint64(FileInformationClass),
    cast[uint64](lpFileInformation),
    uint64(dwBufferSize)
  ])
  hr.dispatchShimHook(hr.HookGetFileInformationByHandleEx, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineSetCurrentDirectoryW(lpPathName: LPCWSTR): BOOL {.stdcall.} =
  if origSetCurrentDirectoryW == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](lpPathName)])
  hr.dispatchShimHook(hr.HookSetCurrentDirectoryW, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineSetCurrentDirectoryA(lpPathName: LPCSTR): BOOL {.stdcall.} =
  if origSetCurrentDirectoryA == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](lpPathName)])
  hr.dispatchShimHook(hr.HookSetCurrentDirectoryA, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineNtCreateFile(FileHandle: ptr HANDLE,
                             DesiredAccess: DWORD,
                             ObjectAttributes: pointer,
                             IoStatusBlock: pointer,
                             AllocationSize: ptr LARGE_INTEGER,
                             FileAttributes: DWORD,
                             ShareAccess: DWORD,
                             CreateDisposition: DWORD,
                             CreateOptions: DWORD,
                             EaBuffer: pointer,
                             EaLength: DWORD): NTSTATUS {.stdcall.} =
  if origNtCreateFile == nil:
    return NTSTATUS(0xC0000001'i32)  # STATUS_UNSUCCESSFUL
  var ctx = hr.HookContext(args: @[
    cast[uint64](FileHandle),
    uint64(DesiredAccess),
    cast[uint64](ObjectAttributes),
    cast[uint64](IoStatusBlock),
    cast[uint64](AllocationSize),
    uint64(FileAttributes),
    uint64(ShareAccess),
    uint64(CreateDisposition),
    uint64(CreateOptions),
    cast[uint64](EaBuffer),
    uint64(EaLength)
  ])
  hr.dispatchShimHook(hr.HookNtCreateFile, ctx)
  # NTSTATUS reinterpret: ctx.result holds the uint32-packed status.
  # Same-size cast avoids `chckRange64` (per the
  # nim_cast_narrowing_rangecheck memo).
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineNtQueryAttributesFile(ObjectAttributes: pointer;
                                      FileInformation: pointer):
                                      NTSTATUS {.stdcall.} =
  if origNtQueryAttributesFile == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](ObjectAttributes),
    cast[uint64](FileInformation)
  ])
  hr.dispatchShimHook(hr.HookNtQueryAttributesFile, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineNtQueryFullAttributesFile(ObjectAttributes: pointer;
                                          FileInformation: pointer):
                                          NTSTATUS {.stdcall.} =
  if origNtQueryFullAttributesFile == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](ObjectAttributes),
    cast[uint64](FileInformation)
  ])
  hr.dispatchShimHook(hr.HookNtQueryFullAttributesFile, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineNtQueryDirectoryFileEx(FileHandle: HANDLE;
                                       Event: HANDLE;
                                       ApcRoutine: pointer;
                                       ApcContext: pointer;
                                       IoStatusBlock: pointer;
                                       FileInformation: pointer;
                                       Length: DWORD;
                                       FileInformationClass: DWORD;
                                       QueryFlags: DWORD;
                                       FileName: pointer):
                                       NTSTATUS {.stdcall.} =
  if origNtQueryDirectoryFileEx == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](FileHandle),
    cast[uint64](Event),
    cast[uint64](ApcRoutine),
    cast[uint64](ApcContext),
    cast[uint64](IoStatusBlock),
    cast[uint64](FileInformation),
    uint64(Length),
    uint64(FileInformationClass),
    uint64(QueryFlags),
    cast[uint64](FileName)
  ])
  hr.dispatchShimHook(hr.HookNtQueryDirectoryFileEx, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineNtQueryInformationByName(ObjectAttributes: pointer;
                                         IoStatusBlock: pointer;
                                         FileInformation: pointer;
                                         Length: DWORD;
                                         FileInformationClass: DWORD):
                                         NTSTATUS {.stdcall.} =
  if origNtQueryInformationByName == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](ObjectAttributes),
    cast[uint64](IoStatusBlock),
    cast[uint64](FileInformation),
    uint64(Length),
    uint64(FileInformationClass)
  ])
  hr.dispatchShimHook(hr.HookNtQueryInformationByName, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

proc trampolineFindFirstFileW(lpFileName: LPCWSTR;
                               lpFindFileData: pointer):
                               HANDLE {.stdcall.} =
  if origFindFirstFileW == nil:
    return INVALID_HANDLE_VALUE
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    cast[uint64](lpFindFileData)
  ])
  hr.dispatchShimHook(hr.HookFindFirstFileW, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineFindFirstFileExW(lpFileName: LPCWSTR;
                                 fInfoLevelId: DWORD;
                                 lpFindFileData: pointer;
                                 fSearchOp: DWORD;
                                 lpSearchFilter: pointer;
                                 dwAdditionalFlags: DWORD):
                                 HANDLE {.stdcall.} =
  if origFindFirstFileExW == nil:
    return INVALID_HANDLE_VALUE
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpFileName),
    uint64(fInfoLevelId),
    cast[uint64](lpFindFileData),
    uint64(fSearchOp),
    cast[uint64](lpSearchFilter),
    uint64(dwAdditionalFlags)
  ])
  hr.dispatchShimHook(hr.HookFindFirstFileExW, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineFindNextFileW(hFindFile: HANDLE;
                              lpFindFileData: pointer):
                              BOOL {.stdcall.} =
  if origFindNextFileW == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFindFile),
    cast[uint64](lpFindFileData)
  ])
  hr.dispatchShimHook(hr.HookFindNextFileW, ctx)
  result = callResultBool(ctx.result)

proc trampolineFindClose(hFindFile: HANDLE): BOOL {.stdcall.} =
  if origFindClose == nil:
    return 0
  var ctx = hr.HookContext(args: @[cast[uint64](hFindFile)])
  hr.dispatchShimHook(hr.HookFindClose, ctx)
  result = callResultBool(ctx.result)

proc trampolineGetProcAddress(hModule: HANDLE;
                               lpProcName: LPCSTR): pointer {.stdcall.} =
  if origGetProcAddress == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    cast[uint64](hModule),
    cast[uint64](lpProcName)
  ])
  hr.dispatchShimHook(hr.HookGetProcAddress, ctx)
  result = cast[pointer](ctx.result)

proc trampolineNtQueryDirectoryFile(FileHandle: HANDLE;
                                     Event: HANDLE;
                                     ApcRoutine: pointer;
                                     ApcContext: pointer;
                                     IoStatusBlock: pointer;
                                     FileInformation: pointer;
                                     Length: DWORD;
                                     FileInformationClass: DWORD;
                                     ReturnSingleEntry: BOOL;
                                     FileName: pointer;
                                     RestartScan: BOOL):
                                     NTSTATUS {.stdcall.} =
  if origNtQueryDirectoryFile == nil:
    return NTSTATUS(0xC0000001'i32)
  var ctx = hr.HookContext(args: @[
    cast[uint64](FileHandle),
    cast[uint64](Event),
    cast[uint64](ApcRoutine),
    cast[uint64](ApcContext),
    cast[uint64](IoStatusBlock),
    cast[uint64](FileInformation),
    uint64(Length),
    uint64(FileInformationClass),
    uint64(ReturnSingleEntry),
    cast[uint64](FileName),
    uint64(RestartScan)
  ])
  hr.dispatchShimHook(hr.HookNtQueryDirectoryFile, ctx)
  result = cast[NTSTATUS](uint32(ctx.result and 0xFFFFFFFF'u64))

# ---------------------------------------------------------------------------
# M5 — original wrappers, snoop callbacks and trampolines for the IPC-connect,
# external-content and non-determinism surface.
#
# Three capabilities the M4 profile declared as gaps, each now backed by a
# record kind rather than by a hooked entry point that produces nothing:
#
#   mcapIpcConnect      -> mrIpcConnect      (connect / WSAConnect, plus the
#                          named-pipe classification in the CreateFile snoops)
#   mcapExternalContent -> mrExternalContent (file mappings, anonymous pipes,
#                          NTFS alternate data streams) + mrFileRead/mrFileWrite
#                          for a view of a FILE-backed section
#   mcapNonDeterminism  -> mrNonDeterministic (entropy) + mrTimeRead (clocks)
# ---------------------------------------------------------------------------

proc originalConnect(ctx: var hr.HookContext) {.raises: [].} =
  if origConnect == nil:
    ctx.result = uint64(0xFFFFFFFF'u32)          # SOCKET_ERROR
    return
  let r = origConnect(uint(ctx.args[0]), cast[pointer](ctx.args[1]),
    cast[int32](uint32(ctx.args[2])))
  ctx.result = uint64(uint32(r))

proc originalWSAConnect(ctx: var hr.HookContext) {.raises: [].} =
  if origWSAConnect == nil:
    ctx.result = uint64(0xFFFFFFFF'u32)
    return
  let r = origWSAConnect(uint(ctx.args[0]), cast[pointer](ctx.args[1]),
    cast[int32](uint32(ctx.args[2])), cast[pointer](ctx.args[3]),
    cast[pointer](ctx.args[4]), cast[pointer](ctx.args[5]),
    cast[pointer](ctx.args[6]))
  ctx.result = uint64(uint32(r))

proc originalCreateFileMappingW(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateFileMappingW == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origCreateFileMappingW(
    cast[HANDLE](ctx.args[0]), cast[LPSECURITY_ATTRIBUTES](ctx.args[1]),
    DWORD(ctx.args[2]), DWORD(ctx.args[3]), DWORD(ctx.args[4]),
    cast[LPCWSTR](ctx.args[5])))

proc originalCreateFileMappingA(ctx: var hr.HookContext) {.raises: [].} =
  if origCreateFileMappingA == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origCreateFileMappingA(
    cast[HANDLE](ctx.args[0]), cast[LPSECURITY_ATTRIBUTES](ctx.args[1]),
    DWORD(ctx.args[2]), DWORD(ctx.args[3]), DWORD(ctx.args[4]),
    cast[LPCSTR](ctx.args[5])))

proc originalOpenFileMappingW(ctx: var hr.HookContext) {.raises: [].} =
  if origOpenFileMappingW == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origOpenFileMappingW(
    DWORD(ctx.args[0]), BOOL(uint32(ctx.args[1])), cast[LPCWSTR](ctx.args[2])))

proc originalOpenFileMappingA(ctx: var hr.HookContext) {.raises: [].} =
  if origOpenFileMappingA == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origOpenFileMappingA(
    DWORD(ctx.args[0]), BOOL(uint32(ctx.args[1])), cast[LPCSTR](ctx.args[2])))

proc originalMapViewOfFile(ctx: var hr.HookContext) {.raises: [].} =
  if origMapViewOfFile == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origMapViewOfFile(
    cast[HANDLE](ctx.args[0]), DWORD(ctx.args[1]), DWORD(ctx.args[2]),
    DWORD(ctx.args[3]), SIZE_T(ctx.args[4])))

proc originalMapViewOfFileEx(ctx: var hr.HookContext) {.raises: [].} =
  if origMapViewOfFileEx == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origMapViewOfFileEx(
    cast[HANDLE](ctx.args[0]), DWORD(ctx.args[1]), DWORD(ctx.args[2]),
    DWORD(ctx.args[3]), SIZE_T(ctx.args[4]), cast[LPVOID](ctx.args[5])))

proc originalCreatePipe(ctx: var hr.HookContext) {.raises: [].} =
  if origCreatePipe == nil:
    ctx.result = 0
    return
  let r = origCreatePipe(cast[ptr HANDLE](ctx.args[0]),
    cast[ptr HANDLE](ctx.args[1]), cast[LPSECURITY_ATTRIBUTES](ctx.args[2]),
    DWORD(ctx.args[3]))
  ctx.result = uint64(uint32(r))

proc originalBCryptGenRandom(ctx: var hr.HookContext) {.raises: [].} =
  if origBCryptGenRandom == nil:
    ctx.result = uint64(0xC0000001'u32)          # STATUS_UNSUCCESSFUL
    return
  let r = origBCryptGenRandom(cast[HANDLE](ctx.args[0]),
    cast[pointer](ctx.args[1]), DWORD(ctx.args[2]), DWORD(ctx.args[3]))
  ctx.result = uint64(uint32(r))

proc originalProcessPrng(ctx: var hr.HookContext) {.raises: [].} =
  if origProcessPrng == nil:
    ctx.result = 0
    return
  let r = origProcessPrng(cast[pointer](ctx.args[0]), SIZE_T(ctx.args[1]))
  ctx.result = uint64(uint32(r))

proc originalSystemFunction036(ctx: var hr.HookContext) {.raises: [].} =
  if origSystemFunction036 == nil:
    ctx.result = 0
    return
  let r = origSystemFunction036(cast[pointer](ctx.args[0]), DWORD(ctx.args[1]))
  ctx.result = uint64(r)

proc originalCryptGenRandom(ctx: var hr.HookContext) {.raises: [].} =
  if origCryptGenRandom == nil:
    ctx.result = 0
    return
  let r = origCryptGenRandom(uint(ctx.args[0]), DWORD(ctx.args[1]),
    cast[pointer](ctx.args[2]))
  ctx.result = uint64(uint32(r))

proc originalQueryPerformanceCounter(ctx: var hr.HookContext) {.raises: [].} =
  if origQueryPerformanceCounter == nil:
    ctx.result = 0
    return
  let r = origQueryPerformanceCounter(cast[ptr LARGE_INTEGER](ctx.args[0]))
  ctx.result = uint64(uint32(r))

proc originalGetSystemTimeAsFileTime(ctx: var hr.HookContext) {.raises: [].} =
  if origGetSystemTimeAsFileTime == nil:
    return
  origGetSystemTimeAsFileTime(cast[pointer](ctx.args[0]))

proc originalGetTickCount64(ctx: var hr.HookContext) {.raises: [].} =
  if origGetTickCount64 == nil:
    ctx.result = 0
    return
  ctx.result = origGetTickCount64()

# --- M10 original callbacks (observed environment) -------------------------
#
# Every one of these returns the callee's value UNCHANGED. An environment read
# is observed, never altered: a shim that answered a getenv itself would be
# changing the build it is supposed to be describing.

proc originalGetEnvironmentVariableW(ctx: var hr.HookContext) {.raises: [].} =
  if origGetEnvironmentVariableW == nil:
    ctx.result = 0
    return
  ctx.result = uint64(origGetEnvironmentVariableW(
    cast[LPCWSTR](ctx.args[0]), cast[LPWSTR](ctx.args[1]), DWORD(ctx.args[2])))

proc originalGetEnvironmentVariableA(ctx: var hr.HookContext) {.raises: [].} =
  if origGetEnvironmentVariableA == nil:
    ctx.result = 0
    return
  ctx.result = uint64(origGetEnvironmentVariableA(
    cast[LPCSTR](ctx.args[0]), cast[LPSTR](ctx.args[1]), DWORD(ctx.args[2])))

proc originalGetEnvironmentStringsW(ctx: var hr.HookContext) {.raises: [].} =
  if origGetEnvironmentStringsW == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origGetEnvironmentStringsW())

proc originalGetEnvironmentStringsA(ctx: var hr.HookContext) {.raises: [].} =
  if origGetEnvironmentStringsA == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origGetEnvironmentStringsA())

proc originalGetEnvironmentStrings(ctx: var hr.HookContext) {.raises: [].} =
  if origGetEnvironmentStrings == nil:
    ctx.result = 0
    return
  ctx.result = cast[uint64](origGetEnvironmentStrings())

template crtGetenvOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = 0
  else:
    ctx.result = cast[uint64](orig(cast[LPCSTR](ctx.args[0])))

template crtWGetenvOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = 0
  else:
    ctx.result = cast[uint64](orig(cast[LPCWSTR](ctx.args[0])))

template crtGetenvSOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = uint64(uint32(22))              # EINVAL
  else:
    ctx.result = uint64(uint32(orig(
      cast[ptr SIZE_T](ctx.args[0]), cast[LPSTR](ctx.args[1]),
      SIZE_T(ctx.args[2]), cast[LPCSTR](ctx.args[3]))))

template crtWGetenvSOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = uint64(uint32(22))              # EINVAL
  else:
    ctx.result = uint64(uint32(orig(
      cast[ptr SIZE_T](ctx.args[0]), cast[LPWSTR](ctx.args[1]),
      SIZE_T(ctx.args[2]), cast[LPCWSTR](ctx.args[3]))))

template crtDupenvSOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = uint64(uint32(22))              # EINVAL
  else:
    ctx.result = uint64(uint32(orig(
      cast[ptr LPSTR](ctx.args[0]), cast[ptr SIZE_T](ctx.args[1]),
      cast[LPCSTR](ctx.args[2]))))

template crtWDupenvSOriginal(orig, ctx: untyped) =
  if orig == nil:
    ctx.result = uint64(uint32(22))              # EINVAL
  else:
    ctx.result = uint64(uint32(orig(
      cast[ptr LPWSTR](ctx.args[0]), cast[ptr SIZE_T](ctx.args[1]),
      cast[LPCWSTR](ctx.args[2]))))

proc originalUcrtGetenv(ctx: var hr.HookContext) {.raises: [].} =
  crtGetenvOriginal(origUcrtGetenv, ctx)
proc originalUcrtWGetenv(ctx: var hr.HookContext) {.raises: [].} =
  crtWGetenvOriginal(origUcrtWGetenv, ctx)
proc originalUcrtGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtGetenvSOriginal(origUcrtGetenvS, ctx)
proc originalUcrtWGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtWGetenvSOriginal(origUcrtWGetenvS, ctx)
proc originalUcrtDupenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtDupenvSOriginal(origUcrtDupenvS, ctx)
proc originalUcrtWDupenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtWDupenvSOriginal(origUcrtWDupenvS, ctx)
proc originalMsvcrtGetenv(ctx: var hr.HookContext) {.raises: [].} =
  crtGetenvOriginal(origMsvcrtGetenv, ctx)
proc originalMsvcrtWGetenv(ctx: var hr.HookContext) {.raises: [].} =
  crtWGetenvOriginal(origMsvcrtWGetenv, ctx)
proc originalMsvcrtGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtGetenvSOriginal(origMsvcrtGetenvS, ctx)
proc originalMsvcrtWGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  crtWGetenvSOriginal(origMsvcrtWGetenvS, ctx)

# --- M5 snoop callbacks ----------------------------------------------------

const
  WSAEWOULDBLOCK = 10035'u32
  WSAEINPROGRESS = 10036'u32

proc socketConnectReachedPeer(rc: int32; wsaError: uint32): bool
    {.inline, raises: [].} =
  ## Did this `connect`/`WSAConnect` call actually reach a peer?
  ##
  ## THE SAME RULE `classifyOpenedPath` STATES FOR PIPES, applied to the socket
  ## arm: only a connect that reached somebody is recorded. An `mrIpcConnect`
  ## naming an UNKNOWN peer is a downgrade signal -- the merge cannot prove the
  ## peer was in-tree, so the whole capture grades `mcIncomplete` and the action
  ## loses its cache publication. Emitting one for a connect that was REFUSED
  ## means a connection that never happened costs a build its cache hit: a
  ## false re-run, which is the failure direction this machinery exists to
  ## avoid. Windows programs probe localhost constantly (daemon discovery,
  ## sccache and language-server probes, "is the server already up?" checks),
  ## and every one of those probes ends in WSAECONNREFUSED by design.
  ##
  ## IN-FLIGHT CONNECTS ARE RECORDED, deliberately, matching the macOS arm's
  ## `EInProgress` case. A non-blocking `connect` returns SOCKET_ERROR with
  ## WSAEWOULDBLOCK (the Winsock spelling of EINPROGRESS; WSAEINPROGRESS is the
  ## WinSock 1.1 blocking-call form and is accepted for completeness) and then
  ## COMPLETES asynchronously -- that is the ordinary shape of an async client
  ## talking to a daemon, so treating it as "reached nobody" would be a silent
  ## false skip over a real peer. The two errors are not symmetric in cost: an
  ## in-flight connect that later fails costs a conservative re-run, while a
  ## refused connect recorded as a peer costs one too, and an in-flight connect
  ## NOT recorded costs a false `mcComplete` over content that arrived from an
  ## out-of-tree daemon. Only the last of those is unrecoverable, so the guard
  ## is drawn to include exactly the states in which a peer may yet be reached.
  ##
  ## `GetLastError` is the source of `wsaError`: `WSAGetLastError` is documented
  ## as returning the same thread-local value, and the snoops already capture it
  ## immediately after `callNext` before anything can clobber it.
  if rc == 0:
    return true
  wsaError == WSAEWOULDBLOCK or wsaError == WSAEINPROGRESS

proc snoopConnect(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let rc = cast[int32](uint32(ctx.result))
    if socketConnectReachedPeer(rc, savedLastError):
      var family: uint16 = 0
      let dest = sockaddrDestination(cast[pointer](ctx.args[1]),
        cast[int32](uint32(ctx.args[2])), family)
      if dest.len > 0:
        # A socket peer's pid is not obtainable in-process on Windows (there is
        # no SO_PEERCRED / LOCAL_PEERPID), so it is reported as unknown and the
        # merge treats it conservatively as out-of-tree -- the same
        # downgrade-on-uncertainty stance the macOS arm takes for an AF_INET
        # peer. The named-pipe arm, which is how Windows build daemons actually
        # talk, DOES supply the pid.
        emitIpcConnect(dest, 0'u64, family, int64(rc), "socket")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopWSAConnect(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let rc = cast[int32](uint32(ctx.result))
    if socketConnectReachedPeer(rc, savedLastError):
      var family: uint16 = 0
      let dest = sockaddrDestination(cast[pointer](ctx.args[1]),
        cast[int32](uint32(ctx.args[2])), family)
      if dest.len > 0:
        emitIpcConnect(dest, 0'u64, family, int64(rc), "socket")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc recordFileMappingCreate(hFile: HANDLE; h: HANDLE; name: string;
                             alreadyExisted: bool) {.raises: [].} =
  ## Shared body of the CreateFileMappingW/A snoops.
  ##
  ## Two distinct facts come out of one call. A section over a real FILE gives
  ## the mapping handle a source path, so a later view can be recorded as a
  ## READ of that file -- the one content channel on Windows that never passes
  ## ReadFile. A NAMED section is the shm analogue, and whether this process
  ## PRODUCED it or merely joined it is decided by ERROR_ALREADY_EXISTS:
  ## `CreateFileMapping` opens an existing section rather than failing, so
  ## recording every call as a `create` would let an out-of-tree producer's
  ## section be paired against a consumer's own record and never downgrade.
  if h == nil or h == INVALID_HANDLE_VALUE:
    return
  if hFile != nil and hFile != INVALID_HANDLE_VALUE:
    let p = pathForHandle(hFile)
    if p.len > 0:
      rememberMappingPath(h, p)
  if name.len > 0:
    emitExternalContent("shm",
      (if alreadyExisted: "attach" else: "create"), name, 0'u64,
      int64(cast[int](h)))

proc snoopCreateFileMappingW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    recordFileMappingCreate(cast[HANDLE](ctx.args[0]),
      cast[HANDLE](ctx.result), widePtrToString(cast[LPCWSTR](ctx.args[5])),
      savedLastError == 183'u32)               # ERROR_ALREADY_EXISTS
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCreateFileMappingA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpName = cast[LPCSTR](ctx.args[5])
    recordFileMappingCreate(cast[HANDLE](ctx.args[0]),
      cast[HANDLE](ctx.result), (if lpName != nil: $lpName else: ""),
      savedLastError == 183'u32)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc recordFileMappingOpen(h: HANDLE; name: string) {.raises: [].} =
  ## `OpenFileMapping` can only ever JOIN a section somebody else made, so it is
  ## unconditionally the consume side. An attach with no in-tree create is the
  ## out-of-tree shared-memory producer the merge downgrades on.
  if h == nil or h == INVALID_HANDLE_VALUE or name.len == 0:
    return
  emitExternalContent("shm", "attach", name, 0'u64, int64(cast[int](h)))

proc snoopOpenFileMappingW(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    recordFileMappingOpen(cast[HANDLE](ctx.result),
      widePtrToString(cast[LPCWSTR](ctx.args[2])))
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopOpenFileMappingA(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    let lpName = cast[LPCSTR](ctx.args[2])
    recordFileMappingOpen(cast[HANDLE](ctx.result),
      (if lpName != nil: $lpName else: ""))
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc recordMappedView(hMap: HANDLE; access: DWORD; view: pointer;
                      detail: string) {.raises: [].} =
  ## A view of a FILE-backed section is a content access to that file that no
  ## ReadFile hook can see. Recording it under the ordinary read/write
  ## observation kinds is what makes the bytes a real dependency for a
  ## content-addressed cache rather than merely visible to inspection.
  if view == nil:
    return
  let p = pathForMapping(hMap)
  if p.len == 0:
    return
  if (access and (FILE_MAP_READ or FILE_MAP_COPY or FILE_MAP_ALL_ACCESS)) != 0:
    var rec = baseRecord(mrFileRead, moFileRead)
    rec.path = p
    rec.flags = uint32(access)
    rec.detail = detail & ":read"
    emitRecord(rec)
  if (access and FILE_MAP_WRITE) != 0:
    var rec = baseRecord(mrFileWrite, moFileWrite)
    rec.path = p
    rec.flags = uint32(access)
    rec.detail = detail & ":write"
    emitRecord(rec)

proc snoopMapViewOfFile(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    recordMappedView(cast[HANDLE](ctx.args[0]), DWORD(ctx.args[1]),
      cast[pointer](ctx.result), "MapViewOfFile")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopMapViewOfFileEx(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    recordMappedView(cast[HANDLE](ctx.args[0]), DWORD(ctx.args[1]),
      cast[pointer](ctx.result), "MapViewOfFileEx")
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopCreatePipe(ctx: var hr.HookContext) {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized:
    SetLastError(savedLastError)
    return
  try:
    if BOOL(uint32(ctx.result)) != 0:
      # `chan=localfd role=create` is the in-tree PRODUCER side the merge pairs
      # an `opaque` read against. Both ends are recorded because either can be
      # the one a monitored child inherits, and a Windows anonymous pipe
      # reports the SAME kernel object name from both -- which is precisely
      # what makes the pairing work across processes.
      let hp = cast[ptr HANDLE](ctx.args[0])
      if hp != nil:
        var other = 0'u64
        let identity = pipePairIdentity(hp[], other)
        emitExternalContent("localfd", "create", identity,
          uint64(GetCurrentProcessId()), 0'i64)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopEntropy(ctx: var hr.HookContext; slot: int; source: string;
                  inProgramArg: int) {.raises: [].} =
  ## Shared body of the four entropy snoops.
  ##
  ## Recorded ONCE per (source, caller-origin) per process. The evidence M6
  ## needs is "this program consumed randomness", not a count, and these entry
  ## points are called at a rate where a per-call record would cost more than
  ## every file observation put together.
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized or fragmentDir.len == 0:
    SetLastError(savedLastError)
    return
  try:
    let inProgram = ctx.args.len > inProgramArg and
      ctx.args[inProgramArg] != 0'u64
    let idx = slot * 2 + (if inProgram: 1 else: 0)
    if not ndEntropySeen[idx]:
      ndEntropySeen[idx] = true
      emitNonDeterministic(source, inProgram)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopBCryptGenRandom(ctx: var hr.HookContext) {.raises: [].} =
  snoopEntropy(ctx, 0, "BCryptGenRandom", 4)

proc snoopProcessPrng(ctx: var hr.HookContext) {.raises: [].} =
  snoopEntropy(ctx, 1, "ProcessPrng", 2)

proc snoopSystemFunction036(ctx: var hr.HookContext) {.raises: [].} =
  snoopEntropy(ctx, 2, "RtlGenRandom", 2)

proc snoopCryptGenRandom(ctx: var hr.HookContext) {.raises: [].} =
  snoopEntropy(ctx, 3, "CryptGenRandom", 3)

proc snoopTime(ctx: var hr.HookContext; slot: int; source: string)
    {.raises: [].} =
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized or fragmentDir.len == 0:
    SetLastError(savedLastError)
    return
  try:
    if not ndTimeSeen[slot]:
      ndTimeSeen[slot] = true
      emitTimeRead(source)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopQueryPerformanceCounter(ctx: var hr.HookContext) {.raises: [].} =
  snoopTime(ctx, 0, "QueryPerformanceCounter")

proc snoopGetSystemTimeAsFileTime(ctx: var hr.HookContext) {.raises: [].} =
  snoopTime(ctx, 1, "GetSystemTimeAsFileTime")

proc snoopGetTickCount64(ctx: var hr.HookContext) {.raises: [].} =
  snoopTime(ctx, 2, "GetTickCount64")

# --- M10 snoop callbacks (observed environment) ----------------------------

proc cstrToString(p: LPCSTR): string {.raises: [].} =
  if p == nil:
    return ""
  var n = 0
  # Bounded for the same reason the block walk is: this pointer came from the
  # monitored program, not from us.
  while n < 32767 and cast[ptr UncheckedArray[char]](p)[n] != '\0':
    inc n
  result = newString(n)
  for i in 0 ..< n:
    result[i] = cast[ptr UncheckedArray[char]](p)[i]

proc snoopEnvName(ctx: var hr.HookContext; nameArg: int; wide: bool;
                  source: string) {.raises: [].} =
  ## Shared body of every NAMED environment read, Win32 and CRT alike.
  ##
  ## The call is forwarded FIRST and the record is written afterwards, so a
  ## record can never be the reason a program saw a different answer.
  ##
  ## The result is NOT consulted. A lookup that returns nothing is still a
  ## dependency on that variable's ABSENCE: a build that behaves one way when
  ## `CFLAGS` is unset and another way when it is set must re-run when someone
  ## sets it, and it can only do that if the failed lookup was recorded. This
  ## is the opposite of the rule the IPC arm follows -- a refused connect
  ## reached no peer and is not recorded -- because there the record would
  ## DOWNGRADE the capture, while here it only adds a name to a cache key.
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized or fragmentDir.len == 0:
    SetLastError(savedLastError)
    return
  try:
    if ctx.args.len > nameArg:
      let name =
        if wide: widePtrToString(cast[LPCWSTR](ctx.args[nameArg]))
        else: cstrToString(cast[LPCSTR](ctx.args[nameArg]))
      recordEnvRead(name, source)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopEnvBlock(ctx: var hr.HookContext; slot: int; source: string;
                   inProgramArg: int) {.raises: [].} =
  ## Shared body of the three whole-block reads.
  ##
  ## CALLER ATTRIBUTION IS LOAD-BEARING HERE, unlike on the named reads. Every
  ## C runtime calls `GetEnvironmentStringsW` ONCE at startup to build the
  ## snapshot `getenv` is served from -- in EVERY process, whatever the program
  ## goes on to do. Expanding that call into per-name records would make every
  ## action on Windows depend on its entire environment, which is a monitor
  ## that makes everything uncacheable. So a block read from a SYSTEM image is
  ## the CRT taking its snapshot and is not recorded; the reads that snapshot
  ## then serves are recorded individually, by the `getenv` hooks, which is
  ## strictly more precise.
  ##
  ## A block read from the program's OWN image is a different act: the program
  ## has the whole environment in hand and we cannot see which parts of it
  ## matter, so every name in the block is recorded.
  ##
  ## The attribution is `callerInProgram`'s, with its stated limits: a program
  ## whose block read comes through a BUNDLED DLL reports `caller=system` and
  ## is treated as a CRT snapshot. Such a program is not blind -- its named
  ## reads are still recorded -- it just does not get the block expansion.
  hr.callNext(ctx)
  let savedLastError = GetLastError()
  if disabled > 0 or not initialized or fragmentDir.len == 0:
    SetLastError(savedLastError)
    return
  try:
    let inProgram = ctx.args.len > inProgramArg and
      ctx.args[inProgramArg] != 0'u64
    let idx = slot * 2 + (if inProgram: 1 else: 0)
    if not envBlockSeen[idx]:
      envBlockSeen[idx] = true
      if inProgram:
        recordEnvBlockRead(source)
  except CatchableError:
    discard
  SetLastError(savedLastError)

proc snoopGetEnvironmentVariableW(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, true, "GetEnvironmentVariableW")
proc snoopGetEnvironmentVariableA(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, false, "GetEnvironmentVariableA")
proc snoopGetEnvironmentStringsW(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvBlock(ctx, 0, "GetEnvironmentStringsW", 0)
proc snoopGetEnvironmentStringsA(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvBlock(ctx, 1, "GetEnvironmentStringsA", 0)
proc snoopGetEnvironmentStrings(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvBlock(ctx, 2, "GetEnvironmentStrings", 0)
proc snoopUcrtGetenv(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, false, "getenv")
proc snoopUcrtWGetenv(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, true, "_wgetenv")
proc snoopUcrtGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 3, false, "getenv_s")
proc snoopUcrtWGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 3, true, "_wgetenv_s")
proc snoopUcrtDupenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 2, false, "_dupenv_s")
proc snoopUcrtWDupenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 2, true, "_wdupenv_s")
proc snoopMsvcrtGetenv(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, false, "getenv")
proc snoopMsvcrtWGetenv(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 0, true, "_wgetenv")
proc snoopMsvcrtGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 3, false, "getenv_s")
proc snoopMsvcrtWGetenvS(ctx: var hr.HookContext) {.raises: [].} =
  snoopEnvName(ctx, 3, true, "_wgetenv_s")

# --- M5 trampolines --------------------------------------------------------
#
# The non-determinism trampolines carry a FAST PATH the file trampolines do
# not need: once a source has been recorded for a given caller origin, the call
# goes straight to the original and never builds a HookContext or walks the
# registry. QueryPerformanceCounter and GetSystemTimeAsFileTime are called
# orders of magnitude more often than any file API, and a per-call seq
# allocation plus a string-keyed chain lookup on them would give back the
# monitoring overhead S4 recovered by batching hook teardown.

proc trampolineConnect(s: uint; name: pointer; namelen: int32): int32
    {.stdcall.} =
  if origConnect == nil:
    return -1
  var ctx = hr.HookContext(args: @[
    uint64(s), cast[uint64](name), uint64(uint32(namelen))])
  hr.dispatchShimHook(hr.HookConnect, ctx)
  result = cast[int32](uint32(ctx.result))

proc trampolineWSAConnect(s: uint; name: pointer; namelen: int32;
                          lpCallerData: pointer; lpCalleeData: pointer;
                          lpSQOS: pointer; lpGQOS: pointer): int32
                          {.stdcall.} =
  if origWSAConnect == nil:
    return -1
  var ctx = hr.HookContext(args: @[
    uint64(s), cast[uint64](name), uint64(uint32(namelen)),
    cast[uint64](lpCallerData), cast[uint64](lpCalleeData),
    cast[uint64](lpSQOS), cast[uint64](lpGQOS)])
  hr.dispatchShimHook(hr.HookWSAConnect, ctx)
  result = cast[int32](uint32(ctx.result))

proc trampolineCreateFileMappingW(hFile: HANDLE;
                                  lpAttributes: LPSECURITY_ATTRIBUTES;
                                  flProtect: DWORD;
                                  dwMaximumSizeHigh: DWORD;
                                  dwMaximumSizeLow: DWORD;
                                  lpName: LPCWSTR): HANDLE {.stdcall.} =
  if origCreateFileMappingW == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFile), cast[uint64](lpAttributes), uint64(flProtect),
    uint64(dwMaximumSizeHigh), uint64(dwMaximumSizeLow), cast[uint64](lpName)])
  hr.dispatchShimHook(hr.HookCreateFileMappingW, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineCreateFileMappingA(hFile: HANDLE;
                                  lpAttributes: LPSECURITY_ATTRIBUTES;
                                  flProtect: DWORD;
                                  dwMaximumSizeHigh: DWORD;
                                  dwMaximumSizeLow: DWORD;
                                  lpName: LPCSTR): HANDLE {.stdcall.} =
  if origCreateFileMappingA == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFile), cast[uint64](lpAttributes), uint64(flProtect),
    uint64(dwMaximumSizeHigh), uint64(dwMaximumSizeLow), cast[uint64](lpName)])
  hr.dispatchShimHook(hr.HookCreateFileMappingA, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineOpenFileMappingW(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
                                lpName: LPCWSTR): HANDLE {.stdcall.} =
  if origOpenFileMappingW == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    uint64(dwDesiredAccess), uint64(uint32(bInheritHandle)),
    cast[uint64](lpName)])
  hr.dispatchShimHook(hr.HookOpenFileMappingW, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineOpenFileMappingA(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
                                lpName: LPCSTR): HANDLE {.stdcall.} =
  if origOpenFileMappingA == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    uint64(dwDesiredAccess), uint64(uint32(bInheritHandle)),
    cast[uint64](lpName)])
  hr.dispatchShimHook(hr.HookOpenFileMappingA, ctx)
  result = cast[HANDLE](ctx.result)

proc trampolineMapViewOfFile(hFileMappingObject: HANDLE;
                             dwDesiredAccess: DWORD;
                             dwFileOffsetHigh: DWORD;
                             dwFileOffsetLow: DWORD;
                             dwNumberOfBytesToMap: SIZE_T): LPVOID
                             {.stdcall.} =
  if origMapViewOfFile == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFileMappingObject), uint64(dwDesiredAccess),
    uint64(dwFileOffsetHigh), uint64(dwFileOffsetLow),
    uint64(dwNumberOfBytesToMap)])
  hr.dispatchShimHook(hr.HookMapViewOfFile, ctx)
  result = cast[LPVOID](ctx.result)

proc trampolineMapViewOfFileEx(hFileMappingObject: HANDLE;
                               dwDesiredAccess: DWORD;
                               dwFileOffsetHigh: DWORD;
                               dwFileOffsetLow: DWORD;
                               dwNumberOfBytesToMap: SIZE_T;
                               lpBaseAddress: LPVOID): LPVOID {.stdcall.} =
  if origMapViewOfFileEx == nil:
    return nil
  var ctx = hr.HookContext(args: @[
    cast[uint64](hFileMappingObject), uint64(dwDesiredAccess),
    uint64(dwFileOffsetHigh), uint64(dwFileOffsetLow),
    uint64(dwNumberOfBytesToMap), cast[uint64](lpBaseAddress)])
  hr.dispatchShimHook(hr.HookMapViewOfFileEx, ctx)
  result = cast[LPVOID](ctx.result)

proc trampolineCreatePipe(hReadPipe: ptr HANDLE; hWritePipe: ptr HANDLE;
                          lpPipeAttributes: LPSECURITY_ATTRIBUTES;
                          nSize: DWORD): BOOL {.stdcall.} =
  if origCreatePipe == nil:
    return 0
  var ctx = hr.HookContext(args: @[
    cast[uint64](hReadPipe), cast[uint64](hWritePipe),
    cast[uint64](lpPipeAttributes), uint64(nSize)])
  hr.dispatchShimHook(hr.HookCreatePipe, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineBCryptGenRandom(hAlgorithm: HANDLE; pbBuffer: pointer;
                               cbBuffer: DWORD; dwFlags: DWORD): NTSTATUS
                               {.stdcall.} =
  if origBCryptGenRandom == nil:
    return cast[NTSTATUS](0xC0000001'u32)
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if ndEntropySeen[0 * 2 + (if inProgram: 1 else: 0)]:
    return origBCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags)
  var ctx = hr.HookContext(args: @[
    cast[uint64](hAlgorithm), cast[uint64](pbBuffer), uint64(cbBuffer),
    uint64(dwFlags), (if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookBCryptGenRandom, ctx)
  result = cast[NTSTATUS](uint32(ctx.result))

proc trampolineProcessPrng(pbData: pointer; cbData: SIZE_T): BOOL {.stdcall.} =
  if origProcessPrng == nil:
    return 0
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if ndEntropySeen[1 * 2 + (if inProgram: 1 else: 0)]:
    return origProcessPrng(pbData, cbData)
  var ctx = hr.HookContext(args: @[
    cast[uint64](pbData), uint64(cbData),
    (if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookProcessPrng, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineSystemFunction036(RandomBuffer: pointer;
                                 RandomBufferLength: DWORD): uint8
                                 {.stdcall.} =
  if origSystemFunction036 == nil:
    return 0
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if ndEntropySeen[2 * 2 + (if inProgram: 1 else: 0)]:
    return origSystemFunction036(RandomBuffer, RandomBufferLength)
  var ctx = hr.HookContext(args: @[
    cast[uint64](RandomBuffer), uint64(RandomBufferLength),
    (if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookSystemFunction036, ctx)
  result = uint8(ctx.result and 0xFF'u64)

proc trampolineCryptGenRandom(hProv: uint; dwLen: DWORD;
                              pbBuffer: pointer): BOOL {.stdcall.} =
  if origCryptGenRandom == nil:
    return 0
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if ndEntropySeen[3 * 2 + (if inProgram: 1 else: 0)]:
    return origCryptGenRandom(hProv, dwLen, pbBuffer)
  var ctx = hr.HookContext(args: @[
    uint64(hProv), uint64(dwLen), cast[uint64](pbBuffer),
    (if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookCryptGenRandom, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineQueryPerformanceCounter(lpPerformanceCount: ptr LARGE_INTEGER):
    BOOL {.stdcall.} =
  if origQueryPerformanceCounter == nil:
    return 0
  if ndTimeSeen[0]:
    return origQueryPerformanceCounter(lpPerformanceCount)
  var ctx = hr.HookContext(args: @[cast[uint64](lpPerformanceCount)])
  hr.dispatchShimHook(hr.HookQueryPerformanceCounter, ctx)
  result = BOOL(uint32(ctx.result))

proc trampolineGetSystemTimeAsFileTime(lpSystemTimeAsFileTime: pointer)
    {.stdcall.} =
  if origGetSystemTimeAsFileTime == nil:
    return
  if ndTimeSeen[1]:
    origGetSystemTimeAsFileTime(lpSystemTimeAsFileTime)
    return
  var ctx = hr.HookContext(args: @[cast[uint64](lpSystemTimeAsFileTime)])
  hr.dispatchShimHook(hr.HookGetSystemTimeAsFileTime, ctx)

proc trampolineGetTickCount64(): uint64 {.stdcall.} =
  if origGetTickCount64 == nil:
    return 0
  if ndTimeSeen[2]:
    return origGetTickCount64()
  var ctx = hr.HookContext(args: @[])
  hr.dispatchShimHook(hr.HookGetTickCount64, ctx)
  result = ctx.result

# --- M10 trampolines (observed environment) --------------------------------
#
# THE FAST PATH IS THE POINT. `getenv` is called at a rate no file API
# approaches, and a build's reads are overwhelmingly REPEATS of names already
# recorded -- the first read of PATH is the evidence, the next nine thousand
# are not. So a named read whose variable is already in the capture goes
# straight to the original: no hook context, no chain lookup, no string built
# from the caller's pointer. Measured on this host, that is the difference
# between 1.43 us and ~100-150 ns per repeat read (the marginal cost of the
# loop case over a no-lookup case, measured across three interleaved runs;
# the whole-run percentages on a 90 ms process are noise).
#
# `envFastSeen*` is EXACT, not a hash filter, and `envFastSeen*`'s own comment
# says why: a filter that answered "seen" for a name it had not seen would
# drop the first read of a real variable, leaving an input missing from a
# capture that still grades `mcComplete`.
#
# The residual, stated because the entropy trampolines have the same one: a
# co-resident interposer registered on these chains does not see the calls the
# fast path skips. It sees the first read of every distinct variable, which is
# every event the monitor itself acts on.
#
# The WHOLE-BLOCK reads take the entropy hooks' shape instead -- a boolean per
# (entry point, caller origin) -- because for them at most one act is
# interesting and every later call repeats a decision already recorded.

template envFastSkip(cond: untyped): untyped =
  ## The guard every named-read trampoline shares. `fragmentDir.len == 0` is
  ## in here rather than only in the snoop so an UNMONITORED process -- one
  ## the shim is loaded into with nowhere to write -- pays nothing per call
  ## instead of dispatching a chain whose only outcome is an early return.
  disabled > 0 or not initialized or fragmentDir.len == 0 or (cond)

proc trampolineGetEnvironmentVariableW(lpName: LPCWSTR; lpBuffer: LPWSTR;
                                       nSize: DWORD): DWORD {.stdcall.} =
  if origGetEnvironmentVariableW == nil:
    return 0
  if envFastSkip(envFastSeenWide(lpName)):
    return origGetEnvironmentVariableW(lpName, lpBuffer, nSize)
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpName), cast[uint64](lpBuffer), uint64(nSize)])
  hr.dispatchShimHook(hr.HookGetEnvironmentVariableW, ctx)
  result = DWORD(ctx.result)

proc trampolineGetEnvironmentVariableA(lpName: LPCSTR; lpBuffer: LPSTR;
                                       nSize: DWORD): DWORD {.stdcall.} =
  if origGetEnvironmentVariableA == nil:
    return 0
  if envFastSkip(envFastSeenCstr(lpName)):
    return origGetEnvironmentVariableA(lpName, lpBuffer, nSize)
  var ctx = hr.HookContext(args: @[
    cast[uint64](lpName), cast[uint64](lpBuffer), uint64(nSize)])
  hr.dispatchShimHook(hr.HookGetEnvironmentVariableA, ctx)
  result = DWORD(ctx.result)

proc trampolineGetEnvironmentStringsW(): LPWSTR {.stdcall.} =
  if origGetEnvironmentStringsW == nil:
    return nil
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if envBlockSeen[0 * 2 + (if inProgram: 1 else: 0)]:
    return origGetEnvironmentStringsW()
  var ctx = hr.HookContext(args: @[(if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookGetEnvironmentStringsW, ctx)
  result = cast[LPWSTR](ctx.result)

proc trampolineGetEnvironmentStringsA(): LPSTR {.stdcall.} =
  if origGetEnvironmentStringsA == nil:
    return nil
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if envBlockSeen[1 * 2 + (if inProgram: 1 else: 0)]:
    return origGetEnvironmentStringsA()
  var ctx = hr.HookContext(args: @[(if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookGetEnvironmentStringsA, ctx)
  result = cast[LPSTR](ctx.result)

proc trampolineGetEnvironmentStrings(): LPSTR {.stdcall.} =
  ## `GetEnvironmentStrings` is a SEPARATE export from
  ## `GetEnvironmentStringsA` -- measured on this host they resolve to
  ## different kernel32 bodies, so hooking one does not cover the other and a
  ## caller that imports the undecorated name would escape.
  if origGetEnvironmentStrings == nil:
    return nil
  let inProgram = callerInProgram(builtinReturnAddress(0))
  if envBlockSeen[2 * 2 + (if inProgram: 1 else: 0)]:
    return origGetEnvironmentStrings()
  var ctx = hr.HookContext(args: @[(if inProgram: 1'u64 else: 0'u64)])
  hr.dispatchShimHook(hr.HookGetEnvironmentStrings, ctx)
  result = cast[LPSTR](ctx.result)

template crtGetenvTrampoline(orig, hookName, nameArg, seenFn: untyped): untyped =
  if orig == nil:
    return nil
  if envFastSkip(seenFn(nameArg)):
    return orig(nameArg)
  var ctx = hr.HookContext(args: @[cast[uint64](nameArg)])
  hr.dispatchShimHook(hookName, ctx)
  return cast[typeof(result)](ctx.result)

template crtGetenvSTrampoline(orig, hookName, a0, a1, a2, a3,
                              seenFn: untyped): untyped =
  if orig == nil:
    return cint(22)                              # EINVAL
  if envFastSkip(seenFn(a3)):
    return orig(a0, a1, a2, a3)
  var ctx = hr.HookContext(args: @[
    cast[uint64](a0), cast[uint64](a1), uint64(a2), cast[uint64](a3)])
  hr.dispatchShimHook(hookName, ctx)
  return cint(int32(uint32(ctx.result)))

template crtDupenvSTrampoline(orig, hookName, a0, a1, a2,
                              seenFn: untyped): untyped =
  if orig == nil:
    return cint(22)                              # EINVAL
  if envFastSkip(seenFn(a2)):
    return orig(a0, a1, a2)
  var ctx = hr.HookContext(args: @[
    cast[uint64](a0), cast[uint64](a1), cast[uint64](a2)])
  hr.dispatchShimHook(hookName, ctx)
  return cint(int32(uint32(ctx.result)))

proc trampolineUcrtGetenv(name: LPCSTR): LPSTR {.cdecl.} =
  crtGetenvTrampoline(origUcrtGetenv, hr.HookUcrtGetenv, name,
    envFastSeenCstr)
proc trampolineUcrtWGetenv(name: LPCWSTR): LPWSTR {.cdecl.} =
  crtGetenvTrampoline(origUcrtWGetenv, hr.HookUcrtWGetenv, name,
    envFastSeenWide)
proc trampolineUcrtGetenvS(pReturnValue: ptr SIZE_T; buffer: LPSTR;
                           numberOfElements: SIZE_T; varname: LPCSTR): cint
                           {.cdecl.} =
  crtGetenvSTrampoline(origUcrtGetenvS, hr.HookUcrtGetenvS,
    pReturnValue, buffer, numberOfElements, varname, envFastSeenCstr)
proc trampolineUcrtWGetenvS(pReturnValue: ptr SIZE_T; buffer: LPWSTR;
                            numberOfElements: SIZE_T; varname: LPCWSTR): cint
                            {.cdecl.} =
  crtGetenvSTrampoline(origUcrtWGetenvS, hr.HookUcrtWGetenvS,
    pReturnValue, buffer, numberOfElements, varname, envFastSeenWide)
proc trampolineUcrtDupenvS(buffer: ptr LPSTR; numberOfElements: ptr SIZE_T;
                           varname: LPCSTR): cint {.cdecl.} =
  crtDupenvSTrampoline(origUcrtDupenvS, hr.HookUcrtDupenvS,
    buffer, numberOfElements, varname, envFastSeenCstr)
proc trampolineUcrtWDupenvS(buffer: ptr LPWSTR; numberOfElements: ptr SIZE_T;
                            varname: LPCWSTR): cint {.cdecl.} =
  crtDupenvSTrampoline(origUcrtWDupenvS, hr.HookUcrtWDupenvS,
    buffer, numberOfElements, varname, envFastSeenWide)
proc trampolineMsvcrtGetenv(name: LPCSTR): LPSTR {.cdecl.} =
  crtGetenvTrampoline(origMsvcrtGetenv, hr.HookMsvcrtGetenv, name,
    envFastSeenCstr)
proc trampolineMsvcrtWGetenv(name: LPCWSTR): LPWSTR {.cdecl.} =
  crtGetenvTrampoline(origMsvcrtWGetenv, hr.HookMsvcrtWGetenv, name,
    envFastSeenWide)
proc trampolineMsvcrtGetenvS(pReturnValue: ptr SIZE_T; buffer: LPSTR;
                             numberOfElements: SIZE_T; varname: LPCSTR): cint
                             {.cdecl.} =
  crtGetenvSTrampoline(origMsvcrtGetenvS, hr.HookMsvcrtGetenvS,
    pReturnValue, buffer, numberOfElements, varname, envFastSeenCstr)
proc trampolineMsvcrtWGetenvS(pReturnValue: ptr SIZE_T; buffer: LPWSTR;
                              numberOfElements: SIZE_T; varname: LPCWSTR): cint
                              {.cdecl.} =
  crtGetenvSTrampoline(origMsvcrtWGetenvS, hr.HookMsvcrtWGetenvS,
    pReturnValue, buffer, numberOfElements, varname, envFastSeenWide)

# --- Registry wiring -------------------------------------------------------
#
# Called once from repro_monitor_shim_init AFTER the registry has been
# allocated but BEFORE inline/IAT installation kicks in. Registers each
# snoop callback at ShimSnoopPriority. The chain's ``original`` callback
# is set by ``installInlineFor`` / ``installIatFor`` below, once we know
# the captured origXxx pointer (or trampoline returned by ct_inline_hook)
# is non-nil.

proc registerMonitorSnoopCallbacks*() =
  hr.registerMonitorHook(hr.HookCreateFileW,        snoopCreateFileW)
  hr.registerMonitorHook(hr.HookCreateFileA,        snoopCreateFileA)
  hr.registerMonitorHook(hr.HookReadFile,           snoopReadFile)
  hr.registerMonitorHook(hr.HookWriteFile,          snoopWriteFile)
  hr.registerMonitorHook(hr.HookCloseHandle,        snoopCloseHandle)
  hr.registerMonitorHook(hr.HookGetFileAttributesExW, snoopGetFileAttributesExW)
  hr.registerMonitorHook(hr.HookGetFileAttributesExA, snoopGetFileAttributesExA)
  hr.registerMonitorHook(hr.HookGetFileAttributesW,   snoopGetFileAttributesW)
  hr.registerMonitorHook(hr.HookGetFileAttributesA,   snoopGetFileAttributesA)
  hr.registerMonitorHook(hr.HookCreateProcessW,     snoopCreateProcessW)
  hr.registerMonitorHook(hr.HookCreateProcessA,     snoopCreateProcessA)
  hr.registerMonitorHook(hr.HookNtTerminateProcess, snoopNtTerminateProcess)
  # M73 Phase 5 — extended hook surface.
  hr.registerMonitorHook(hr.HookDeleteFileW,        snoopDeleteFileW)
  hr.registerMonitorHook(hr.HookDeleteFileA,        snoopDeleteFileA)
  hr.registerMonitorHook(hr.HookCreateDirectoryW,   snoopCreateDirectoryW)
  hr.registerMonitorHook(hr.HookCreateDirectoryA,   snoopCreateDirectoryA)
  hr.registerMonitorHook(hr.HookCopyFileW,          snoopCopyFileW)
  hr.registerMonitorHook(hr.HookCopyFileA,          snoopCopyFileA)
  hr.registerMonitorHook(hr.HookMoveFileExW,        snoopMoveFileExW)
  hr.registerMonitorHook(hr.HookMoveFileExA,        snoopMoveFileExA)
  hr.registerMonitorHook(hr.HookGetFileInformationByHandleEx,
                         snoopGetFileInformationByHandleEx)
  hr.registerMonitorHook(hr.HookSetCurrentDirectoryW,
                         snoopSetCurrentDirectoryW)
  hr.registerMonitorHook(hr.HookSetCurrentDirectoryA,
                         snoopSetCurrentDirectoryA)
  hr.registerMonitorHook(hr.HookNtCreateFile,       snoopNtCreateFile)
  hr.registerMonitorHook(hr.HookNtQueryAttributesFile,
                         snoopNtQueryAttributesFile)
  hr.registerMonitorHook(hr.HookNtQueryFullAttributesFile,
                         snoopNtQueryFullAttributesFile)
  # Temporarily disabled — the inline detour on NtQueryDirectoryFile /
  # NtQueryDirectoryFileEx is destabilising libuv's readdir path. The
  # crash is reproducible with the readdir-bundle fixture; the cause
  # is most likely a thread-safety issue in handlePaths access during
  # the chunked enumeration. The hooks remain compiled in (HookSpec
  # entries still install the inline detour) but the snoop callback
  # is not registered, so the chain calls the original directly. Fix
  # tracked separately; stat-class hooks are unaffected.
  # hr.registerMonitorHook(hr.HookNtQueryDirectoryFile,
  #                        snoopNtQueryDirectoryFile)
  hr.registerMonitorHook(hr.HookNtQueryInformationByName,
                         snoopNtQueryInformationByName)
  # kernel32 directory-enumerate hooks (libuv's streaming uv_fs_opendir
  # API uses FindFirstFileW + FindNextFileW; Node.js fs.opendirSync
  # routes through this. fs.readdirSync uses NtQueryDirectoryFile
  # which we catch via the GetProcAddress interception below — its
  # snoop is registered against the synthetic trampoline returned to
  # libuv from our hooked GetProcAddress.)
  hr.registerMonitorHook(hr.HookFindFirstFileW, snoopFindFirstFileW)
  hr.registerMonitorHook(hr.HookFindFirstFileExW, snoopFindFirstFileExW)
  hr.registerMonitorHook(hr.HookFindNextFileW, snoopFindNextFileW)
  hr.registerMonitorHook(hr.HookFindClose, snoopFindClose)
  hr.registerMonitorHook(hr.HookGetProcAddress, snoopGetProcAddress)
  # hr.registerMonitorHook(hr.HookNtQueryDirectoryFileEx,
  #                        snoopNtQueryDirectoryFileEx)
  # M5 — IPC-connect (socket arm; the named-pipe arm is classified inside the
  # CreateFile / NtCreateFile snoops above).
  hr.registerMonitorHook(hr.HookConnect, snoopConnect)
  hr.registerMonitorHook(hr.HookWSAConnect, snoopWSAConnect)
  # M5 — external content.
  hr.registerMonitorHook(hr.HookCreateFileMappingW, snoopCreateFileMappingW)
  hr.registerMonitorHook(hr.HookCreateFileMappingA, snoopCreateFileMappingA)
  hr.registerMonitorHook(hr.HookOpenFileMappingW, snoopOpenFileMappingW)
  hr.registerMonitorHook(hr.HookOpenFileMappingA, snoopOpenFileMappingA)
  hr.registerMonitorHook(hr.HookMapViewOfFile, snoopMapViewOfFile)
  hr.registerMonitorHook(hr.HookMapViewOfFileEx, snoopMapViewOfFileEx)
  hr.registerMonitorHook(hr.HookCreatePipe, snoopCreatePipe)
  # M5 — non-determinism.
  hr.registerMonitorHook(hr.HookBCryptGenRandom, snoopBCryptGenRandom)
  hr.registerMonitorHook(hr.HookProcessPrng, snoopProcessPrng)
  hr.registerMonitorHook(hr.HookSystemFunction036, snoopSystemFunction036)
  hr.registerMonitorHook(hr.HookCryptGenRandom, snoopCryptGenRandom)
  hr.registerMonitorHook(hr.HookQueryPerformanceCounter,
                         snoopQueryPerformanceCounter)
  hr.registerMonitorHook(hr.HookGetSystemTimeAsFileTime,
                         snoopGetSystemTimeAsFileTime)
  hr.registerMonitorHook(hr.HookGetTickCount64, snoopGetTickCount64)
  # M10 — observed environment. Both halves of the Windows environment: the
  # PEB block through kernel32, and each C runtime's own startup snapshot
  # through its `getenv` family.
  hr.registerMonitorHook(hr.HookGetEnvironmentVariableW,
                         snoopGetEnvironmentVariableW)
  hr.registerMonitorHook(hr.HookGetEnvironmentVariableA,
                         snoopGetEnvironmentVariableA)
  hr.registerMonitorHook(hr.HookGetEnvironmentStringsW,
                         snoopGetEnvironmentStringsW)
  hr.registerMonitorHook(hr.HookGetEnvironmentStringsA,
                         snoopGetEnvironmentStringsA)
  hr.registerMonitorHook(hr.HookGetEnvironmentStrings,
                         snoopGetEnvironmentStrings)
  hr.registerMonitorHook(hr.HookUcrtGetenv, snoopUcrtGetenv)
  hr.registerMonitorHook(hr.HookUcrtWGetenv, snoopUcrtWGetenv)
  hr.registerMonitorHook(hr.HookUcrtGetenvS, snoopUcrtGetenvS)
  hr.registerMonitorHook(hr.HookUcrtWGetenvS, snoopUcrtWGetenvS)
  hr.registerMonitorHook(hr.HookUcrtDupenvS, snoopUcrtDupenvS)
  hr.registerMonitorHook(hr.HookUcrtWDupenvS, snoopUcrtWDupenvS)
  hr.registerMonitorHook(hr.HookMsvcrtGetenv, snoopMsvcrtGetenv)
  hr.registerMonitorHook(hr.HookMsvcrtWGetenv, snoopMsvcrtWGetenv)
  hr.registerMonitorHook(hr.HookMsvcrtGetenvS, snoopMsvcrtGetenvS)
  hr.registerMonitorHook(hr.HookMsvcrtWGetenvS, snoopMsvcrtWGetenvS)

# --- Unified install backend (M73 Phase 1) ---------------------------------
#
# Per Monitor-Hook-Shim.md §"Install Backend Requirement:
# dispatch-mechanism-agnostic", the shim's install backend MUST catch every
# call to a hooked Win32 API regardless of how the caller resolved the entry
# point (IAT-routed, runtime-resolved via GetProcAddress, late-bound from a
# DLL loaded after init, CRT-forwarded). The only point where every
# dispatch mechanism converges is the kernel32 function body itself, so the
# primary install for every hooked API is a 5-byte JMP rel32 inline detour
# at the function body via ct_inline_hook. IAT patching is retained ONLY as
# the fallback path for APIs whose prologue the ct_inline_hook length
# decoder cannot safely relocate (see ct_inline_hook/install_windows.h
# error code -2). A hook landing on the IAT fallback is by spec an
# acceptance issue, not a permanent design choice — Phase 4 will install an
# audit accessor that hard-fails on non-zero fallback counts.
#
# Expected install mechanism on supported Windows versions (Win10 1809+,
# Win11): every hook lands on the INLINE path. The IAT fallback path is
# reserved for the rare prologue layout the length decoder rejects; in
# practice none of the eleven kernel32 APIs in this table have shipped
# with such a prologue. The dispatch-mechanism coverage test (Phase 2)
# proves all five caller dispatch mechanisms converge on the inline
# trampoline; the install audit (Phase 4) verifies the first five bytes
# of each kernel32 target are an E9-class detour after init.

type
  HookSpec = object
    name: string                # e.g. "CreateFileW"
    trampoline: pointer         # cast[pointer](trampolineCreateFileW)
    origStorage: ptr pointer    # cast[ptr pointer](addr origCreateFileW)
    origCallback: hr.HookCallback
    iatDlls: seq[string]        # Fallback search list when inline rejects.
    moduleDll: string           # M73 Phase 5: target module the inline +
                                # audit paths resolve the function from
                                # (default "kernel32.dll"). NtCreateFile
                                # sets this to "ntdll.dll".
    optionalModule: bool        # M5: the entry point may legitimately not
                                # exist on a supported host (a newer-Windows
                                # export). A missing module is then NOT an
                                # unhooked entry point, because there is no
                                # API for a call to escape through -- as
                                # opposed to a module that IS present and
                                # whose hook failed, which stays a loss.
    exportName: string          # M10: the UNDECORATED export to resolve, when
                                # it differs from the registry key. The
                                # registry is keyed by name and BOTH C
                                # runtimes export `getenv`, so the two chains
                                # are keyed `ucrtbase!getenv` /
                                # `msvcrt!getenv` while the install pass and
                                # the audit still ask each module for plain
                                # `getenv`. Empty means "same as `name`".

const kernel32FileIatDlls = @[
  "kernel32.dll", "kernelbase.dll",
  "api-ms-win-core-file-l1-1-0.dll",
  "api-ms-win-core-file-l1-2-0.dll",
  "api-ms-win-core-file-l2-1-0.dll",
  "api-ms-win-core-handle-l1-1-0.dll",
  "api-ms-win-core-processthreads-l1-1-0.dll",
  "api-ms-win-core-processthreads-l1-1-1.dll"
]

# NtCreateFile lives in ntdll. Only ntdll.dll itself exports it; the
# api-ms-win-* shims forward to it but no module advertises it under a
# different ExportName, so the IAT-fallback list can stay minimal here.
const ntdllNtIatDlls = @["ntdll.dll"]

# M5 — the modules the IPC / entropy entry points live in. They are
# force-loaded before the install pass (see `forceLoadObservedModules`) so the
# hook is in place before any user code can call through them.
const ws2IatDlls = @["ws2_32.dll", "wsock32.dll"]
const bcryptIatDlls = @["bcrypt.dll"]
const bcryptPrimitivesIatDlls = @["bcryptprimitives.dll"]
# `SystemFunction036` / `CryptGenRandom` are advapi32 exports that FORWARD to
# cryptbase / cryptsp; GetProcAddress resolves the forward, so the inline
# detour lands on the real body. The IAT fallback list names all three because
# a caller may import from whichever module its SDK headers pointed at.
const advapi32IatDlls = @["advapi32.dll", "cryptbase.dll", "cryptsp.dll"]

# M10 — the environment surface.
#
# kernel32's environment APIs are re-exported through the `api-ms-win-core-
# processenvironment-*` sets, so a caller's IAT may name either. The inline
# detour at the kernel32 body covers both; these are the fallback list.
const kernel32EnvIatDlls = @[
  "kernel32.dll", "kernelbase.dll",
  "api-ms-win-core-processenvironment-l1-1-0.dll",
  "api-ms-win-core-processenvironment-l1-2-0.dll"
]
# The UCRT's environment functions are exported by `ucrtbase.dll` and
# re-exported by `api-ms-win-crt-environment-l1-1-0.dll`; a program compiled
# against the UCRT imports from the api-set, which FORWARDS, so the inline
# detour on the ucrtbase body catches it either way.
const ucrtEnvIatDlls = @[
  "ucrtbase.dll", "api-ms-win-crt-environment-l1-1-0.dll"]
const msvcrtEnvIatDlls = @["msvcrt.dll"]

# Addresses of the kernel32 / ntdll entry points we successfully
# inline-patched. The C-runtime atexit handler walks this and calls
# ``ctInlineHookUninstall`` on every entry so the original 5 bytes
# at each kernel32 function are restored before the shim DLL's code
# pages disappear. Without this, any kernel32 call from a later
# atexit handler (libtest's, the CRT's) chases a JMP into unmapped
# memory and the process dies with ``STATUS_ACCESS_VIOLATION``.
var installedHookTargets {.global.}: seq[pointer] = @[]

var unhookedEntryPointNames {.global.}: string = ""
  ## Names behind `unhookedEntryPoints`, for the loss record's detail.

var unhookedEntryPoints {.global.}: int = 0
  ## Entry points that landed NEITHER an inline detour nor an IAT patch.
  ##
  ## A process whose hooks did not install is not a process with no
  ## dependencies -- it is a process whose dependencies were never observed,
  ## and the two are indistinguishable in the record stream. Left unreported,
  ## the run grades mcComplete over evidence that was never collected, and a
  ## consumer publishes an action-cache entry keyed on inputs it did not see.
  ## Counted here so `repro_monitor_shim_init` can emit an explicit
  ## event-loss record instead.

# Module-global hook table. Built once with the trampoline + origStorage
# pointers — these are addresses of module-level statics so they're known
# at module-init time; a `let` binding is sufficient.
let hookTable {.global.}: seq[HookSpec] = @[
  HookSpec(name: hr.HookCreateFileW,
    trampoline: cast[pointer](trampolineCreateFileW),
    origStorage: cast[ptr pointer](addr origCreateFileW),
    origCallback: originalCreateFileW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateFileA,
    trampoline: cast[pointer](trampolineCreateFileA),
    origStorage: cast[ptr pointer](addr origCreateFileA),
    origCallback: originalCreateFileA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookReadFile,
    trampoline: cast[pointer](trampolineReadFile),
    origStorage: cast[ptr pointer](addr origReadFile),
    origCallback: originalReadFile,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookWriteFile,
    trampoline: cast[pointer](trampolineWriteFile),
    origStorage: cast[ptr pointer](addr origWriteFile),
    origCallback: originalWriteFile,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCloseHandle,
    trampoline: cast[pointer](trampolineCloseHandle),
    origStorage: cast[ptr pointer](addr origCloseHandle),
    origCallback: originalCloseHandle,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetFileAttributesExW,
    trampoline: cast[pointer](trampolineGetFileAttributesExW),
    origStorage: cast[ptr pointer](addr origGetFileAttributesExW),
    origCallback: originalGetFileAttributesExW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetFileAttributesExA,
    trampoline: cast[pointer](trampolineGetFileAttributesExA),
    origStorage: cast[ptr pointer](addr origGetFileAttributesExA),
    origCallback: originalGetFileAttributesExA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetFileAttributesW,
    trampoline: cast[pointer](trampolineGetFileAttributesW),
    origStorage: cast[ptr pointer](addr origGetFileAttributesW),
    origCallback: originalGetFileAttributesW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetFileAttributesA,
    trampoline: cast[pointer](trampolineGetFileAttributesA),
    origStorage: cast[ptr pointer](addr origGetFileAttributesA),
    origCallback: originalGetFileAttributesA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateProcessW,
    trampoline: cast[pointer](trampolineCreateProcessW),
    origStorage: cast[ptr pointer](addr origCreateProcessW),
    origCallback: originalCreateProcessW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateProcessA,
    trampoline: cast[pointer](trampolineCreateProcessA),
    origStorage: cast[ptr pointer](addr origCreateProcessA),
    origCallback: originalCreateProcessA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # Not an observation hook: `snoopNtTerminateProcess` is the last
  # chance to make this process's buffered records durable.
  HookSpec(name: hr.HookNtTerminateProcess,
    trampoline: cast[pointer](trampolineNtTerminateProcess),
    origStorage: cast[ptr pointer](addr origNtTerminateProcess),
    origCallback: originalNtTerminateProcess,
    iatDlls: ntdllNtIatDlls,
    moduleDll: "ntdll.dll"),
  # M73 Phase 5 — extended Win32 entry points (kernel32.dll).
  HookSpec(name: hr.HookDeleteFileW,
    trampoline: cast[pointer](trampolineDeleteFileW),
    origStorage: cast[ptr pointer](addr origDeleteFileW),
    origCallback: originalDeleteFileW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookDeleteFileA,
    trampoline: cast[pointer](trampolineDeleteFileA),
    origStorage: cast[ptr pointer](addr origDeleteFileA),
    origCallback: originalDeleteFileA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateDirectoryW,
    trampoline: cast[pointer](trampolineCreateDirectoryW),
    origStorage: cast[ptr pointer](addr origCreateDirectoryW),
    origCallback: originalCreateDirectoryW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateDirectoryA,
    trampoline: cast[pointer](trampolineCreateDirectoryA),
    origStorage: cast[ptr pointer](addr origCreateDirectoryA),
    origCallback: originalCreateDirectoryA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCopyFileW,
    trampoline: cast[pointer](trampolineCopyFileW),
    origStorage: cast[ptr pointer](addr origCopyFileW),
    origCallback: originalCopyFileW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCopyFileA,
    trampoline: cast[pointer](trampolineCopyFileA),
    origStorage: cast[ptr pointer](addr origCopyFileA),
    origCallback: originalCopyFileA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookMoveFileExW,
    trampoline: cast[pointer](trampolineMoveFileExW),
    origStorage: cast[ptr pointer](addr origMoveFileExW),
    origCallback: originalMoveFileExW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookMoveFileExA,
    trampoline: cast[pointer](trampolineMoveFileExA),
    origStorage: cast[ptr pointer](addr origMoveFileExA),
    origCallback: originalMoveFileExA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetFileInformationByHandleEx,
    trampoline: cast[pointer](trampolineGetFileInformationByHandleEx),
    origStorage: cast[ptr pointer](addr origGetFileInformationByHandleEx),
    origCallback: originalGetFileInformationByHandleEx,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookSetCurrentDirectoryW,
    trampoline: cast[pointer](trampolineSetCurrentDirectoryW),
    origStorage: cast[ptr pointer](addr origSetCurrentDirectoryW),
    origCallback: originalSetCurrentDirectoryW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookSetCurrentDirectoryA,
    trampoline: cast[pointer](trampolineSetCurrentDirectoryA),
    origStorage: cast[ptr pointer](addr origSetCurrentDirectoryA),
    origCallback: originalSetCurrentDirectoryA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # NT Native API backstop — lives in ntdll, not kernel32.
  HookSpec(name: hr.HookNtCreateFile,
    trampoline: cast[pointer](trampolineNtCreateFile),
    origStorage: cast[ptr pointer](addr origNtCreateFile),
    origCallback: originalNtCreateFile,
    iatDlls: ntdllNtIatDlls,
    moduleDll: "ntdll.dll"),
  # NT stat-class hooks (libuv fast-path for fs.statSync).
  HookSpec(name: hr.HookNtQueryAttributesFile,
    trampoline: cast[pointer](trampolineNtQueryAttributesFile),
    origStorage: cast[ptr pointer](addr origNtQueryAttributesFile),
    origCallback: originalNtQueryAttributesFile,
    iatDlls: ntdllNtIatDlls,
    moduleDll: "ntdll.dll"),
  HookSpec(name: hr.HookNtQueryFullAttributesFile,
    trampoline: cast[pointer](trampolineNtQueryFullAttributesFile),
    origStorage: cast[ptr pointer](addr origNtQueryFullAttributesFile),
    origCallback: originalNtQueryFullAttributesFile,
    iatDlls: ntdllNtIatDlls,
    moduleDll: "ntdll.dll"),
  # NT path-information hook (libuv 1.52 fast-path on Win11 for stat).
  HookSpec(name: hr.HookNtQueryInformationByName,
    trampoline: cast[pointer](trampolineNtQueryInformationByName),
    origStorage: cast[ptr pointer](addr origNtQueryInformationByName),
    origCallback: originalNtQueryInformationByName,
    iatDlls: ntdllNtIatDlls,
    moduleDll: "ntdll.dll"),
  # NtQueryDirectoryFile inline detour is NOT installed: the function's
  # syscall-stub prologue on Win11 26100 is irrelocatable by the
  # length-decoder in ct_inline_hook (relocating the JMP-thunk lands
  # in the middle of a MOV EAX,imm32 instruction → crash). Instead we
  # intercept libuv's GetProcAddress(ntdll, "NtQueryDirectoryFile")
  # lookup at the kernel32 layer (registered as snoopGetProcAddress
  # below) and return our wrapper. libuv 1.52's saved pointer then
  # calls into our code without needing the inline detour.
  # kernel32 directory-enumerate hooks (libuv 1.52 fs.readdirSync uses
  # FindFirstFileExW + FindNextFileW + FindClose, not the NT
  # NtQueryDirectoryFile export; the NT-layer detour crashed Node so
  # we hook the kernel32 entry points instead).
  HookSpec(name: hr.HookFindFirstFileW,
    trampoline: cast[pointer](trampolineFindFirstFileW),
    origStorage: cast[ptr pointer](addr origFindFirstFileW),
    origCallback: originalFindFirstFileW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookFindFirstFileExW,
    trampoline: cast[pointer](trampolineFindFirstFileExW),
    origStorage: cast[ptr pointer](addr origFindFirstFileExW),
    origCallback: originalFindFirstFileExW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookFindNextFileW,
    trampoline: cast[pointer](trampolineFindNextFileW),
    origStorage: cast[ptr pointer](addr origFindNextFileW),
    origCallback: originalFindNextFileW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookFindClose,
    trampoline: cast[pointer](trampolineFindClose),
    origStorage: cast[ptr pointer](addr origFindClose),
    origCallback: originalFindClose,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # kernel32!GetProcAddress — intercepted to substitute our wrapper
  # for ntdll!NtQueryDirectoryFile (see comment near snoop body).
  HookSpec(name: hr.HookGetProcAddress,
    trampoline: cast[pointer](trampolineGetProcAddress),
    origStorage: cast[ptr pointer](addr origGetProcAddress),
    origCallback: originalGetProcAddress,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # --- M5: IPC-connect (ws2_32.dll) ---------------------------------------
  HookSpec(name: hr.HookConnect,
    trampoline: cast[pointer](trampolineConnect),
    origStorage: cast[ptr pointer](addr origConnect),
    origCallback: originalConnect,
    iatDlls: ws2IatDlls,
    moduleDll: "ws2_32.dll"),
  HookSpec(name: hr.HookWSAConnect,
    trampoline: cast[pointer](trampolineWSAConnect),
    origStorage: cast[ptr pointer](addr origWSAConnect),
    origCallback: originalWSAConnect,
    iatDlls: ws2IatDlls,
    moduleDll: "ws2_32.dll"),
  # --- M5: external content (kernel32.dll) --------------------------------
  HookSpec(name: hr.HookCreateFileMappingW,
    trampoline: cast[pointer](trampolineCreateFileMappingW),
    origStorage: cast[ptr pointer](addr origCreateFileMappingW),
    origCallback: originalCreateFileMappingW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreateFileMappingA,
    trampoline: cast[pointer](trampolineCreateFileMappingA),
    origStorage: cast[ptr pointer](addr origCreateFileMappingA),
    origCallback: originalCreateFileMappingA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookOpenFileMappingW,
    trampoline: cast[pointer](trampolineOpenFileMappingW),
    origStorage: cast[ptr pointer](addr origOpenFileMappingW),
    origCallback: originalOpenFileMappingW,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookOpenFileMappingA,
    trampoline: cast[pointer](trampolineOpenFileMappingA),
    origStorage: cast[ptr pointer](addr origOpenFileMappingA),
    origCallback: originalOpenFileMappingA,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookMapViewOfFile,
    trampoline: cast[pointer](trampolineMapViewOfFile),
    origStorage: cast[ptr pointer](addr origMapViewOfFile),
    origCallback: originalMapViewOfFile,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookMapViewOfFileEx,
    trampoline: cast[pointer](trampolineMapViewOfFileEx),
    origStorage: cast[ptr pointer](addr origMapViewOfFileEx),
    origCallback: originalMapViewOfFileEx,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookCreatePipe,
    trampoline: cast[pointer](trampolineCreatePipe),
    origStorage: cast[ptr pointer](addr origCreatePipe),
    origCallback: originalCreatePipe,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # --- M5: non-determinism ------------------------------------------------
  HookSpec(name: hr.HookBCryptGenRandom,
    trampoline: cast[pointer](trampolineBCryptGenRandom),
    origStorage: cast[ptr pointer](addr origBCryptGenRandom),
    origCallback: originalBCryptGenRandom,
    iatDlls: bcryptIatDlls,
    moduleDll: "bcrypt.dll"),
  # ProcessPrng is the Win10 1809+ export that bcrypt / the modern CRT / Go /
  # Rust actually bottom out in. Optional because a host without it has no such
  # API for a call to escape through.
  HookSpec(name: hr.HookProcessPrng,
    trampoline: cast[pointer](trampolineProcessPrng),
    origStorage: cast[ptr pointer](addr origProcessPrng),
    origCallback: originalProcessPrng,
    iatDlls: bcryptPrimitivesIatDlls,
    moduleDll: "bcryptprimitives.dll",
    optionalModule: true),
  HookSpec(name: hr.HookSystemFunction036,
    trampoline: cast[pointer](trampolineSystemFunction036),
    origStorage: cast[ptr pointer](addr origSystemFunction036),
    origCallback: originalSystemFunction036,
    iatDlls: advapi32IatDlls,
    moduleDll: "advapi32.dll"),
  HookSpec(name: hr.HookCryptGenRandom,
    trampoline: cast[pointer](trampolineCryptGenRandom),
    origStorage: cast[ptr pointer](addr origCryptGenRandom),
    origCallback: originalCryptGenRandom,
    iatDlls: advapi32IatDlls,
    moduleDll: "advapi32.dll"),
  HookSpec(name: hr.HookQueryPerformanceCounter,
    trampoline: cast[pointer](trampolineQueryPerformanceCounter),
    origStorage: cast[ptr pointer](addr origQueryPerformanceCounter),
    origCallback: originalQueryPerformanceCounter,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetSystemTimeAsFileTime,
    trampoline: cast[pointer](trampolineGetSystemTimeAsFileTime),
    origStorage: cast[ptr pointer](addr origGetSystemTimeAsFileTime),
    origCallback: originalGetSystemTimeAsFileTime,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetTickCount64,
    trampoline: cast[pointer](trampolineGetTickCount64),
    origStorage: cast[ptr pointer](addr origGetTickCount64),
    origCallback: originalGetTickCount64,
    iatDlls: kernel32FileIatDlls,
    moduleDll: "kernel32.dll"),
  # --- M10: observed environment (kernel32.dll) ---------------------------
  HookSpec(name: hr.HookGetEnvironmentVariableW,
    trampoline: cast[pointer](trampolineGetEnvironmentVariableW),
    origStorage: cast[ptr pointer](addr origGetEnvironmentVariableW),
    origCallback: originalGetEnvironmentVariableW,
    iatDlls: kernel32EnvIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetEnvironmentVariableA,
    trampoline: cast[pointer](trampolineGetEnvironmentVariableA),
    origStorage: cast[ptr pointer](addr origGetEnvironmentVariableA),
    origCallback: originalGetEnvironmentVariableA,
    iatDlls: kernel32EnvIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetEnvironmentStringsW,
    trampoline: cast[pointer](trampolineGetEnvironmentStringsW),
    origStorage: cast[ptr pointer](addr origGetEnvironmentStringsW),
    origCallback: originalGetEnvironmentStringsW,
    iatDlls: kernel32EnvIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetEnvironmentStringsA,
    trampoline: cast[pointer](trampolineGetEnvironmentStringsA),
    origStorage: cast[ptr pointer](addr origGetEnvironmentStringsA),
    origCallback: originalGetEnvironmentStringsA,
    iatDlls: kernel32EnvIatDlls,
    moduleDll: "kernel32.dll"),
  HookSpec(name: hr.HookGetEnvironmentStrings,
    trampoline: cast[pointer](trampolineGetEnvironmentStrings),
    origStorage: cast[ptr pointer](addr origGetEnvironmentStrings),
    origCallback: originalGetEnvironmentStrings,
    iatDlls: kernel32EnvIatDlls,
    moduleDll: "kernel32.dll"),
  # --- M10: observed environment (the UCRT) -------------------------------
  #
  # `optionalModule` on every UCRT entry, because a process built against the
  # legacy msvcrt need not have `ucrtbase.dll` mapped at all. `forceLoad
  # ObservedModules` asks for it, but an absent module means there is no
  # entry point for a call to escape through -- the same judgement M5 made for
  # `bcryptprimitives.dll`.
  HookSpec(name: hr.HookUcrtGetenv,
    trampoline: cast[pointer](trampolineUcrtGetenv),
    origStorage: cast[ptr pointer](addr origUcrtGetenv),
    origCallback: originalUcrtGetenv,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "getenv"),
  HookSpec(name: hr.HookUcrtWGetenv,
    trampoline: cast[pointer](trampolineUcrtWGetenv),
    origStorage: cast[ptr pointer](addr origUcrtWGetenv),
    origCallback: originalUcrtWGetenv,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "_wgetenv"),
  HookSpec(name: hr.HookUcrtGetenvS,
    trampoline: cast[pointer](trampolineUcrtGetenvS),
    origStorage: cast[ptr pointer](addr origUcrtGetenvS),
    origCallback: originalUcrtGetenvS,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "getenv_s"),
  HookSpec(name: hr.HookUcrtWGetenvS,
    trampoline: cast[pointer](trampolineUcrtWGetenvS),
    origStorage: cast[ptr pointer](addr origUcrtWGetenvS),
    origCallback: originalUcrtWGetenvS,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "_wgetenv_s"),
  HookSpec(name: hr.HookUcrtDupenvS,
    trampoline: cast[pointer](trampolineUcrtDupenvS),
    origStorage: cast[ptr pointer](addr origUcrtDupenvS),
    origCallback: originalUcrtDupenvS,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "_dupenv_s"),
  HookSpec(name: hr.HookUcrtWDupenvS,
    trampoline: cast[pointer](trampolineUcrtWDupenvS),
    origStorage: cast[ptr pointer](addr origUcrtWDupenvS),
    origCallback: originalUcrtWDupenvS,
    iatDlls: ucrtEnvIatDlls,
    moduleDll: "ucrtbase.dll",
    optionalModule: true,
    exportName: "_wdupenv_s"),
  # --- M10: observed environment (the legacy CRT) -------------------------
  #
  # `msvcrt.dll` exports NEITHER `_dupenv_s` NOR `_wdupenv_s` (probed on this
  # host, Win11 26200), so there is nothing to hook and nothing to escape
  # through; only the four it does export are listed.
  HookSpec(name: hr.HookMsvcrtGetenv,
    trampoline: cast[pointer](trampolineMsvcrtGetenv),
    origStorage: cast[ptr pointer](addr origMsvcrtGetenv),
    origCallback: originalMsvcrtGetenv,
    iatDlls: msvcrtEnvIatDlls,
    moduleDll: "msvcrt.dll",
    optionalModule: true,
    exportName: "getenv"),
  HookSpec(name: hr.HookMsvcrtWGetenv,
    trampoline: cast[pointer](trampolineMsvcrtWGetenv),
    origStorage: cast[ptr pointer](addr origMsvcrtWGetenv),
    origCallback: originalMsvcrtWGetenv,
    iatDlls: msvcrtEnvIatDlls,
    moduleDll: "msvcrt.dll",
    optionalModule: true,
    exportName: "_wgetenv"),
  HookSpec(name: hr.HookMsvcrtGetenvS,
    trampoline: cast[pointer](trampolineMsvcrtGetenvS),
    origStorage: cast[ptr pointer](addr origMsvcrtGetenvS),
    origCallback: originalMsvcrtGetenvS,
    iatDlls: msvcrtEnvIatDlls,
    moduleDll: "msvcrt.dll",
    optionalModule: true,
    exportName: "getenv_s"),
  HookSpec(name: hr.HookMsvcrtWGetenvS,
    trampoline: cast[pointer](trampolineMsvcrtWGetenvS),
    origStorage: cast[ptr pointer](addr origMsvcrtWGetenvS),
    origCallback: originalMsvcrtWGetenvS,
    iatDlls: msvcrtEnvIatDlls,
    moduleDll: "msvcrt.dll",
    optionalModule: true,
    exportName: "_wgetenv_s")
]

proc specExportName(spec: HookSpec): string {.raises: [].} =
  ## The undecorated export to resolve for `spec`. Differs from the registry
  ## key only for the CRT entries, whose keys are module-qualified because two
  ## modules export the same name into one process.
  if spec.exportName.len > 0: spec.exportName else: spec.name

proc forceLoadObservedModules() {.raises: [].} =
  ## Map the modules the M5 entry points live in, before the install pass.
  ##
  ## A hook can only be installed into a LOADED module. ws2_32 / bcrypt /
  ## advapi32 / bcryptprimitives are not part of every process's static import
  ## closure, so without this the install would skip them in exactly the
  ## processes that later `LoadLibrary` one and call through it -- an entry
  ## point advertised as hooked and in fact not, which is the M4 over-claim in
  ## a new place. Forcing them in makes "hooked for the whole process
  ## lifetime" true rather than incidental.
  ##
  ## The cost is that these images join the process's recorded module set, so
  ## they appear as library-load reads. That is not a fiction -- they really
  ## are mapped -- and it is the same status the shim's own DLL already has.
  ## M10 adds the two C runtimes for the same reason. `ucrtbase.dll` and
  ## `msvcrt.dll` each keep their OWN copy of the environment, and a process
  ## may map either, both, or one of them late (a plugin DLL built against the
  ## other runtime). Mapping both up front makes "the `getenv` family is
  ## hooked" true for the whole process lifetime instead of true only when the
  ## program happened to be linked the way we guessed.
  const names = ["ws2_32.dll", "bcrypt.dll", "advapi32.dll",
                 "bcryptprimitives.dll", "ucrtbase.dll", "msvcrt.dll"]
  for n in names:
    var wide = newSeq[uint16](n.len + 1)
    for i, c in n:
      wide[i] = uint16(ord(c))
    wide[n.len] = 0'u16
    discard LoadLibraryW(cast[LPCWSTR](addr wide[0]))

proc queueInlineInstall(spec: HookSpec; hModule: HANDLE): cint =
  ## Queue an inline JMP rel32 install for ``spec.name`` against
  ## ``hModule``'s function body (kernel32 for the M73 Phase 1-4 surface;
  ## ntdll for the M73 Phase 5 NtCreateFile backstop). Under an active
  ## transaction, the call returns 0 as soon as the op is queued; the
  ## trampoline pointer is written into ``spec.origStorage[]`` at commit
  ## time.
  ##
  ## Importantly, the ``out_trampoline`` argument we pass is
  ## ``spec.origStorage`` itself (the module-global ``addr origXxx``).
  ## Under a transaction the install primitive holds onto that pointer
  ## and writes through it at commit; a stack-local pointer would
  ## dangle by then. Wiring the chain's "original" callback MUST
  ## therefore be deferred until after ``ctInlineHookCommitTransaction``
  ## returns — otherwise, with the inline JMP already landed at the
  ## function body but ``origXxx`` still holding the (now-patched) real
  ## entry, the chain's "original" recurses through the trampoline.
  when not ctInlineHookAvailable:
    return -4
  else:
    if spec.origStorage[] != nil:
      # Already installed (idempotent call). Treat as success.
      return 0
    let exportName = specExportName(spec)
    let target = GetProcAddress(hModule, cast[LPCSTR](exportName.cstring))
    if target == nil:
      return -1
    let rc = ctInlineHookInstall(target, spec.trampoline, spec.origStorage)
    if rc == 0:
      installedHookTargets.add(target)
    return rc

proc installIatFor(spec: HookSpec) =
  ## Fallback IAT install for an entry point that the inline path rejected.
  ## Walks every fallback DLL the spec declares and patches the first IAT
  ## slot that yields a non-nil original pointer; subsequent DLLs only
  ## redirect (the chain already has the original wired).
  let exportName = specExportName(spec)
  for dll in spec.iatDlls:
    if spec.origStorage[] == nil:
      let orig = patchIATAllModules(dll.cstring, exportName.cstring,
                                    spec.trampoline)
      if orig != nil:
        spec.origStorage[] = orig
        hr.setOriginalCallback(spec.name, spec.origCallback)
        dbg(cstring("[repro_monitor_shim] hooked " & spec.name &
          " from " & dll & " (IAT fallback)\n"))
    else:
      # We already captured the real function pointer; only redirect the IAT.
      discard patchIATAllModules(dll.cstring, exportName.cstring,
                                 spec.trampoline)

proc installAllHooks(): int =
  ## Install every entry in ``hookTable``. Inline is preferred for every
  ## hook (dispatch-mechanism-agnostic, per Monitor-Hook-Shim.md spec);
  ## the IAT path is only walked for hooks the inline backend rejected.
  ## All inline installs are grouped inside a single transaction so the
  ## thread-suspend window happens once for the whole table rather than
  ## once per hook (see ct_inline_hook/install_windows.h "Transactions").
  ## Returns the count of hooks that fell through to the IAT fallback —
  ## tests treat any non-zero count as an acceptance issue.
  result = 0
  var failed: seq[HookSpec] = @[]
  # Per-spec record of "did the queued-install call succeed?" — only
  # specs that queued successfully will have their trampoline filled at
  # commit time, so only those should have ``setOriginalCallback`` wired
  # post-commit. The same vector also tells us which specs need the IAT
  # fallback (the ones where queueing was rejected OR commit failed).
  var inlineQueued = newSeq[bool](hookTable.len)
  var commitOk = false
  when ctInlineHookAvailable:
    # Per-spec hModule resolution. Cache module handles by name so we
    # don't burn a GetModuleHandleA per entry on the kernel32 surface.
    var moduleHandles = initTable[string, HANDLE]()
    proc resolveModule(name: string): HANDLE {.raises: [].} =
      try:
        if name in moduleHandles:
          return moduleHandles[name]
        let h = GetModuleHandleA(cast[LPCSTR](name.cstring))
        moduleHandles[name] = h
        return h
      except KeyError:
        # Defensive: `name in moduleHandles` already guarded the lookup;
        # the catch is here to satisfy `{.raises: [].}` on the outer
        # installAllHooks contract.
        return GetModuleHandleA(cast[LPCSTR](name.cstring))

    let beginRc = ctInlineHookBeginTransaction()
    let inTransaction = (beginRc == 0)
    if not inTransaction:
      dbg(cstring("[repro_monitor_shim] installAllHooks: begin_transaction failed rc=" & $beginRc & "; installing per-hook\n"))
    for i, spec in hookTable:
      let modName =
        if spec.moduleDll.len > 0: spec.moduleDll else: "kernel32.dll"
      let hModule = resolveModule(modName)
      if hModule == nil:
        if spec.optionalModule:
          # The module is not present on this host, so the entry point does not
          # exist and no call can escape through it. Skipping is honest here;
          # routing it to the IAT fallback would end with an event-loss record
          # naming an API the OS does not have, which would downgrade every
          # capture on that host for no observational shortfall.
          dbg(cstring("[repro_monitor_shim] installAllHooks: optional module " &
            modName & " absent; skipping " & spec.name & "\n"))
          continue
        dbg(cstring("[repro_monitor_shim] installAllHooks: " &
          "GetModuleHandleA(" & modName & ") returned NULL; falling back to IAT for " &
          spec.name & "\n"))
        failed.add(spec)
        continue
      let rc = queueInlineInstall(spec, hModule)
      if rc == 0:
        inlineQueued[i] = true
      else:
        dbg(cstring("[repro_monitor_shim] inline-hook FAILED for " &
          spec.name & " (rc=" & $rc & "); will try IAT fallback\n"))
        failed.add(spec)
    if inTransaction:
      let commitRc = ctInlineHookCommitTransaction()
      if commitRc == 0:
        commitOk = true
      else:
        dbg(cstring("[repro_monitor_shim] installAllHooks: commit_transaction failed rc=" & $commitRc & "\n"))
        # Commit failed -> ct_inline_hook rolls back the
        # partially-applied batch and origStorage[] stays nil for
        # every queued spec. Re-route them all to the IAT fallback.
        for i, spec in hookTable:
          if inlineQueued[i]:
            inlineQueued[i] = false
            failed.add(spec)
    else:
      # No transaction was active; each ctInlineHookInstall call ran
      # synchronously and wrote spec.origStorage[] in-line. The
      # successful ones are already committed.
      commitOk = true
  else:
    # ct_inline_hook sources unavailable — every hook degrades to IAT.
    for spec in hookTable:
      failed.add(spec)

  # Post-commit pass 1: wire the chain's "original" callback for every
  # spec whose inline install actually landed (trampoline pointer is now
  # non-nil in spec.origStorage[]). Pass 1 runs to completion BEFORE any
  # dbg log line — dbg itself dispatches through CreateFileA (and the
  # CRT path under it touches GetFileAttributesW), and emitting a log
  # line while any chain.original is still nil would short-circuit the
  # log file's own CreateFileA / GetFileAttributesW calls to a fake "fail"
  # path. Pass 2 below is the actual log emission, after every chain is
  # fully wired.
  var commitEmpty = newSeq[bool](hookTable.len)
  when ctInlineHookAvailable:
    if commitOk:
      for i, spec in hookTable:
        if inlineQueued[i]:
          if spec.origStorage[] != nil:
            hr.setOriginalCallback(spec.name, spec.origCallback)
          else:
            commitEmpty[i] = true
            failed.add(spec)

  # Post-commit pass 2: emit diagnostic lines. By this point every spec
  # in hookTable either has a wired chain (origStorage[] non-nil +
  # chain.original set) or is on the failed list awaiting IAT fallback.
  when ctInlineHookAvailable:
    if commitOk:
      for i, spec in hookTable:
        if inlineQueued[i] and not commitEmpty[i]:
          dbg(cstring("[repro_monitor_shim] inline-hooked " & spec.name & "\n"))
        elif commitEmpty[i]:
          dbg(cstring("[repro_monitor_shim] inline-hook commit-empty for " &
            spec.name & "; will try IAT fallback\n"))

  for spec in failed:
    installIatFor(spec)
    if spec.origStorage[] == nil:
      dbg(cstring("[repro_monitor_shim] install FAILED for " & spec.name &
        " (neither inline nor IAT landed a hook)\n"))
      inc unhookedEntryPoints
      if unhookedEntryPointNames.len > 0:
        unhookedEntryPointNames.add(", ")
      unhookedEntryPointNames.add(spec.name)
  result = failed.len

proc uninstallInlineHooksBatched*(targets: openArray[pointer]): int
    {.raises: [], discardable.} =
  ## Restore the original prologue bytes at every target in ``targets``
  ## inside a SINGLE thread-freeze window. Returns the number of targets
  ## whose restore was accepted.
  ##
  ## The batching is not a micro-optimisation, it is the whole cost of
  ## teardown. `ct_inline_hook_uninstall` freezes the process's other
  ## threads around each patch, and the freeze is a
  ## `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` — a SYSTEM-WIDE thread
  ## enumeration whose cost is set by the load of the whole machine, not by
  ## how many threads this process has. Measured on this host it is ~23.5 ms
  ## per call. Called once per hook, the 31-entry `hookTable` therefore cost
  ## ~0.73 s of pure freeze at exit in EVERY monitored process — and since a
  ## build is mostly short-lived compiler processes, that single loop was the
  ## dominant cost of monitoring a build (S4: a monitored `nim c` ran 8x
  ## slower than an unmonitored one, and ~90% of the gap was here).
  ##
  ## `installAllHooks` already groups its patches into one transaction for
  ## exactly this reason and says so in its docstring; teardown simply never
  ## got the same treatment. A transaction defers each op and applies the
  ## whole batch inside one freeze, so the window is one round for the table
  ## instead of one per entry. Nothing is skipped: this changes WHEN the
  ## threads are frozen, not WHICH patches are restored — the post-exit state
  ## is still byte-equivalent to a never-hooked process, which is the
  ## property the exit handler exists to guarantee.
  when ctInlineHookAvailable:
    var pending = 0
    for tgt in targets:
      if tgt != nil:
        inc pending
    if pending == 0:
      return 0
    # A transaction is bounded; past its capacity the queue rejects ops and
    # hooks would silently stay installed. Fall back to the per-hook path
    # rather than lose a restore — slow is recoverable, a JMP into an
    # unmapped code page is not.
    let batched = pending <= int(inlineHookTransactionCapacity()) and
      ctInlineHookBeginTransaction() == 0
    for tgt in targets:
      if tgt != nil and ctInlineHookUninstall(tgt) == 0:
        inc result
    if not batched:
      return
    let commitRc = ctInlineHookCommitTransaction()
    if commitRc == 0:
      return
    # A failed commit leaves an UNKNOWN mix: `ct_inline_hook_commit_transaction`
    # stops at the first failing op and its rollback pass only undoes queued
    # INSTALLS (it cannot re-install an uninstall — the caller's trampoline
    # pointer is gone), so the restores it already applied stay applied and
    # everything from the failing op onwards is still detoured. Which is which
    # is not reported. So retry the whole list one at a time: an already-restored
    # target has no table entry left and `uninstall_locked` returns -1 without
    # touching a byte, which makes the retry idempotent, and every target that
    # IS still detoured gets its prologue back. The freeze cost is the thing
    # this proc exists to avoid, but not at the price of leaving detours in
    # place while the shim's code pages go away.
    #
    # The count is therefore a LOWER bound in this path: restores that the
    # partial commit already performed answer -1 on the retry and are not
    # counted. Nothing reads it here (the exit handler discards it), and
    # under-reporting a teardown that had to fall back is the safe direction.
    dbg(cstring("[repro_monitor_shim] uninstallInlineHooksBatched: " &
      "commit_transaction failed rc=" & $commitRc &
      "; restoring per-hook\n"))
    result = 0
    for tgt in targets:
      if tgt != nil and ctInlineHookUninstall(tgt) == 0:
        inc result
  else:
    result = 0

proc uninstallAllInlineHooks(): int {.raises: [].} =
  ## Batched teardown of every entry point THIS process inline-patched.
  ## Split from `uninstallInlineHooksBatched` only so the batching itself
  ## can be asserted on an explicit target set from a test, without the
  ## test having to arrange for a live injection to populate
  ## `installedHookTargets`.
  uninstallInlineHooksBatched(installedHookTargets)

# --- Public exports ---------------------------------------------------------

proc repro_monitor_shim_init*(configPath: cstring): cint
    {.exportc, dynlib, cdecl.} =
  dbg("[repro_monitor_shim] repro_monitor_shim_init entered\n")
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    initLock(envLock)
    locksReady = true
  acquire(initLockVar)
  if initialized:
    release(initLockVar)
    return 0
  withShimMuted:
    fragmentDir = readEnvString("REPRO_MONITOR_FRAGMENT_DIR")
    ensureFragmentDir()
    # Snapshot the monitoring configuration BEFORE any hook is installed, so
    # the spawn path can hand it to a child whose caller built its own
    # environment block.
    captureMonitorEnvSnapshot()
    # Arm the thread-exit flush for the whole process. Must precede the first
    # record, because every registry entry made before this exists without a
    # destructor behind it.
    if fragmentFlsIndex.load() == 0:
      let idx = FlsAlloc(fragmentSlotThreadExit)
      if idx != high(uint32):
        fragmentFlsIndex.store(idx + 1)
    when defined(ioMonShimSpawnEscapeTest):
      # Only this build reads it at all; in the shipped shim the variable is
      # inert because the code that would honour it does not exist.
      case readEnvString("REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE")
      of "return": testSpawnEscape = tseEarlyReturn
      of "raise": testSpawnEscape = tseRaise
      else: testSpawnEscape = tseNone
  let dbgMsg = "[repro_monitor_shim] fragmentDir=" & fragmentDir & "\n"
  dbg(cstring(dbgMsg))
  # M26: initialise the hook registry + register the monitor's snoop
  # callbacks BEFORE installing the inline/IAT patches. installAllHooks
  # wires the captured origXxx into the chain's ``original`` slot once
  # the inline-hook trampoline (or IAT-captured real pointer) is in
  # hand; the snoop callbacks are already in place so the very first
  # hooked call sees a fully-built chain.
  hr.initShimRegistry()
  registerMonitorSnoopCallbacks()
  # M5 — caller attribution for the entropy hooks needs the program's own image
  # bounds, and the IPC / entropy entry points need their modules mapped before
  # the install pass can patch them. Both are cheap and must precede
  # installAllHooks.
  initMainImageRange()
  withShimMuted:
    forceLoadObservedModules()
  initialized = true
  release(initLockVar)
  recordProcessStart()
  # M73 Phase 1: single dispatch-mechanism-agnostic install pass.
  # Prefers ct_inline_hook (5-byte JMP rel32 at the kernel32 function
  # body — catches every dispatch mechanism), falls back to IAT
  # patching only for entry points the inline backend rejects. The
  # returned count is logged so any fall-through is visible in the
  # debug output and a future control-ABI accessor (Phase 4) can
  # surface it programmatically.
  let iatFallbackCount = installAllHooks()
  dbg(cstring("[repro_monitor_shim] installAllHooks: " &
    $iatFallbackCount & " hook(s) fell through to IAT fallback\n"))
  if unhookedEntryPoints > 0:
    recordHookInstallLoss(unhookedEntryPoints, unhookedEntryPointNames)

  # Library-load observation. Two halves, because neither alone is complete:
  # the loader notification only reports images mapped after we subscribe, and
  # an enumeration only sees the ones mapped so far. Registering FIRST means
  # an image mapped between the two steps is reported twice rather than not at
  # all; duplicate records are deduplicated downstream, a missed one is not.
  #
  # This is what earns `mcapLibraryLoad`, which is in
  # `InputEvidenceCapabilities` -- the floor a backend must meet before any
  # capture from it may claim mcComplete. Windows previously claimed it by
  # inheriting the macOS profile while observing no loads at all.
  registerDllNotification()
  emitAlreadyLoadedModules()
  # Flush for the same reason `recordProcessStart` does, and it bites harder
  # here: these records are `moFileRead`, so they land in the per-thread READ
  # BATCH, and this is the injector's remote init thread, which exits as soon
  # as init returns. An unflushed read batch whose thread disappears is
  # reported as "process killed with an un-flushed read batch" -- a loss that
  # downgrades the whole run. Emitting the enumeration without this flush
  # traded a capability gap for an event loss.
  withShimMuted:
    try:
      flushFragmentBatch()
    except CatchableError:
      discard
  # M73 Phase 4: post-install audit. Walk the hookTable, resolve each
  # spec's kernel32 address, and classify the first five bytes at the
  # target. The audit MUST run synchronously here — Monitor-Hook-Shim.md
  # §"Install Backend Requirement" requires the post-install state be
  # captured before any other code can uninstall hooks. Cost is ~11 *
  # (GetProcAddress + 5-byte read) = microseconds, well within the
  # loader's critical-path budget.
  block:
    # M73 Phase 5: every spec carries its own ``moduleDll`` so the audit
    # can resolve kernel32 + ntdll entries through one walk. Cache the
    # module handles to keep the GetModuleHandleA calls minimal.
    var auditModules = initTable[string, HANDLE]()
    var targets: seq[(string, pointer)] = @[]
    for spec in hookTable:
      let modName =
        if spec.moduleDll.len > 0: spec.moduleDll else: "kernel32.dll"
      var hMod: HANDLE = nil
      try:
        if modName in auditModules:
          hMod = auditModules[modName]
        else:
          hMod = GetModuleHandleA(cast[LPCSTR](modName.cstring))
          auditModules[modName] = hMod
      except KeyError:
        hMod = GetModuleHandleA(cast[LPCSTR](modName.cstring))
      if hMod == nil:
        if spec.optionalModule:
          # Absent optional module: nothing to audit and nothing missing.
          continue
        dbg(cstring("[repro_monitor_shim] install-audit SKIPPED for " &
          spec.name & ": GetModuleHandleA(" & modName & ") returned NULL\n"))
        # Pass nil so the audit module reports the failure consistently
        # with its existing "addr == nil -> failing name" branch.
        targets.add((spec.name, pointer(nil)))
        continue
      let auditExport = specExportName(spec)
      let addr0 = GetProcAddress(hMod, cast[LPCSTR](auditExport.cstring))
      targets.add((spec.name, addr0))
    runInstallAudit(targets, dbg)
  dbg("[repro_monitor_shim] initialization complete\n")
  # Pin the shim DLL in the process so its module image is never
  # unmapped — every kernel32 / ntdll entry point we patched holds a
  # 5-byte ``JMP rel32`` whose target is a proc inside this DLL, so
  # the JMP targets MUST remain valid for the entire process
  # lifetime. Without pinning, FreeLibrary calls (LdrUnloadDll, the
  # loader's automatic detach pass at process exit, etc.) can unmap
  # the shim image while the patched kernel32 functions are still
  # reachable through C-runtime exit handlers (libtest's atexit
  # chain calls CloseHandle / GetFileAttributesW / etc.), and the
  # next call hits ``STATUS_ACCESS_VIOLATION (0xc0000005)`` jumping
  # into unmapped memory. ``GetModuleHandleExW`` with
  # ``GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`` resolves the module
  # base from an address inside this DLL (the ``repro_monitor_shim_init``
  # proc's own code page); adding ``GET_MODULE_HANDLE_EX_FLAG_PIN``
  # bumps the loader refcount to ``MAXDWORD`` so subsequent
  # FreeLibrary calls become no-ops. Costs one resident DLL until
  # process exit — well worth avoiding the access violations.
  block:
    # Go through ByteAddress like ``ensureSelfDllPath`` does so gcc's
    # ``-Wincompatible-pointer-types`` warn-as-error path doesn't trip
    # on the function-pointer-to-LPCWSTR cast.
    let pinProbe = cast[ByteAddress](repro_monitor_shim_init)
    var dummy: HANDLE = nil
    discard GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS or
      GET_MODULE_HANDLE_EX_FLAG_PIN,
      cast[LPCWSTR](pinProbe),
      addr dummy)
  # Belt-and-suspenders: also register an atexit handler that uninstalls
  # every inline patch we installed. The PIN above keeps the shim DLL
  # mapped for the lifetime of the process so JMPs into its code remain
  # valid even if FreeLibrary is called repeatedly, but Pythonish embedded
  # interpreters / .NET hosts / cargo subprocesses we don't fully control
  # can still tear down their CRT state in surprising orders. Restoring
  # the original 5 bytes at each kernel32 entry point makes the post-exit
  # state byte-equivalent to a never-hooked process, so any further
  # kernel32 call from a deeper atexit chain is a normal direct call.
  block:
    {.gcsafe.}:
      addExitProc(proc() {.noconv.} =
        # ROUND-5 F (Windows parity) — flush the calling thread's fragment
        # slot before uninstalling the hook trampolines. Without this the
        # Windows shim leaves the read-tail-pending sentinel un-committed
        # on the fragment file, which mergeFragments accounts as a
        # kill-before-flush event-loss and false-downgrades the build's
        # completeness to mcIncomplete. The Linux shim flushes via its
        # `_exit` hook + `__attribute__((destructor))` (writer.nim's
        # closeFragmentSlot writes the matching committed marker); the
        # Windows shim previously did neither. addExitProc runs the
        # callbacks in LIFO order on ExitProcess / normal-return / CRT
        # `exit`, before the CRT walks Nim's atexit chain — matching the
        # Linux destructor's timing.
        #
        # EVERY thread's batch, not just this one's. `closeFragmentSlot`
        # reaches the caller's `fragmentSlot` THREADVAR and nothing else, so
        # in any process whose records were made on more than one thread the
        # other threads' buffered tails were simply abandoned -- which is
        # most monitored processes, and all of the interesting ones. Measured
        # on this host: `bash -c "grep foo <file>"` with the grep child
        # injected produced, from the child, its process-start and its
        # library loads (both emitted on the injector's init thread, which
        # flushes explicitly) and NOT ONE of the file opens or reads grep
        # actually did -- those were made on grep's own main thread, whose
        # batch died with it.
        #
        # `flushAllRegisteredSlots` is the same sweep the Linux shim has run
        # at shutdown since DEP-FLUSH-1, over the same registry; it ends by
        # closing the caller's own slot, so it SUBSUMES the call it replaces.
        # It deliberately does not retire another thread's read-tail sentinel
        # -- only that thread can -- so a swept batch still shows up as a
        # kill-before-flush loss. That keeps the change in the safe
        # direction: strictly more evidence on disk, never a better grade
        # than before.
        try:
          flushAllRegisteredSlots()
        except CatchableError, IOError, OSError:
          discard
        when ctInlineHookAvailable:
          discard uninstallAllInlineHooks()
        installedHookTargets.setLen(0))
  result = 0

proc repro_monitor_shim_flush*(): cint {.exportc, dynlib, cdecl.} =
  ## ROUND-5 F (Windows parity) — flush + close the calling thread's
  ## fragment slot so no buffered records are dropped. Previously a
  ## no-op stub (`= 0`), which meant every Windows-side execve /
  ## process-exit called by an out-of-tree consumer through the exported
  ## ABI left the read-tail sentinel dirty; mergeFragments accounted
  ## each dirty sentinel as kill-before-flush event-loss and downgraded
  ## completeness to mcIncomplete. Matches the Linux shim's flush proc.
  try:
    closeFragmentSlot()
  except CatchableError, IOError, OSError:
    discard
  result = 0

proc repro_monitor_shim_shutdown*(): cint {.exportc, dynlib, cdecl.} =
  ## ROUND-5 F (Windows parity) — process/thread shutdown: flush + close
  ## the calling thread's fragment slot. Invoked by the CRT exit
  ## machinery and by the Windows injector's synthetic-cleanup thread.
  ## Previously a no-op stub (`= 0`); same rationale as
  ## repro_monitor_shim_flush.
  try:
    closeFragmentSlot()
  except CatchableError, IOError, OSError:
    discard
  result = 0

proc repro_monitor_shim_disable_current_thread*() {.exportc, dynlib, cdecl.} =
  inc disabled

proc repro_monitor_shim_enable_current_thread*() {.exportc, dynlib, cdecl.} =
  if disabled > 0:
    dec disabled

proc repro_monitor_shim_version*(): cstring {.exportc, dynlib, cdecl.} =
  "repro_monitor_shim_m26"

# repro_runtime_init: stdcall entry point invoked by the Windows injector
# via CreateRemoteThread after LoadLibraryW returns. Matches the
# LPTHREAD_START_ROUTINE signature: DWORD WINAPI ThreadProc(LPVOID).
proc repro_runtime_init*(lpParameter: pointer): uint32
    {.stdcall, exportc, dynlib.} =
  result = uint32(repro_monitor_shim_init(nil))

# The exported repro_hook_* signatures mirror the macOS shim so that downstream
# tools that expected to find these symbols (e.g. for integration testing of
# the macOS hooks) can also link against the Windows DLL. They are *not* the
# real injection entry points on Windows — the IAT patcher swaps the imported
# Win32 API pointers directly — but they remain available for symmetry.

type
  PidT = uint32

proc repro_hook_open*(path: cstring; flags, mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  # Windows: POSIX-style open() is not the primary hook surface; we expose this
  # only for ABI parity with macos_interpose.nim. No record is emitted here.
  discard path
  discard flags
  discard mode
  result = -1

proc repro_hook_openat*(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  discard dirfd
  discard path
  discard flags
  discard mode
  result = -1

proc repro_hook_read*(fd: cint; buf: pointer; count: csize_t): int
    {.exportc, cdecl, dynlib.} =
  discard fd
  discard buf
  discard count
  result = -1

proc repro_hook_write*(fd: cint; buf: pointer; count: csize_t): int
    {.exportc, cdecl, dynlib.} =
  discard fd
  discard buf
  discard count
  result = -1

proc repro_hook_stat*(path: cstring; buf: pointer): cint
    {.exportc, cdecl, dynlib.} =
  discard path
  discard buf
  result = -1

proc repro_hook_fork*(): PidT {.exportc, cdecl, dynlib.} =
  # Windows: fork() has no Win32 equivalent; CreateProcess is hooked instead.
  result = PidT(0)

proc repro_hook_execve*(path: cstring; argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  discard path
  discard argv
  discard envp
  result = -1

proc repro_hook_posix_spawn*(pid: ptr PidT; path: cstring;
                              fileActions, attrp: pointer;
                              argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  discard pid
  discard path
  discard fileActions
  discard attrp
  discard argv
  discard envp
  result = -1

{.pop.}
