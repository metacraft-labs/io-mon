when not defined(windows):
  {.error: "repro_monitor_shim/windows_iat_patcher is Windows-only".}

# Windows: Standalone IAT (Import Address Table) patcher used by the
# repro_monitor_shim Windows DLL. This is structurally identical to the
# IAT patcher shipped in codetracer-native-recorder's ct_interpose, but
# inlined here so the Reprobuild Windows shim has no cross-repo Nim
# dependency on ct_runtime / ct_events / ct_ringbuf. The technique is
# the documented Windows equivalent of macOS DYLD_INSERT_LIBRARIES
# interposition: walk every loaded module's PE import directory, locate
# the named import, and atomically swap the IAT slot with VirtualProtect.

{.push raises: [].}

type
  HANDLE = pointer
  DWORD = uint32
  WORD = uint16
  LONG = int32
  ULONGLONG = uint64
  BOOL = int32
  BYTE = byte
  LPVOID = pointer

proc GetModuleHandleA(lpModuleName: cstring): pointer
  {.importc, stdcall, dynlib: "kernel32".}
proc VirtualProtect(lpAddress: LPVOID, dwSize: uint, flNewProtect: DWORD,
                    lpflOldProtect: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc EnumProcessModules(hProcess: HANDLE, lphModule: ptr pointer,
                        cb: DWORD, lpcbNeeded: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "psapi".}

const
  PAGE_READWRITE = 0x04'u32
  IMAGE_DOS_SIGNATURE = 0x5A4D'u16
  IMAGE_NT_SIGNATURE = 0x00004550'u32
  IMAGE_DIRECTORY_ENTRY_IMPORT = 1
  IMAGE_ORDINAL_FLAG64 = 0x8000000000000000'u64
  IMAGE_ORDINAL_FLAG32 = 0x80000000'u32

type
  ImageDosHeader {.packed.} = object
    e_magic: WORD
    e_cblp: WORD
    e_cp: WORD
    e_crlc: WORD
    e_cparhdr: WORD
    e_minalloc: WORD
    e_maxalloc: WORD
    e_ss: WORD
    e_sp: WORD
    e_csum: WORD
    e_ip: WORD
    e_cs: WORD
    e_lfarlc: WORD
    e_ovno: WORD
    e_res: array[4, WORD]
    e_oemid: WORD
    e_oeminfo: WORD
    e_res2: array[10, WORD]
    e_lfanew: LONG

  ImageFileHeader {.packed.} = object
    machine: WORD
    numberOfSections: WORD
    timeDateStamp: DWORD
    pointerToSymbolTable: DWORD
    numberOfSymbols: DWORD
    sizeOfOptionalHeader: WORD
    characteristics: WORD

  ImageDataDirectory {.packed.} = object
    virtualAddress: DWORD
    size: DWORD

  ImageOptionalHeader64 {.packed.} = object
    magic: WORD
    majorLinkerVersion: BYTE
    minorLinkerVersion: BYTE
    sizeOfCode: DWORD
    sizeOfInitializedData: DWORD
    sizeOfUninitializedData: DWORD
    addressOfEntryPoint: DWORD
    baseOfCode: DWORD
    imageBase: ULONGLONG
    sectionAlignment: DWORD
    fileAlignment: DWORD
    majorOperatingSystemVersion: WORD
    minorOperatingSystemVersion: WORD
    majorImageVersion: WORD
    minorImageVersion: WORD
    majorSubsystemVersion: WORD
    minorSubsystemVersion: WORD
    win32VersionValue: DWORD
    sizeOfImage: DWORD
    sizeOfHeaders: DWORD
    checkSum: DWORD
    subsystem: WORD
    dllCharacteristics: WORD
    sizeOfStackReserve: ULONGLONG
    sizeOfStackCommit: ULONGLONG
    sizeOfHeapReserve: ULONGLONG
    sizeOfHeapCommit: ULONGLONG
    loaderFlags: DWORD
    numberOfRvaAndSizes: DWORD
    dataDirectory: array[16, ImageDataDirectory]

  ImageNtHeaders64 {.packed.} = object
    signature: DWORD
    fileHeader: ImageFileHeader
    optionalHeader: ImageOptionalHeader64

  # PE32. Not a trimmed PE32+: `baseOfData` exists only here, and the five
  # fields that hold addresses or sizes of address ranges are DWORD rather
  # than ULONGLONG. The cumulative shift moves `dataDirectory` -- the only
  # field this module reads -- by 16 bytes, so parsing a PE32 image with the
  # PE32+ layout does not fail loudly; it reads a plausible-looking import
  # directory RVA from the wrong offset.
  ImageOptionalHeader32 {.packed.} = object
    magic: WORD
    majorLinkerVersion: BYTE
    minorLinkerVersion: BYTE
    sizeOfCode: DWORD
    sizeOfInitializedData: DWORD
    sizeOfUninitializedData: DWORD
    addressOfEntryPoint: DWORD
    baseOfCode: DWORD
    baseOfData: DWORD
    imageBase: DWORD
    sectionAlignment: DWORD
    fileAlignment: DWORD
    majorOperatingSystemVersion: WORD
    minorOperatingSystemVersion: WORD
    majorImageVersion: WORD
    minorImageVersion: WORD
    majorSubsystemVersion: WORD
    minorSubsystemVersion: WORD
    win32VersionValue: DWORD
    sizeOfImage: DWORD
    sizeOfHeaders: DWORD
    checkSum: DWORD
    subsystem: WORD
    dllCharacteristics: WORD
    sizeOfStackReserve: DWORD
    sizeOfStackCommit: DWORD
    sizeOfHeapReserve: DWORD
    sizeOfHeapCommit: DWORD
    loaderFlags: DWORD
    numberOfRvaAndSizes: DWORD
    dataDirectory: array[16, ImageDataDirectory]

  ImageNtHeaders32 {.packed.} = object
    signature: DWORD
    fileHeader: ImageFileHeader
    optionalHeader: ImageOptionalHeader32

  ImageImportDescriptor {.packed.} = object
    originalFirstThunk: DWORD
    timeDateStamp: DWORD
    forwarderChain: DWORD
    name: DWORD
    firstThunk: DWORD

  ImageThunkData64 {.packed.} = object
    u1: ULONGLONG

  ImageThunkData32 {.packed.} = object
    u1: DWORD

  ImageImportByName {.packed.} = object
    hint: WORD

# The walk below only ever visits modules loaded into THIS process, and a
# process's modules all share its bitness -- a 32-bit process cannot load a
# PE32+ image, nor a 64-bit process a PE32. So the build's own pointer size
# selects the format; there is no need to read each image's `magic`, and no
# case where one process must handle both.
#
# Getting this wrong was silent in the direction that matters. The 32-bit
# shim walked PE32 imports with the PE32+ layout: an import directory read
# from a 16-byte-shifted offset, then 8-byte thunk strides across a table of
# 4-byte thunks. It matched nothing, returned nil for every entry point, and
# reported no error -- so a 32-bit child ran fully unhooked while looking, in
# the record stream, exactly like a process with no dependencies.
when sizeof(pointer) == 8:
  type
    ImageNtHeaders = ImageNtHeaders64
    ImageThunkData = ImageThunkData64
  const IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64
else:
  type
    ImageNtHeaders = ImageNtHeaders32
    ImageThunkData = ImageThunkData32
  const IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32

proc rvaToPtr(base: pointer, rva: DWORD): pointer {.inline.} =
  cast[pointer](cast[uint64](base) + uint64(rva))

proc cStrEqInsensitive(a, b: cstring): bool =
  var i = 0
  while true:
    var ca = a[i]
    var cb = b[i]
    if ca >= 'A' and ca <= 'Z': ca = chr(ord(ca) + 32)
    if cb >= 'A' and cb <= 'Z': cb = chr(ord(cb) + 32)
    if ca != cb:
      return false
    if ca == '\0':
      return true
    inc i

proc cStrEq(a, b: cstring): bool =
  var i = 0
  while true:
    if a[i] != b[i]:
      return false
    if a[i] == '\0':
      return true
    inc i

proc patchIATInModule*(moduleBase: pointer, targetDll: cstring,
                       funcName: cstring, hookFunc: pointer): pointer =
  let dosHeader = cast[ptr ImageDosHeader](moduleBase)
  if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    return nil

  let ntHeaders = cast[ptr ImageNtHeaders](
    rvaToPtr(moduleBase, DWORD(dosHeader.e_lfanew)))
  if ntHeaders.signature != IMAGE_NT_SIGNATURE:
    return nil

  let importDir = ntHeaders.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  if importDir.virtualAddress == 0 or importDir.size == 0:
    return nil

  var importDesc = cast[ptr ImageImportDescriptor](
    rvaToPtr(moduleBase, importDir.virtualAddress))

  while importDesc.name != 0:
    let dllName = cast[cstring](rvaToPtr(moduleBase, importDesc.name))

    if cStrEqInsensitive(dllName, targetDll):
      let intBase = importDesc.originalFirstThunk
      let iatBase = importDesc.firstThunk

      if iatBase == 0:
        importDesc = cast[ptr ImageImportDescriptor](
          cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))
        continue

      let lookupBase = if intBase != 0: intBase else: iatBase

      var idx = 0
      while true:
        let lookupThunk = cast[ptr ImageThunkData](
          rvaToPtr(moduleBase, lookupBase + DWORD(idx * sizeof(ImageThunkData))))
        let iatThunk = cast[ptr ImageThunkData](
          rvaToPtr(moduleBase, iatBase + DWORD(idx * sizeof(ImageThunkData))))

        if lookupThunk.u1 == 0:
          break

        if (lookupThunk.u1 and IMAGE_ORDINAL_FLAG) == 0:
          let importByName = cast[ptr ImageImportByName](
            rvaToPtr(moduleBase, DWORD(lookupThunk.u1)))
          let importFuncName = cast[cstring](
            cast[uint64](importByName) + uint64(sizeof(WORD)))

          if cStrEq(importFuncName, funcName):
            let iatEntryAddr = cast[ptr pointer](addr iatThunk.u1)
            let originalFunc = cast[pointer](iatThunk.u1)

            var oldProtect: DWORD = 0
            let protResult = VirtualProtect(
              cast[LPVOID](iatEntryAddr),
              uint(sizeof(pointer)),
              PAGE_READWRITE,
              addr oldProtect)
            if protResult == 0:
              return nil

            iatEntryAddr[] = hookFunc

            var dummy: DWORD = 0
            discard VirtualProtect(
              cast[LPVOID](iatEntryAddr),
              uint(sizeof(pointer)),
              oldProtect,
              addr dummy)

            return originalFunc

        inc idx

    importDesc = cast[ptr ImageImportDescriptor](
      cast[uint64](importDesc) + uint64(sizeof(ImageImportDescriptor)))

  return nil

proc GetModuleFileNameA(hModule: pointer, lpFilename: cstring,
                        nSize: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}

proc moduleBaseName(handle: pointer): string =
  var buf: array[1024, char]
  let n = GetModuleFileNameA(handle, cast[cstring](addr buf[0]),
                              DWORD(buf.len))
  if n == 0:
    return ""
  result = ""
  var start = 0
  for i in 0 ..< int(n):
    if buf[i] == '\\' or buf[i] == '/':
      start = i + 1
  for i in start ..< int(n):
    var c = buf[i]
    if c >= 'A' and c <= 'Z':
      c = chr(ord(c) + 32)
    result.add(c)

proc strStartsWith(s, prefix: string): bool =
  if s.len < prefix.len: return false
  for i in 0 ..< prefix.len:
    if s[i] != prefix[i]: return false
  true

proc isLoaderCriticalModule(name: string): bool =
  ## Windows: skip these modules to avoid breaking the loader's own
  ## pass-through to the real Win32 API. When kernel32.dll forwards into
  ## kernelbase.dll via its own IAT, patching that IAT entry traps the
  ## pass-through call from our hook back into our hook (infinite
  ## recursion). The set below is the standard list of "tier 0" modules
  ## that any production API hooker (Detours, EasyHook, MinHook) excludes
  ## from IAT rewrites for the same reason.
  name == "kernel32.dll" or name == "kernelbase.dll" or
    name == "ntdll.dll" or name == "kernel.appcore.dll" or
    strStartsWith(name, "api-ms-win-") or
    strStartsWith(name, "ext-ms-win-")

proc patchIATAllModules*(targetDll: cstring, funcName: cstring,
                         hookFunc: pointer): pointer =
  ## Patch the IAT entry for `funcName` (imported from `targetDll`) across
  ## every loaded module that isn't itself part of the Windows API import
  ## chain (kernel32 / kernelbase / ntdll / api-ms-win-*). Returns the
  ## first original function pointer discovered, or nil if no module
  ## imports the symbol.
  let hProcess = GetCurrentProcess()
  var modules: array[1024, pointer]
  var cbNeeded: DWORD = 0

  let enumResult = EnumProcessModules(
    hProcess,
    addr modules[0],
    DWORD(sizeof(modules)),
    addr cbNeeded)

  if enumResult == 0:
    let mainModule = GetModuleHandleA(nil)
    if mainModule == nil:
      return nil
    return patchIATInModule(mainModule, targetDll, funcName, hookFunc)

  let moduleCount = int(cbNeeded) div sizeof(pointer)
  var firstOriginal: pointer = nil

  for i in 0 ..< min(moduleCount, 1024):
    let modHandle = modules[i]
    let modName = moduleBaseName(modHandle)
    if isLoaderCriticalModule(modName):
      continue
    let original = patchIATInModule(modHandle, targetDll, funcName, hookFunc)
    if original != nil and firstOriginal == nil:
      firstOriginal = original

  return firstOriginal

{.pop.}
