when not defined(macosx):
  {.error: "io_mon/hooks/macos_bodypatch is macOS-only".}

## Compatibility wrapper for the former io-mon-local macOS bodypatch module.
## The substantive install/trampoline implementation now lives in
## `stackable_hooks/platform/macos_bodypatch`; io-mon keeps this path only for
## transitional imports and the historical `reproMacosBodypatch*` Nim names.

import stackable_hooks/platform/macos_bodypatch

export macos_bodypatch

const BodypatchExcludeImage = "librepro_monitor_shim"

proc reproMacosBodypatchInstall*(target, hook: pointer): cint =
  stackableMacosBodypatchInstall(target, hook)

proc reproMacosBodypatchInstallNamed*(name: cstring; hook: pointer;
    installed, failed, absent: ptr cint) =
  stackableMacosBodypatchInstallNamedExcluding(name, hook,
    cstring(BodypatchExcludeImage), installed, failed, absent)

proc reproMacosBodypatchBuildTrampoline*(target: pointer; err: ptr cint): pointer =
  stackableMacosBodypatchBuildTrampoline(target, err)

proc reproMacosBodypatchInstallNamedTramp*(name: cstring; hook: pointer;
    outTrampoline: ptr pointer; installed, failed, absent: ptr cint) =
  stackableMacosBodypatchInstallNamedTrampExcluding(name, hook,
    cstring(BodypatchExcludeImage), outTrampoline, installed, failed, absent)
