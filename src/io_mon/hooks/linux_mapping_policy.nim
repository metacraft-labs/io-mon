## Mapping selection shared by the Linux interposer and its policy tests.
## Importing this module does not export libc interposers or install hooks.

when not defined(linux):
  {.error: "io_mon/hooks/linux_mapping_policy is Linux-only".}

import std/[os, strutils]
import stackable_hooks/platform/linux_raw_syscalls

proc normalizeMappingPath(path: string): string {.raises: [].} =
  if path.len == 0:
    return ""
  try:
    result = expandSymlink(path)
  except CatchableError:
    result = path

proc isSystemRuntimeMappingPath*(path: string): bool {.raises: [].} =
  ## Keep startup DSO scanning out of loader/libc/toolchain runtime mappings.
  ## io-mon can safely classify file syscalls once a selected site traps, but
  ## broad runtime-library patching would turn ordinary libc/loader internals
  ## into false raw-syscall event-loss for every monitored process.
  ##
  ## Exported for M9.R.67.1's regression test
  ## (`tests/linux/test_io_mon_inline_patch_predicate.nim`) so the
  ## precedence order between this predicate and the
  ## `executable-mapping-short-circuit` in
  ## `shouldPatchInlineSyscallMapping` stays under regression cover.
  let filename = path.extractFilename
  filename in [
      "libanl.so.1", "libBrokenLocale.so.1", "libc.so.6", "libdl.so.2",
      "libm.so.6", "libmvec.so.1", "libpthread.so.0", "libresolv.so.2",
      "librt.so.1", "libthread_db.so.1", "libutil.so.1",
    ] or
    filename.startsWith("libnss_") or
    filename.startsWith("ld-linux-") or
    filename.startsWith("ld-musl-") or
    path.startsWith("/lib/") or path.startsWith("/lib64/") or
    path.startsWith("/usr/lib/") or path.startsWith("/usr/lib64/") or
    path.startsWith("/nix/store/")

proc isMonitorShimMappingPath*(path: string): bool {.raises: [].} =
  ## Exported alongside `isSystemRuntimeMappingPath` for the same M9.R.67.1
  ## regression test.
  path.contains("/librepro_monitor_shim.") or
    path.endsWith("/librepro_monitor_shim.so") or
    path.endsWith("/librepro_monitor_shim.so (deleted)")

proc shouldPatchInlineSyscallMapping*(mapping: LinuxExecutableMapping;
                                      executablePath: string): bool {.raises: [].} =
  if not (mapping.readable and mapping.executable):
    return false
  if mapping.writable or mapping.path.len == 0 or not mapping.privateMapping:
    return false
  if mapping.path[0] == '[' or mapping.path[0] != '/':
    return false
  if executablePath.len == 0:
    return false
  let normalized = normalizeMappingPath(mapping.path)
  # M9.R.67.1 — the system-runtime / monitor-shim exclusions MUST take
  # precedence over the executable short-circuit. When a monitored
  # subtree's top-of-tree exec is itself a toolchain binary (e.g. Nix's
  # `/nix/store/…-gcc-14.3.0/…/cc1`) we still want the `isSystemRuntime`
  # policy to apply: patching a `/nix/store/…/cc1` false-positive `0F 05
  # XX` byte sequence (from `looksLikeLinuxX8664Syscall`) mid-instruction
  # corrupts cc1 and crashes it at `init_emit_regs` on the FIRST
  # sanitycheckc.c meson build. See
  # `recipes/reproos-image/run-evidence/m9r67/m9r67_phaseA_byte_identity.txt`
  # for the byte-identity + path-dependence characterization.
  if isMonitorShimMappingPath(normalized) or isSystemRuntimeMappingPath(normalized):
    return false
  if normalized == executablePath:
    return true
  normalized.endsWith(".so") or normalized.contains(".so.")
