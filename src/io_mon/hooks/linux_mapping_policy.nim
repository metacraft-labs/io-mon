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
  ## The second line of the shim's exclusion: a mapping whose path names a
  ## shim by its canonical file name. The first line is the address test
  ## (`OwnImage`), which finds the running image whatever its name. This one
  ## still matters for a canonically named shim the address test does not
  ## cover: the running image when its address was not placed in any
  ## enumerated mapping, and a second, inactive shim image in the same
  ## process (a nested monitor's distinct copy).
  ##
  ## Exported alongside `isSystemRuntimeMappingPath` for the same M9.R.67.1
  ## regression test.
  path.contains("/librepro_monitor_shim.") or
    path.endsWith("/librepro_monitor_shim.so") or
    path.endsWith("/librepro_monitor_shim.so (deleted)")

type
  OwnImage* = object
    ## The file the code doing the inline-syscall scan was loaded from: the
    ## shim, or any other hook library built over the preload runtime. Its
    ## text holds the SIGTRAP handler and the raw-syscall helpers the
    ## installer itself runs, so patching any of it with `int3` makes the
    ## installer trap on its own next syscall before the handler can take it
    ## (issue 2026-11-14-the-linux-shim-recognizes-its-own-mapping-by-file-
    ## name-so-a-renamed-copy-traps-on-its-own-syscalls). The spec excludes
    ## "the shim itself", whatever its file is called, so the image is found
    ## by address: the mapping that contains an address inside the runtime.
    known*: bool
      ## False when no enumerated mapping contained the address; the policy
      ## then falls back to the file-name test alone.
    start*, stop*: uint
      ## The mapping that contains the address.
    device*: string
    inode*: uint64
      ## The backing file's identity as `/proc/self/maps` prints it. Every
      ## other mapping of the same file is the same image (a non-default
      ## layout can give an image more than one executable segment).

proc ownImageOf*(mappings: openArray[LinuxExecutableMapping];
                 address: uint): OwnImage {.raises: [].} =
  ## The image among `mappings` that contains `address`. The caller passes an
  ## address in its own text (the trap handler's), so the result is the
  ## image the caller runs from, found the way `dladdr(3)` would find it
  ## (https://man7.org/linux/man-pages/man3/dladdr.3.html): by range, not by
  ## name.
  if address == 0:
    return
  for mapping in mappings:
    if address >= mapping.start and address < mapping.stop:
      return OwnImage(known: true, start: mapping.start, stop: mapping.stop,
                      device: mapping.device, inode: mapping.inode)

proc isOwnImageMapping*(mapping: LinuxExecutableMapping;
                        own: OwnImage): bool {.raises: [].} =
  ## Whether `mapping` belongs to the running image `own`: it is the mapping
  ## that contains the image's address, or another mapping of the same file.
  if not own.known:
    return false
  if mapping.start == own.start and mapping.stop == own.stop:
    return true
  own.inode != 0 and mapping.inode == own.inode and
    mapping.device == own.device

proc shouldPatchInlineSyscallMapping*(mapping: LinuxExecutableMapping;
                                      executablePath: string;
                                      own: OwnImage): bool {.raises: [].} =
  ## Whether the startup / post-loader scan patches `mapping`'s inline
  ## syscalls. `own` is the image the scan runs from (`ownImageOf`); it is
  ## never patched, whatever its file name.
  if not (mapping.readable and mapping.executable):
    return false
  if mapping.writable or mapping.path.len == 0 or not mapping.privateMapping:
    return false
  if mapping.path[0] == '[' or mapping.path[0] != '/':
    return false
  # The running image first: it is excluded even when it is the executable
  # (a program that links the runtime in) and even under a file name the
  # name test below does not know.
  if isOwnImageMapping(mapping, own):
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
