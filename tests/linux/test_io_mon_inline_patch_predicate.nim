## test_io_mon_inline_patch_predicate — M9.R.67.1 regression pin.
##
## Locks in the CORRECTED precedence order between the
## `isSystemRuntimeMappingPath` / `isMonitorShimMappingPath` exclusions
## and the executable-mapping short-circuit inside
## `shouldPatchInlineSyscallMapping`.
##
## Pre-fix, the executable short-circuit ran BEFORE the system-runtime
## exclusion. When a monitored subtree's top-of-tree exec was a
## nix-store toolchain binary (e.g. `/nix/store/…-gcc-14.3.0/…/cc1`),
## the executable short-circuit patched cc1's `.text` even though
## `isSystemRuntimeMappingPath` classified `/nix/store/` as toolchain
## runtime. Cc1's `init_emit_regs` contained a byte sequence the
## conservative `looksLikeLinuxX8664Syscall` predicate false-positived
## on (`0F 05 XX` with `XX != 0x00` at a non-instruction boundary);
## INT3 replacement mid-instruction crashed the FIRST meson
## `sanitycheckc.c` compile with `internal compiler error: Segmentation
## fault` at `init_emit_regs()` (SEGV_MAPERR, si_addr=0x3a0).
##
## After the M9.R.67.1 order swap: the system-runtime / monitor-shim
## exclusions take precedence over the executable short-circuit. A
## nix-store toolchain executable is now correctly excluded from
## inline-syscall INT3 patching.
##
## The user-app inline-syscall regression pin
## (`test_io_mon_linux_inline_asm_exit_group.nim`) still passes: its
## probe lives under `/tmp/`, outside every `isSystemRuntimeMappingPath`
## prefix, so its executable IS still patched.

import std/[unittest]

import io_mon/hooks/linux_preload_runtime
import stackable_hooks/platform/linux_raw_syscalls

# `linux_preload_runtime`'s embedded C block references
# `repro_linux_sig_safe_flush` from `shim/linux_preload.nim`. Since this
# unit test only exercises the pure-Nim predicate, provide an empty stub
# so the link step succeeds without pulling in the full shim assembly.
{.emit: """
void repro_linux_sig_safe_flush(void) { }
""".}

proc mapping(path: string; writable = false; privateMapping = true;
             readable = true; executable = true;
             start = 0x1000'u; stop = 0x2000'u): LinuxExecutableMapping =
  LinuxExecutableMapping(
    path: path,
    start: start,
    stop: stop,
    readable: readable,
    writable: writable,
    executable: executable,
    privateMapping: privateMapping,
  )

suite "M9.R.67.1 inline-syscall patch predicate precedence":

  test "isSystemRuntimeMappingPath classifies the documented prefixes":
    check isSystemRuntimeMappingPath("/lib/x86_64-linux-gnu/libc.so.6")
    check isSystemRuntimeMappingPath("/lib64/ld-linux-x86-64.so.2")
    check isSystemRuntimeMappingPath("/usr/lib/libpthread.so.0")
    check isSystemRuntimeMappingPath("/usr/lib64/libstdc++.so.6")
    check isSystemRuntimeMappingPath(
      "/nix/store/kzq78n13l8w24jn8bx4djj79k5j717f1-gcc-14.3.0" &
      "/libexec/gcc/x86_64-unknown-linux-gnu/14.3.0/cc1")
    # Not-covered prefixes:
    check not isSystemRuntimeMappingPath("/opt/repro/reprobuild/build/lib/foo.so")
    check not isSystemRuntimeMappingPath("/tmp/probe/user_app")
    check not isSystemRuntimeMappingPath("/home/user/project/main")

  test "isMonitorShimMappingPath recognises the canonical shim filename":
    check isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so")
    check isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so (deleted)")
    check isMonitorShimMappingPath("/tmp/librepro_monitor_shim.debug")
    # Non-canonical variants MUST NOT match (renaming the shim to any
    # other filename lifts the "self" exemption, as the M9.R.67 Phase B
    # bisection observed):
    check not isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/shim.so")
    check not isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_monitor.so")
    check not isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_shim.so")

  test "M9.R.67.1: nix-store toolchain executable is EXCLUDED even when it " &
       "matches executablePath":
    ## The core regression pin. A toolchain binary at a `/nix/store/`
    ## path was pre-M9.R.67.1 patched via the executable short-circuit,
    ## crashing cc1 at `init_emit_regs`. After the order swap, the
    ## system-runtime exclusion wins.
    let cc1 = "/nix/store/kzq78n13l8w24jn8bx4djj79k5j717f1-gcc-14.3.0" &
      "/libexec/gcc/x86_64-unknown-linux-gnu/14.3.0/cc1"
    let m = mapping(cc1)
    check not shouldPatchInlineSyscallMapping(m, executablePath = cc1)

  test "shim's own mapping is EXCLUDED regardless of executablePath":
    let shim = "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so"
    check not shouldPatchInlineSyscallMapping(
      mapping(shim),
      executablePath = "/opt/repro/reprobuild/build/bin/repro")

  test "user-app executable outside system-runtime prefixes IS patched":
    ## The M9.R.63.2 inline-asm exit_group pin lives under `/tmp/`.
    ## Its patching MUST still happen after the M9.R.67.1 swap so
    ## the shim can still catch that class of inline syscalls.
    let userApp = "/tmp/probe_dir/inline_asm_exit_group"
    check shouldPatchInlineSyscallMapping(mapping(userApp),
      executablePath = userApp)

  test "arbitrary user-owned .so (not shim, not system runtime) IS patched":
    let libFoo = "/opt/repro/reprobuild/build/lib/libfoo.so"
    check shouldPatchInlineSyscallMapping(mapping(libFoo),
      executablePath = "/opt/repro/reprobuild/build/bin/repro")

  test "system-runtime .so is EXCLUDED":
    let libc = "/nix/store/xx7cm72qy2c0643cm1ipngd87aqwkcdp-glibc-2.40-66" &
      "/lib/libc.so.6"
    check not shouldPatchInlineSyscallMapping(mapping(libc),
      executablePath = "/opt/repro/reprobuild/build/bin/repro")

  test "writable / shared / anonymous mappings are always EXCLUDED":
    let userApp = "/tmp/probe_dir/foo"
    check not shouldPatchInlineSyscallMapping(
      mapping(userApp, writable = true), executablePath = userApp)
    check not shouldPatchInlineSyscallMapping(
      mapping(userApp, privateMapping = false), executablePath = userApp)
    check not shouldPatchInlineSyscallMapping(
      mapping("[heap]"), executablePath = userApp)
    check not shouldPatchInlineSyscallMapping(
      mapping(""), executablePath = userApp)
