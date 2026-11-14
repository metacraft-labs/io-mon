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

import io_mon/hooks/linux_mapping_policy
import stackable_hooks/platform/linux_raw_syscalls

# No mocks or link-only stubs: test the production mapping policy directly.
# The runtime imports this same module; libc interposition stays in its own
# integration tests so the outer build monitor can observe this test normally.

proc mapping(path: string; writable = false; privateMapping = true;
             readable = true; executable = true;
             start = 0x1000'u; stop = 0x2000'u;
             device = "fd:01"; inode = 0'u64): LinuxExecutableMapping =
  LinuxExecutableMapping(
    path: path,
    start: start,
    stop: stop,
    readable: readable,
    writable: writable,
    executable: executable,
    privateMapping: privateMapping,
    device: device,
    inode: inode,
  )

# The cases below test the path policy, so no running image is identified:
# exactly what the scan sees when `ownImageOf` finds no mapping.
const noOwn = OwnImage()

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

  test "source-built dynamic runtimes are excluded outside system prefixes":
    let sourceGlibc = "/home/user/reprobuild/recipes/packages/source/glibc" &
      "/.repro/output/install/usr/lib"
    check isSystemRuntimeMappingPath(sourceGlibc & "/libc.so.6")
    check isSystemRuntimeMappingPath(
      sourceGlibc & "/ld-linux-x86-64.so.2")
    for runtime in ["libdl.so.2", "libm.so.6", "libpthread.so.0", "librt.so.1"]:
      check isSystemRuntimeMappingPath(sourceGlibc & "/" & runtime)
    check isSystemRuntimeMappingPath(
      "/home/user/musl/output/lib/ld-musl-x86_64.so.1")
    check not isSystemRuntimeMappingPath(sourceGlibc & "/libuser.so.1")

  test "isMonitorShimMappingPath recognises the canonical shim filename":
    check isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so")
    check isMonitorShimMappingPath(
      "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so (deleted)")
    check isMonitorShimMappingPath("/tmp/librepro_monitor_shim.debug")
    # Non-canonical variants do not match the NAME test. A renamed shim is
    # excluded by the address test instead (`OwnImage`, the suite below):
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
    check not shouldPatchInlineSyscallMapping(m, executablePath = cc1, own = noOwn)

  test "shim's own mapping is EXCLUDED regardless of executablePath":
    let shim = "/opt/repro/reprobuild/build/lib/librepro_monitor_shim.so"
    check not shouldPatchInlineSyscallMapping(
      mapping(shim),
      executablePath = "/opt/repro/reprobuild/build/bin/repro", own = noOwn)

  test "user-app executable outside system-runtime prefixes IS patched":
    ## The M9.R.63.2 inline-asm exit_group pin lives under `/tmp/`.
    ## Its patching MUST still happen after the M9.R.67.1 swap so
    ## the shim can still catch that class of inline syscalls.
    let userApp = "/tmp/probe_dir/inline_asm_exit_group"
    check shouldPatchInlineSyscallMapping(mapping(userApp),
      executablePath = userApp, own = noOwn)

  test "arbitrary user-owned .so (not shim, not system runtime) IS patched":
    let libFoo = "/opt/repro/reprobuild/build/lib/libfoo.so"
    check shouldPatchInlineSyscallMapping(mapping(libFoo),
      executablePath = "/opt/repro/reprobuild/build/bin/repro", own = noOwn)

  test "system-runtime .so is EXCLUDED":
    let libc = "/nix/store/xx7cm72qy2c0643cm1ipngd87aqwkcdp-glibc-2.40-66" &
      "/lib/libc.so.6"
    check not shouldPatchInlineSyscallMapping(mapping(libc),
      executablePath = "/opt/repro/reprobuild/build/bin/repro", own = noOwn)

  test "source-built glibc runtime is EXCLUDED":
    let sourceGlibc = "/home/user/reprobuild/recipes/packages/source/glibc" &
      "/.repro/output/install/usr/lib/libc.so.6"
    check not shouldPatchInlineSyscallMapping(mapping(sourceGlibc),
      executablePath = "/opt/repro/reprobuild/build/bin/repro", own = noOwn)

  test "writable / shared / anonymous mappings are always EXCLUDED":
    let userApp = "/tmp/probe_dir/foo"
    check not shouldPatchInlineSyscallMapping(
      mapping(userApp, writable = true), executablePath = userApp, own = noOwn)
    check not shouldPatchInlineSyscallMapping(
      mapping(userApp, privateMapping = false), executablePath = userApp, own = noOwn)
    check not shouldPatchInlineSyscallMapping(
      mapping("[heap]"), executablePath = userApp, own = noOwn)
    check not shouldPatchInlineSyscallMapping(
      mapping(""), executablePath = userApp, own = noOwn)

suite "the running image is excluded by address, not by file name":
  ## Issue 2026-11-14-the-linux-shim-recognizes-its-own-mapping-by-file-name-
  ## so-a-renamed-copy-traps-on-its-own-syscalls: a copy of the shim under any
  ## other file name patched its own raw-syscall sites and died of SIGTRAP.
  ## `tests/linux/test_io_mon_shim_renamed_copy_runs.nim` drives the real
  ## shim; these cases pin the policy that decides it.
  let renamed = "/tmp/x/other-name.so"
  let shimText = mapping(renamed, start = 0x7f0000001000'u,
                         stop = 0x7f0000080000'u, inode = 4242)
  let shimOtherText = mapping(renamed, start = 0x7f0000100000'u,
                              stop = 0x7f0000110000'u, inode = 4242)
  let libFoo = mapping("/opt/app/lib/libfoo.so", start = 0x7f0000200000'u,
                       stop = 0x7f0000210000'u, inode = 77)
  let mappings = [libFoo, shimText, shimOtherText]
  let handler = 0x7f0000002345'u
  let exe = "/opt/app/bin/app"

  test "ownImageOf finds the mapping that contains the address":
    let own = ownImageOf(mappings, handler)
    check own.known
    check own.start == shimText.start
    check own.stop == shimText.stop
    check own.inode == 4242
    check not ownImageOf(mappings, 0x10'u).known
    check not ownImageOf(mappings, 0'u).known
    # `stop` is exclusive, as in /proc/self/maps.
    check not ownImageOf([shimText], shimText.stop).known

  test "a renamed shim is not patched, though the name test misses it":
    let own = ownImageOf(mappings, handler)
    check not isMonitorShimMappingPath(renamed)
    check shouldPatchInlineSyscallMapping(shimText, exe, own = noOwn)
    check not shouldPatchInlineSyscallMapping(shimText, exe, own)
    # Every mapping of the same file is the same image.
    check not shouldPatchInlineSyscallMapping(shimOtherText, exe, own)
    # Other libraries are still patched.
    check shouldPatchInlineSyscallMapping(libFoo, exe, own)

  test "the running image is excluded even when it is the executable":
    let own = ownImageOf(mappings, handler)
    check not shouldPatchInlineSyscallMapping(shimText, renamed, own)

  test "a different file with the same inode on another device is patched":
    let own = ownImageOf(mappings, handler)
    let elsewhere = mapping("/mnt/b/libbar.so", start = 0x7f0000300000'u,
                            stop = 0x7f0000310000'u, device = "fd:02",
                            inode = 4242)
    check shouldPatchInlineSyscallMapping(elsewhere, exe, own)

  test "an image without an inode is matched by its range only":
    let anonShim = mapping(renamed, start = 0x7f0000001000'u,
                           stop = 0x7f0000080000'u, inode = 0)
    let other = mapping("/opt/app/lib/libz.so", start = 0x7f0000400000'u,
                        stop = 0x7f0000410000'u, inode = 0)
    let own = ownImageOf([anonShim, other], handler)
    check not shouldPatchInlineSyscallMapping(anonShim, exe, own)
    check shouldPatchInlineSyscallMapping(other, exe, own)

  test "the name test still excludes a canonical shim the address missed":
    let shim = mapping("/opt/repro/lib/librepro_monitor_shim.so",
                       start = 0x7f0000500000'u, stop = 0x7f0000510000'u,
                       inode = 9)
    check not shouldPatchInlineSyscallMapping(shim, exe,
      ownImageOf(mappings, handler))
