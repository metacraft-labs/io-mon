## Every compiler driver a build can reach as a `/usr/bin` `xcode_select` shim
## has an Apple toolchain drop-in.
##
## On macOS each of `/usr/bin/cc`, `c++`, `gcc`, `g++`, `clang` and `clang++`
## is the same SIP-protected `xcode_select` shim, which re-execs the matching
## binary in the active developer directory (`/usr/bin/gcc` runs
## `xcrun gcc`, Apple clang in gcc driver mode). Exec'ing a SIP binary strips
## `DYLD_INSERT_LIBRARIES`, so the compile it starts runs unobserved. io-mon
## covers this by writing a drop-in for each name in `AppleToolchainDropIns`
## into the sandbox-tools directory, and by redirecting a monitored root or
## child that resolves to the shim to that drop-in.
##
## A name missing from the set is the defect recorded in reprobuild-pm
## issues/2026-10-06-c-executable-link-edge-never-caches-and-grows-a-record-per-build.md:
## reprobuild's C conventions run a bare `gcc`; a Nix dev shell's clang
## wrapper provides `cc` and `clang` but not `gcc`, so the monitored root
## `gcc` resolves to `/usr/bin/gcc`. With no drop-in for that name the root
## keeps its SIP path, the capture reports an unknown-scope loss, and the
## edge is never published to the action cache: it relinks on every build.
##
## The names are data, so the set is checked here on every POSIX host. The
## real-compiler half (populating the drop-ins from a developer directory and
## compiling through a bare `gcc` root under the monitor) needs a Mac and is
## tests/macos/test_io_mon_macos_apple_toolchain_dropins.nim.
##
## Mocking: none. The test reads the constant `populateAppleToolchainDropIns`
## iterates.

import foreign_preload_isolation

import std/unittest

import io_mon/fs_snoop

suite "Apple toolchain drop-in names":
  test "every compiler driver spelling a build can exec has a drop-in":
    for name in ["cc", "c++", "gcc", "g++", "clang", "clang++"]:
      checkpoint("compiler driver: " & name)
      check name in AppleToolchainDropIns

  test "the tools a compiler driver forks have drop-ins too":
    # The driver forks the assembler and the linker, and `ar` builds static
    # libraries; each is its own /usr/bin shim with its own SIP strip.
    for name in ["ld", "as", "ar"]:
      checkpoint("toolchain tool: " & name)
      check name in AppleToolchainDropIns
