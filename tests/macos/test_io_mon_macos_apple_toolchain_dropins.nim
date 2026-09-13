## The compiler drop-in points at APPLE'S OWN toolchain, at a path the monitor
## can follow.
##
## ## What was broken
##
## `/usr/bin/cc` is not the compiler. It is a 118 KB `xcode_select` shim
## (signed `com.apple.dt.xcode_select.tool-shim-public`) that re-execs the real
## clang inside the active developer directory. The shim lives under a
## SIP-protected prefix, so exec'ing it strips `DYLD_INSERT_LIBRARIES` — and
## because the strip happens in the shim's own environment, the real compiler
## it then execs does not receive the shim library either. The whole compile is
## invisible, which the depfile records as `exec without post-exec
## process-start` → `mesUnknownScopeLoss` → the consuming action cannot be
## published to the action cache.
##
## Measured on aarch64-darwin, `bash -c '/usr/bin/cc --version'` under the
## monitor: **one** unknown-scope loss. With the drop-in below: **none**. On a
## reprobuild dev-env activation that single loss was the difference between a
## provider compile that publishes and one that recompiles on every new shell —
## 20.5 s of a 26 s `cd`.
##
## ## Why this is a redirect and not a substitution
##
## The real compiler, at `xcrun -f clang`, is outside every SIP prefix and is
## signed `flags=0x0(none)` — no hardened runtime, no library validation — so
## it takes the injection normally. The drop-in is therefore a SYMLINK TO THE
## SAME BINARY the shim would have exec'd: same compiler, same SDK resolution,
## same defaults. Nothing about the build changes, only whether it can be
## observed.
##
## That distinction is the reason this is sound where shipping a different
## compiler would not be. A nixpkgs clang is a different toolchain with
## different default include paths and a different linker; redirecting to it
## would silently change what gets built. The tests below therefore assert the
## symlink's TARGET, not merely its existence.
##
## Mocking: none. Every assertion runs against the host's real developer
## directory, and the suite skips when there is none — a host without Xcode or
## the Command Line Tools has nothing to resolve, and a fabricated toolchain
## would assert nothing about the property under test.

import std/[os, strutils, tempfiles, unittest]

import io_mon/fs_snoop
import stackable_hooks/propagation as ct_propagation

when not defined(macosx):
  echo "apple-toolchain drop-ins are macOS-only; nothing to assert here"
else:
  suite "macOS Apple-toolchain drop-ins":

    let resolvedClang = resolveAppleToolchainTool("clang")
    let haveToolchain = resolvedClang.len > 0

    test "the resolved compiler is real, and outside every SIP prefix":
      if not haveToolchain:
        echo "no active developer directory (xcrun -f clang resolved nothing)"
        skip()
      else:
        check fileExists(resolvedClang)
        # The property the mechanism rests on. If Apple ever moved the
        # toolchain under /usr/bin proper, the drop-in would be pointless and
        # this is where we would find out.
        check not ct_propagation.isSipProtected(resolvedClang)
        # And it is the Apple toolchain, not something that happened to be
        # called clang: xcrun resolves through the ACTIVE developer dir.
        check resolvedClang.contains("Developer")

    test "an unresolvable tool yields an empty string, not a guess":
      # `xcrun -f` fails for a name no toolchain provides. A resolver that
      # guessed a path would create a dangling drop-in, and a dangling drop-in
      # turns a working exec into ENOENT — strictly worse than no drop-in.
      check resolveAppleToolchainTool("definitely-not-a-toolchain-tool") == ""

    test "populate drops in cc, and it points at the same compiler":
      if not haveToolchain:
        skip()
      else:
        let dir = createTempDir("io-mon-toolchain-dropins", "")
        defer: removeDir(dir)
        populateAppleToolchainDropIns(dir)
        let cc = dir / "usr" / "bin" / "cc"
        check symlinkExists(cc)
        # Same binary the shim would have exec'd — the load-bearing assertion.
        check expandSymlink(cc) == resolveAppleToolchainTool("cc")
        # And the rewrite the spawn hook performs resolves to it.
        check ct_propagation.rewriteSipPath("/usr/bin/cc", dir) == cc
        check fileExists(ct_propagation.rewriteSipPath("/usr/bin/cc", dir))

    test "the whole toolchain set lands, not just the compiler":
      if not haveToolchain:
        skip()
      else:
        let dir = createTempDir("io-mon-toolchain-set", "")
        defer: removeDir(dir)
        populateAppleToolchainDropIns(dir)
        # A monitored compile execs more than the compiler: the driver forks
        # the assembler and the linker, and each of those is its own
        # /usr/bin shim with its own SIP strip.
        for name in ["cc", "clang", "c++", "cpp", "ld", "as", "ar"]:
          check symlinkExists(dir / "usr" / "bin" / name)

    test "populate is idempotent and never clobbers an existing entry":
      if not haveToolchain:
        skip()
      else:
        let dir = createTempDir("io-mon-toolchain-idem", "")
        defer: removeDir(dir)
        # A pre-seeded entry stands for a distribution-grade bundle the
        # operator pointed CT_SANDBOX_TOOLS_DIR at: populate must extend it,
        # never rewrite it.
        createDir(dir / "usr" / "bin")
        let preseeded = dir / "usr" / "bin" / "cc"
        writeFile(preseeded, "#!/bin/sh\nexit 0\n")
        populateAppleToolchainDropIns(dir)
        populateAppleToolchainDropIns(dir)
        check not symlinkExists(preseeded)
        check readFile(preseeded).contains("exit 0")
        # The entries it did create are still there after a second pass.
        check symlinkExists(dir / "usr" / "bin" / "clang")

    test "a host with no developer directory gets no drop-ins, and no error":
      # DEVELOPER_DIR pointing nowhere is how a machine without Xcode behaves.
      # The populate must degrade to "no entry" — the same fail-safe every
      # other unresolvable tool takes — rather than raising into the monitor's
      # startup path.
      let previous = getEnv("DEVELOPER_DIR")
      putEnv("DEVELOPER_DIR", "/nonexistent-developer-dir")
      defer:
        if previous.len > 0: putEnv("DEVELOPER_DIR", previous)
        else: delEnv("DEVELOPER_DIR")
      let dir = createTempDir("io-mon-toolchain-absent", "")
      defer: removeDir(dir)
      populateAppleToolchainDropIns(dir)
      check not symlinkExists(dir / "usr" / "bin" / "cc")
      check not fileExists(dir / "usr" / "bin" / "cc")
