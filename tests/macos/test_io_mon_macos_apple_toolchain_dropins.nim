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
## it takes the injection normally. The drop-in therefore execs THE SAME BINARY
## the shim would have exec'd: same compiler, same SDK resolution, same
## defaults. Nothing about the build changes, only whether it can be observed.
##
## ## Why the drop-in is a script and not a symlink
##
## "Same SDK resolution" is not free. The shim sets `SDKROOT` before it execs
## the toolchain binary, and the toolchain binary has no SDK of its own. A
## symlink straight to it, run with `SDKROOT` unset, fails on the first libc
## header. Measured on aarch64-darwin with Xcode.app selected (Xcode 26.6,
## macOS 26.5), `inc.c` = `#include <stdlib.h>`:
##
##     env -i PATH=/usr/bin:/bin /usr/bin/clang -fsyntax-only inc.c     -> ok
##     env -i PATH=/usr/bin:/bin $(xcrun -f clang) -fsyntax-only inc.c  -> 'stdlib.h' file not found
##
## An action environment that scrubs `SDKROOT` runs every monitored compile
## the second way. The drop-in is therefore a small script that applies the
## shim's environment and then execs the binary (`renderAppleToolchainDropIn`;
## its shell semantics are checked on every POSIX host by
## tests/posix/test_io_mon_apple_toolchain_dropin_script.nim). The tests below
## compile through it with `SDKROOT` unset, directly and under the monitor.
##
## That distinction is the reason this is sound where shipping a different
## compiler would not be. A nixpkgs clang is a different toolchain with
## different default include paths and a different linker; redirecting to it
## would silently change what gets built. The tests below therefore assert the
## drop-in's TARGET, not merely its existence.
##
## The compile tests run with `DEVELOPER_DIR` and `SDKROOT` removed from the
## test's own environment, so the drop-ins are populated from the host's
## `xcode-select` choice (Xcode.app or the Command Line Tools), as for a
## monitor started from an operator's shell. Inside a Nix dev shell those
## variables point at Nix's SDK, and `xcrun -f clang` then answers with Nix's
## compiler wrapper, which carries its own sysroot and would make the SDK
## assertions vacuous.
##
## Mocking: none. Every assertion runs against the host's real developer
## directory, and the suite skips when there is none — a host without Xcode or
## the Command Line Tools has nothing to resolve, and a fabricated toolchain
## would assert nothing about the property under test.

import std/[os, osproc, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop
import stackable_hooks/propagation as ct_propagation

when defined(macosx):
  import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when not defined(macosx):
  echo "apple-toolchain drop-ins are macOS-only; nothing to assert here"
else:
  suite "macOS Apple-toolchain drop-ins":

    let resolvedClang = resolveAppleToolchainTool("clang")
    let haveToolchain = resolvedClang.len > 0

    proc appleDefaultSdk(): string =
      ## What the shim selects with no SDKROOT, for the current environment:
      ## computed here independently of io-mon's own resolver.
      let probe = execCmdEx("/usr/bin/env -u SDKROOT /usr/bin/xcrun " &
        "--show-sdk-path 2>/dev/null")
      if probe.exitCode == 0 and dirExists(probe.output.strip()):
        probe.output.strip()
      else:
        ""

    template withSystemSelection(body: untyped) =
      ## Run `body` with the host's `xcode-select` choice in force: no
      ## DEVELOPER_DIR and no SDKROOT in this process's environment.
      let savedDeveloperDir = getEnv("DEVELOPER_DIR")
      let savedSdkRoot = getEnv("SDKROOT")
      delEnv("DEVELOPER_DIR")
      delEnv("SDKROOT")
      try:
        body
      finally:
        if savedDeveloperDir.len > 0: putEnv("DEVELOPER_DIR", savedDeveloperDir)
        if savedSdkRoot.len > 0: putEnv("SDKROOT", savedSdkRoot)

    proc dropInRuns(dropIn, tool: string): bool =
      ## A drop-in runs `tool`: a symlink to it when there is no SDK to
      ## carry, otherwise a script that ends by exec'ing it.
      if appleDefaultSdk().len == 0:
        return symlinkExists(dropIn) and expandSymlink(dropIn) == tool
      fileExists(dropIn) and not symlinkExists(dropIn) and
        readFile(dropIn).endsWith("exec " & quoteShell(tool) & " \"$@\"\n")

    proc isolatedRun(command: string): tuple[output: string; exitCode: int] =
      ## `command` with an environment that names no SDK, as an action
      ## environment that scrubs SDKROOT and DEVELOPER_DIR runs it.
      execCmdEx("/usr/bin/env -i PATH=/usr/bin:/bin HOME=" &
        quoteShell(getTempDir()) & " " & command)

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
        # Nix's xcrun resolves its pinned Clang under /nix/store. Verify the
        # compiler's identity without requiring an Apple installation path.
        let version = execCmdEx(quoteShell(resolvedClang) & " --version")
        check version.exitCode == 0
        check "clang" in version.output.toLowerAscii

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
        # Same binary the shim would have exec'd — the load-bearing assertion.
        check dropInRuns(cc, resolveAppleToolchainTool("cc"))
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
          check dropInRuns(dir / "usr" / "bin" / name,
            resolveAppleToolchainTool(name))

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
        check dropInRuns(dir / "usr" / "bin" / "clang", resolvedClang)

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

    test "a compile through the drop-in finds libc headers with SDKROOT unset":
      # The defect this guards: with Xcode.app selected, a drop-in that was a
      # bare symlink to the toolchain clang compiled with no SDK at all.
      withSystemSelection:
        let resolvedClang = resolveAppleToolchainTool("clang")
        let defaultSdk = appleDefaultSdk()
        if resolvedClang.len == 0 or defaultSdk.len == 0:
          echo "no developer directory or no SDK in it; nothing to compile with"
          skip()
        else:
          let dir = createTempDir("io-mon-toolchain-sdk", "")
          defer: removeDir(dir)
          populateAppleToolchainDropIns(dir)
          let source = dir / "inc.c"
          writeFile(source, "#include <stdlib.h>\n#include <string.h>\n" &
            "int main(void) { return (int)strlen(getenv(\"HOME\")) * 0; }\n")
          let clang = dir / "usr" / "bin" / "clang"
          # Control, so this cannot pass vacuously: the toolchain binary alone,
          # with the same environment. On a host whose toolchain carries a
          # default sysroot it succeeds and proves nothing; say so.
          let bare = isolatedRun(quoteShell(resolvedClang) & " -fsyntax-only " &
            quoteShell(source))
          if bare.exitCode == 0:
            echo "this toolchain finds its SDK unaided; the control is vacuous here"
          else:
            check "file not found" in bare.output
          let through = isolatedRun(quoteShell(clang) & " -fsyntax-only " &
            quoteShell(source))
          checkpoint(through.output)
          check through.exitCode == 0
          # The SDK it used is the shim's default, passed as the sysroot.
          let driver = isolatedRun(quoteShell(clang) & " -### -c " &
            quoteShell(source))
          check ("\"-isysroot\" \"" & defaultSdk & "\"") in driver.output
          # And an SDKROOT the environment names wins, as it does for the shim.
          let named = execCmdEx("/usr/bin/env -i PATH=/usr/bin:/bin SDKROOT=" &
            quoteShell(dir) & " " & quoteShell(clang) & " -### -c " &
            quoteShell(source))
          check ("\"-isysroot\" \"" & dir & "\"") in named.output

    proc nonSipShell(): string =
      ## An injectable shell to root the monitored tree: a SIP root would
      ## itself strip the injection before it ever reached /usr/bin/clang.
      for name in ["sh", "bash"]:
        for entry in getEnv("PATH").split(PathSep):
          let candidate = entry / name
          if entry.len > 0 and ct_propagation.isValidSipReplacement(candidate):
            return expandFilename(candidate)
      ""

    test "a monitored compile of /usr/bin/clang with SDKROOT unset succeeds and records the SDK":
      # End to end: the SIP path a build reaches through an inherited PATH,
      # rewritten by the spawn hook to the drop-in the monitor populated.
      withSystemSelection:
        let shell = nonSipShell()
        let defaultSdk = appleDefaultSdk()
        if resolveAppleToolchainTool("clang").len == 0 or defaultSdk.len == 0:
          skip()
        elif shell.len == 0:
          echo "no non-SIP shell on PATH to root the monitored tree"
          skip()
        else:
          let work = createTempDir("io-mon-toolchain-monitored", "")
          defer: removeDir(work)
          let source = work / "inc.c"
          writeFile(source, "#include <stdlib.h>\nint f(void) { return abs(-1); }\n")
          let objectFile = work / "inc.o"
          let depfile = work / "capture.iomon"
          let shim = buildPrivateMacosShim(repoRoot)
          let oldShim = getEnv("REPRO_MONITOR_SHIM_LIB")
          let oldSandbox = getEnv("CT_SANDBOX_TOOLS_DIR")
          defer:
            if oldShim.len > 0: putEnv("REPRO_MONITOR_SHIM_LIB", oldShim)
            else: delEnv("REPRO_MONITOR_SHIM_LIB")
            if oldSandbox.len > 0: putEnv("CT_SANDBOX_TOOLS_DIR", oldSandbox)
            else: delEnv("CT_SANDBOX_TOOLS_DIR")
          putEnv("REPRO_MONITOR_SHIM_LIB", shim)
          # A sandbox populated by this run, not an operator bundle.
          delEnv("CT_SANDBOX_TOOLS_DIR")
          let captured = runMonitored(FsSnoopRequest(
            command: @[shell, "-c", "/usr/bin/clang -c " & quoteShell(source) &
              " -o " & quoteShell(objectFile)],
            cwd: work, depFilePath: depfile, streamMode: fsoNone,
            isolateEnv: true,
            env: @[("PATH", "/usr/bin:/bin"), ("HOME", work)]))
          check captured.exitCode == 0
          check fileExists(objectFile)
          let evidence = readMonitorDepFile(depfile)
          var sdkHeaderRead = false
          var sourceRead = false
          let sourceSpellings = [source, expandFilename(source)]
          for record in evidence.records:
            if record.kind == mrEventLoss: checkpoint(record.detail)
            if record.kind in {mrFileOpen, mrFileRead}:
              if record.path.startsWith(defaultSdk) and
                  record.path.endsWith("/stdlib.h"):
                sdkHeaderRead = true
              if record.path in sourceSpellings:
                sourceRead = true
          # The compiler ran observed, and the SDK it compiled against is in the
          # evidence like any other input.
          check sourceRead
          check sdkHeaderRead
