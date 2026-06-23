## test_io_mon_shim_builds_standalone — the RELOCATED interpose shim builds as a
## drop-in shared library on nim-stackable-hooks, with NO dependency on
## reprobuild, and exports the byte-identical interpose ABI.
##
## M6b relocated reprobuild's `repro_monitor_shim` + `repro_monitor_hooks`
## interpose closure into io-mon (`io_mon/shim/*`, `io_mon/hooks/*`), completing
## the io-mon library (M5 had relocated only the depfile half). The shim is an
## `--app:lib` entry point with a `{.emit.}` constructor and (on macOS) a
## `__DATA,__interpose` section, so it cannot be `import`ed into a unittest
## runner; instead this test drives `nim c --app:lib` on the platform shim
## module and asserts:
##
##   1. it COMPILES with ONLY `--path:src` (io-mon) + `--path:../nim-stackable-hooks/src`
##      and NO reprobuild path — a lingering `repro_*` import would fail to
##      resolve (the standalone contract: stackable_hooks yes, reprobuild no);
##   2. the produced shared library exports the historical interpose-control
##      ABI (`repro_monitor_shim_init` / `_version`), kept byte-identical so the
##      M7 swap into reprobuild is drop-in;
##   3. the shared-library FILE NAME is `librepro_monitor_shim.<ext>` — the
##      drop-in name every consumer (incl. io-mon's own `fs_snoop`) locates.
##
## A LIVE interpose run (the shim actually injecting into a real recorded
## process via DYLD_INSERT_LIBRARIES / LD_PRELOAD) is NOT exercised here — that
## needs the platform injection path + entitlements and is gated, mirroring how
## the campaign gates platform-specific runs. This test proves the shim BUILDS
## and exports the right ABI, which is the strongest standalone-relocation proof
## runnable on a build host.

import std/[os, osproc, strutils, tempfiles, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"

proc platformShimModule(): string =
  ## The `--app:lib` entry point for the current platform's interpose shim.
  when defined(macosx):
    repoRoot / "src" / "io_mon" / "shim" / "macos_interpose.nim"
  elif defined(linux):
    repoRoot / "src" / "io_mon" / "shim" / "linux_preload.nim"
  elif defined(windows):
    repoRoot / "src" / "io_mon" / "shim" / "windows_interpose.nim"
  else:
    ""

proc sharedLibExt(): string =
  when defined(macosx): ".dylib"
  elif defined(windows): ".dll"
  else: ".so"

suite "io-mon shim standalone relocation":

  test "nim-stackable-hooks sibling checkout is present":
    # The shim builds ON nim-stackable-hooks. Without it the relocation can't be
    # validated, so make the prerequisite explicit rather than silently skipping.
    check dirExists(hooksSrc)

  test "the relocated shim builds as a drop-in shared library, no reprobuild path":
    let shimModule = platformShimModule()
    check shimModule.len > 0
    check fileExists(shimModule)

    let outName = "librepro_monitor_shim" & sharedLibExt()
    let outDir = createTempDir("io-mon-shim-build", "")
    defer: removeDir(outDir)
    let outPath = outDir / outName
    let nimcache = outDir / "nimcache"

    var args = @[
      "c",
      "--app:lib",
      "--threads:on",
      "--hints:off",
      "--path:" & (repoRoot / "src"),
      "--path:" & hooksSrc,
      "--nimcache:" & nimcache,
      "--out:" & outPath,
    ]
    when defined(macosx):
      if hostCPU == "arm64":
        # arm64e is required so the dylib loads into SIP'd / hardened processes
        # — preserved from the relocated build recipe.
        args.add(["--passC:-arch arm64", "--passC:-arch arm64e",
                  "--passL:-arch arm64", "--passL:-arch arm64e"])
    args.add(shimModule)

    # Deliberately do NOT put any reprobuild path on the command line: the only
    # non-stdlib path is io-mon's own src + nim-stackable-hooks. If the shim
    # still pulled a `repro_*` module, the compile would fail here.
    let (output, exitCode) = execCmdEx("nim " & quoteShellCommand(args))
    checkpoint("nim compile output:\n" & output)
    check exitCode == 0
    check fileExists(outPath)

    when defined(macosx) or defined(linux):
      # The interpose-control ABI must be exported under its historical names so
      # the M7 swap into reprobuild is drop-in.
      when defined(macosx):
        let (syms, symRc) = execCmdEx("nm -gU " & quoteShell(outPath))
      else:
        let (syms, symRc) = execCmdEx("nm -D " & quoteShell(outPath))
      check symRc == 0
      check syms.contains("repro_monitor_shim_init")
      check syms.contains("repro_monitor_shim_version")
