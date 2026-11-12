## rustc compiles the two crates of the rustc 1.94.0 SIGILL issue under the shim.
##
## WHY. Under the Linux shim, with a monitor session
## set, the upstream Rust 1.94.0 x86-64 tarball's `rustc` died with SIGILL on
## any crate containing a `macro_rules!`, and compiled a trivial crate fine.
## The tarball's `librustc_driver` is BOLT-optimised: its executable segment
## carries `.rodata`, and the inline raw-syscall scanner's whole-mapping sweep
## INT3-patched a jump-table entry there (`fa 0f 05 fe`). The scanner now
## decodes an image's `SHF_EXECINSTR` sections only
## (test_io_mon_linux_inline_scan_code_sections_only.nim pins the mechanism on
## a synthetic image); this test is the issue's own gate: the crate pair,
## compiled by whatever `rustc` the host supplies, under the shim.
##
## WHICH RUSTC. `IO_MON_TEST_RUSTC` when set, else `findExe("rustc")`. On the
## upstream tarball realisation (reprobuild's `rustc.nim` pins 1.94.0,
## `--tool-provisioning=tarball`) the library lives outside the mapping
## policy's system-runtime exclusions and this test exercises the fix. On
## nixpkgs' rustc the library is under `/nix/store`, which the policy never
## scans, so the run is a control that the shim and rustc still cooperate.
## The override exists because the decisive toolchain is not the one on a dev
## shell's PATH: point it at the realised tarball's `rustc`, or at a wrapper
## script that runs it (on NixOS the tarball's binaries need the glibc loader
## invoked explicitly, `ld-linux-x86-64.so.2 --library-path ... rustc`).
## Which one ran, and whether it is decisive or a control, is printed on
## stderr so a passing run says what it proved.
##
## Mocks: none. Real rustc, real shim, real crates.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim
import unmonitored_env

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  macroCrate = "#[macro_export] macro_rules! m { () => {} }\n"
  trivialCrate = "fn main(){}\n"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
         workingDir = ""): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env, workingDir = workingDir,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

type Fixture = object
  work, snoopBin, rustc: string
  env: StringTableRef

proc hostRustc(): string =
  ## The rustc this run drives: `IO_MON_TEST_RUSTC` (a binary or a wrapper
  ## script; see the header) or the first `rustc` on PATH. "" when neither.
  let override = getEnv("IO_MON_TEST_RUSTC")
  if override.len > 0: override else: findExe("rustc")

proc setUpFixture(): Fixture =
  result.rustc = hostRustc()
  result.work = expandFilename(getTempDir()) /
    ("io-mon-rustc-crates-" & $getCurrentProcessId())
  removeDir(result.work)
  createDir(result.work)
  writeFile(result.work / "mac.rs", macroCrate)
  writeFile(result.work / "x.rs", trivialCrate)
  let shimLib = buildPrivateLinuxShim(repoRoot)
  result.snoopBin = result.work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & result.snoopBin, snoopSrc])
  checkpoint(cli.output)
  doAssert cli.code == 0, "io-mon CLI build failed"
  result.env = unmonitoredEnv()
  result.env["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc rustcArgs(f: Fixture; crate, output: string): seq[string] =
  @[f.rustc, "--crate-type", "lib", "--emit=metadata", "-o", f.work / output,
    f.work / crate]

proc describeRustc(f: Fixture) =
  ## Say on stderr which rustc ran and whether its driver library is one the
  ## mapping policy scans (outside /nix/store, /lib, /usr/lib). Printed, not
  ## checkpointed: a checkpoint is shown only when a check fails, and the
  ## point of this line is to qualify a PASS. For an `IO_MON_TEST_RUSTC`
  ## wrapper script the library's location is the script author's to know, so
  ## the line says only that the override was used.
  let resolved =
    try: expandSymlink(f.rustc)
    except OSError: f.rustc  # a regular file, not a symlink
  let libDir = resolved.parentDir.parentDir / "lib"
  let scanned = not (resolved.startsWith("/nix/store/") or
    libDir.startsWith("/nix/store/") or libDir.startsWith("/usr/lib") or
    libDir.startsWith("/lib"))
  let verdict =
    if getEnv("IO_MON_TEST_RUSTC").len > 0:
      " (IO_MON_TEST_RUSTC override; decisive when it runs the upstream " &
        "tarball toolchain)"
    elif scanned:
      " (librustc_driver is scanned by the inline-syscall patcher: decisive)"
    else:
      " (librustc_driver is under a system-runtime path the mapping policy " &
        "excludes: control run)"
  stderr.writeLine("rustc crate pair: rustc=" & f.rustc & " resolved=" &
    resolved & verdict)

suite "io-mon Linux: rustc crate pair under the shim":
  when defined(linux) and defined(amd64):
    let rustcPath = hostRustc()
    test "the host supplies a rustc":
      require rustcPath.len > 0
    let f = setUpFixture()
    describeRustc(f)

    test "bare control: both crates compile without the shim":
      for (crate, output) in [("mac.rs", "mac-bare.rmeta"), ("x.rs", "x-bare.rmeta")]:
        let r = run(f.rustc, f.rustcArgs(crate, output)[1 .. ^1], unmonitoredEnv(),
          f.work)
        checkpoint(crate & ": " & r.output)
        check r.code == 0
        check fileExists(f.work / output)

    test "macro_rules! crate compiles under the shim":
      let depfile = f.work / "mac.iomon"
      let r = run(f.snoopBin, @["run", "--depfile", depfile, "--"] &
        f.rustcArgs("mac.rs", "mac.rmeta"), f.env, f.work)
      checkpoint(r.output)
      check r.code == 0
      check "SIGILL" notin r.output
      check fileExists(f.work / "mac.rmeta")
      let dep = readMonitorDepFile(depfile)
      checkpoint("completeness=" & $dep.completeness)

    test "trivial crate compiles under the shim":
      let depfile = f.work / "x.iomon"
      let r = run(f.snoopBin, @["run", "--depfile", depfile, "--"] &
        f.rustcArgs("x.rs", "x.rmeta"), f.env, f.work)
      checkpoint(r.output)
      check r.code == 0
      check "SIGILL" notin r.output
      check fileExists(f.work / "x.rmeta")
  else:
    test "rustc crate pair under the shim (x86_64 INT3 backend only)":
      skip()
