## The Linux shim and the `io-mon` CLI type-check for every Linux CPU the
## shim supports, whatever CPU the test host has.
##
## WHY. Much of the Linux shim is x86-64 only: the inline raw-`syscall` scan,
## its `int3` patching and the inline site tables are declared under
## `when defined(amd64)`. Nim does not type-check the branch of a `when` it
## does not take, so a use of an x86-64-only symbol outside its guard compiles
## on every x86-64 host and fails only where the shim is built for another
## CPU. CI builds and tests the shim on x86-64 Linux only, so that is where a
## user meets it first. It happened: the inline site table global
## `siteTableView: SiteTableView` sat outside the guard, and the first build on
## a Linux AArch64 host stopped with "undeclared identifier: 'SiteTableView'".
##
## WHAT THIS TEST GRADES. `nim check --os:linux --cpu:<cpu>` of the shim's
## project file (`src/io_mon/shim/linux_preload.nim`, with the defines
## `scripts/build_shim.sh` passes) and of the CLI (`cmd/io_mon_snoop.nim`,
## which imports the host side, `fs_snoop`) succeeds for x86-64, AArch64 and
## 32-bit ARM, the Linux targets the shim supports. `nim check` runs the whole
## front end for the target CPU, including every `when defined(<cpu>)`, and
## generates no C, so it needs no cross compiler and runs on any host. It
## does not prove the C translation units compile for the target, nor
## anything about run-time behaviour on it.
##
## Falsifying mutation: moving the `siteTableView` declaration in
## `src/io_mon/hooks/linux_preload_runtime.nim` out of its
## `when defined(linux) and defined(amd64)` block fails the arm64 and arm
## cases with the error above.
##
## No mocks: the real compiler over the real sources.

import foreign_preload_isolation

import std/[os, osproc, strutils, unittest]

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc siblingSrc(envVar, repo: string): string =
  ## The source root of a sibling library, chosen as `config.nims` and
  ## `scripts/build_shim.sh` choose it: the environment override, else the
  ## sibling checkout next to this one.
  result = getEnv(envVar)
  if result.len == 0:
    result = repoRoot.parentDir() / repo / "src"

proc checkFor(project, cpu: string; extra: openArray[string]):
    tuple[output: string; exitCode: int] =
  let nim = findExe("nim")
  doAssert nim.len > 0, "nim is not on PATH"
  var args = @[nim, "check", "--hints:off", "--os:linux", "--cpu:" & cpu,
    "--threads:on",
    "--path:" & (repoRoot / "src"),
    "--path:" & siblingSrc("STACKABLE_HOOKS_SRC", "nim-stackable-hooks"),
    "--path:" & siblingSrc("SHM_QUEUE_SRC", "nim-shm-queue"),
    "--path:" & siblingSrc("SHM_GSET_SRC", "nim-shm-gset"),
    "--path:" & siblingSrc("CLI_SPEC_SRC", "nim-cli-spec")]
  for a in extra: args.add a
  args.add repoRoot / project
  execCmdEx(quoteShellCommand(args), workingDir = repoRoot)

const linuxShimCpus = ["amd64", "arm64", "arm"]
  ## The Linux targets the shim supports (docs/contributors/architecture.md:
  ## x86_64, AArch64, armhf).

suite "the Linux shim type-checks for every supported CPU":
  for cpu in linuxShimCpus:
    test "linux_preload.nim for " & cpu:
      # `-d:useMalloc` and `--app:lib` as `scripts/build_shim.sh` passes them:
      # the shim's entry module refuses to compile as a library without the
      # define.
      let (output, code) = checkFor("src/io_mon/shim/linux_preload.nim", cpu,
        ["-d:useMalloc", "--app:lib"])
      checkpoint(output)
      check code == 0
      check "Error:" notin output

    test "io_mon_snoop.nim (the host side) for " & cpu:
      let (output, code) = checkFor("cmd/io_mon_snoop.nim", cpu, [])
      checkpoint(output)
      check code == 0
      check "Error:" notin output
