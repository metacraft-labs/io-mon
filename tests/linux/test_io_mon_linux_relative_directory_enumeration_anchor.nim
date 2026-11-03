## test_io_mon_linux_relative_directory_enumeration_anchor — a directory
## enumeration is recorded anchored on the cwd (or the fd's directory) the
## process had AT THE TIME OF THE CALL.
##
## # The break
##
## Issue: `reprobuild-pm/issues/2026-10-20-linux-shim-anchors-relative-
## directory-enumerations-on-the-action-cwd.md`. Spec:
## `reprobuild-pm/spec/Monitor-Hook-Shim.md` § CWD And Path Context — "CWD
## tracking is required for relative path normalization."
##
## The Linux shim anchors a relative OPEN on the live cwd (`pathForAt`), but
## `repro_hook_opendir` stored the caller's path string verbatim and
## `repro_hook_readdir` emitted it as the enumerated directory. After
## `chdir("repo"); opendir(".git/objects/pack")` — what `git -C repo` does —
## the evidence named `.git/objects/pack`, which a consumer can only resolve
## against the action's cwd: Reprobuild keyed a monitored `git -C repo show`
## on the phantom enumerations `<action-cwd>/.git/objects/pack` and
## `<action-cwd>/.git/refs/`. Its regression case
## `tests/integration/t_git_object_store_lookups_are_not_cache_inputs.nim`
## ("`git -C` paths are not re-anchored on the action's cwd") failed with 8
## phantoms. `fdopendir` had the neighbouring gap: it took the directory from
## the shim's fd table only, so a descriptor the shim never saw opened (a
## `dup`, an inherited fd) gave every later `readdir` an EMPTY path.
##
## # What is asserted
##
## A fixture starts in `old/`, enumerates one directory there, then chdir()s
## into `new/` and enumerates directories by relative path: through
## `opendir` (a plain name, a name with a trailing slash as git spells
## `.git/refs/`, and a `..`-prefixed name that leaves `new/`), through
## `fdopendir` of a relatively opened directory fd, and through `fdopendir`
## of a `dup` of one (a descriptor no open returned). Every
## directory-enumerate record in the capture must be non-empty and ABSOLUTE,
## and the record for each directory must name it under the directory the
## call resolved against: `old/` for the enumeration made before the chdir
## (anchoring happens at call time, not at the end), `new/` after it, the
## sibling `dir/` for the `..` path (the `..` applied, not left in the
## path). Every directory must be enumerated at all, so a shim that records
## nothing cannot pass. No record made after the chdir may name `old/`: the
## names exist only under `new/` and `dir/`, so a record under `old/` is
## exactly the phantom the issue reports.
##
## The root is realpath-resolved so the expected spelling is the one getcwd
## and /proc/self/fd produce.
##
## MOCK POLICY — NO MOCKS. A real C program performs real syscalls under the
## real production shim (built from this checkout by `buildPrivateLinuxShim`)
## launched by the real `io-mon run` CLI, and the real fragment merge produces
## the evidence the assertions read. What is under test is what the shim
## records for real relative-path directory enumerations; a synthetic record
## set would assert only what its author believed the shim does.

import std/[os, strutils, unittest]
import io_mon

when defined(linux):
  import std/[osproc, streams, strtabs, tempfiles]
  import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(linux):
  const
    hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
    snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
           workingDir = ""): tuple[output: string; code: int] =
    let p = startProcess(cmd, workingDir = workingDir, args = args, env = env,
      options = {poStdErrToStdOut, poUsePath})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    (output, code)

  proc stripTrailingSlash(path: string): string =
    result = path
    while result.len > 1 and result.endsWith("/"):
      result.setLen(result.len - 1)

  proc enumerationsNaming(dep: MonitorDepFile; leaf: string):
      seq[MonitorRecord] =
    ## Every directory-enumerate record whose last component is `leaf`,
    ## ignoring a trailing slash (git opens `.git/refs/`).
    for rec in dep.records:
      if rec.kind != mrDirectoryEnumerate:
        continue
      let p = stripTrailingSlash(rec.path)
      if p == leaf or p.endsWith("/" & leaf):
        result.add rec

suite "Linux shim anchors relative directory enumerations on the cwd at " &
    "call time":
  when defined(linux):
    let root = expandFilename(createTempDir("io-mon-relenum-", ""))
    let oldDir = root / "old"
    let newDir = root / "new"
    let dirDir = root / "dir"
    let snoopBin = root / "io-mon"
    block:
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      doAssert cli.code == 0, cli.output
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let fixture = root / "relative_path_ops"
    block:
      let cc = run(getEnv("CC", "cc"), @[
        repoRoot / "tests" / "helpers" / "relative_path_ops.c",
        "-o", fixture])
      doAssert cc.code == 0, "cc failed: " & cc.output

    # Each directory exists ONLY where the call should resolve it, and holds
    # one entry so readdir returns at least one record-producing result.
    let layout = @[
      (oldDir, "e-before"),
      (newDir, "e-enum"), (newDir, "e-slash"),
      (newDir, "e-fd"), (newDir, "e-fddup"),
      (dirDir, "e-dotdot")]
    for (parent, leaf) in layout:
      createDir(parent / leaf)
      writeFile(parent / leaf / "entry.txt", "present\n")

    let ops = @[
      # Before the chdir: resolved against `old/`.
      "opendir:e-before",
      "chdir:" & newDir,
      "opendir:e-enum",
      # git's spelling of a directory it enumerates (`.git/refs/`).
      "opendir:e-slash/",
      # A leading ".." is applied to the cwd (`git -C ../repo`).
      "opendir:../dir/e-dotdot",
      # A DIR* over a directory fd opened by a relative path …
      "fdopendir:e-fd",
      # … and over a dup of one, which no open call returned.
      "fdopendirdup:e-fddup"]

    proc monitor(tag: string): MonitorDepFile =
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let depfile = root / ("cap-" & tag & ".iomon")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", fixture] &
        ops, env, oldDir)
      checkpoint(tag & " (exit " & $cap.code & "):\n" & cap.output)
      doAssert cap.code == 0, "monitored fixture failed: " & cap.output
      doAssert fileExists(depfile), "no depfile for " & tag
      result = readMonitorDepFile(depfile)

    test "every directory enumeration is recorded absolute, in the " &
        "directory the call resolved against":
      let dep = monitor("anchor")
      var enumerations = 0
      for rec in dep.records:
        if rec.kind == mrDirectoryEnumerate:
          inc enumerations
          checkpoint("  enumerate " & rec.path & " [" & rec.detail & "]")
          check rec.path.len > 0
          check rec.path.isAbsolute
      check enumerations > 0
      for (expectedDir, leaf) in layout:
        let recs = dep.enumerationsNaming(leaf)
        checkpoint(leaf & ": " & $recs.len & " enumerate records")
        # Positive control: the enumeration was observed at all.
        check recs.len > 0
        for rec in recs:
          checkpoint("  " & leaf & " -> " & rec.path)
          check rec.path.isAbsolute
          # parentDir folds "..", so check for it separately: no path here
          # crosses a symlink, so every ".." must have been applied.
          check "/../" notin rec.path
          check stripTrailingSlash(rec.path).parentDir == expectedDir
      # Nothing enumerated after the chdir may be attributed to the old cwd.
      for rec in dep.records:
        if rec.path.startsWith(oldDir & "/"):
          checkpoint("  under old/: " & $rec.kind & " " & rec.path)
          check stripTrailingSlash(rec.path) == oldDir / "e-before" or
            rec.path.startsWith(oldDir / "e-before" & "/")

    removeDir(root)
  else:
    test "relative directory-enumeration anchoring is a Linux shim " &
        "property (no-op here)":
      check true
