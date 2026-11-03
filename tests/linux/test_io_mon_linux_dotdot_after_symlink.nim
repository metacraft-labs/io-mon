## test_io_mon_linux_dotdot_after_symlink — a `..` that follows a symlink is
## recorded as spelled, not folded into the text before it; a LEADING `..` is
## applied to a symlink-free anchor.
##
## # The break
##
## Issue: `reprobuild-pm/issues/2026-10-21-linux-shim-folds-dotdot-after-a-
## symlink-lexically.md`. Spec: `reprobuild-pm/spec/Monitor-Hook-Shim.md`
## § "Metadata, Probe, And Symlink APIs" — "Relative paths are walked as
## spelled: `..` after a link applies to where the link points, not to the
## text before it" and "Never pop a symlink component lexically" — and § CWD
## And Path Context ("CWD tracking is required for relative path
## normalization").
##
## `pathForAt` made a relative path absolute with Nim's `/` (`joinPath`),
## which folds every `..` lexically: `"<root>" / "link/../file"` is
## `"<root>/file"`. The kernel resolves `link/../file` beside the link's
## TARGET, so with `link -> sub/target` the process opened `<root>/sub/file`
## while the shim recorded `<root>/file` — a file it never read — and a
## change to the file it did read could not invalidate the action. The same
## fold happened on a dirfd: its base is the shim's recorded spelling, so a
## directory opened as `link` and then used for `openat(dfd, "../file")`
## named `<root>/file` as well.
##
## # What is asserted
##
## A fixture in `<root>` (`link -> sub/target`; every name the kernel
## resolves exists under `sub/`, and a DECOY with the same name exists at the
## folded location under `<root>`) performs, through the real libc calls:
##
## * `open("link/../f-open")` and `opendir("link/../d-enum")` relative to the
##   cwd. The record keeps the `..` after the link: exactly
##   `<root>/link/../f-open` and `<root>/link/../d-enum`, the spelling the
##   kernel resolved (the realpath companion, not the as-passed record,
##   decides what it names). The macOS shim records the same string.
## * from `<root>/w`, `open("../x-lead")`: a LEADING `..` is still applied to
##   the cwd (getcwd names it without a symlink, so popping is exact):
##   exactly `<root>/x-lead`.
## * a directory fd opened through the link (`open("../link")` from
##   `<root>/w`, recorded `<root>/link`), then `openat(dfd, "../f-fd")` and
##   `fstatat(dfd, "../d-probe")`. The recorded spelling of the fd ends in a
##   symlink, so popping it would be the fold again; the leading `..` must be
##   applied to the directory the fd really is (`/proc/self/fd`):
##   exactly `<root>/sub/f-fd` and `<root>/sub/d-probe`.
## * a directory fd whose recorded spelling keeps a `..` after the link
##   (`open("../link/../d-kept")`, recorded `<root>/link/../d-kept`; the
##   kernel opened `<root>/sub/d-kept`), then `openat(dfd, "e-kept")` (no
##   leading `..`: the recorded spelling is kept as the base, exactly
##   `<root>/link/../d-kept/e-kept`) and `openat(dfd, "../f-kept")` (leading
##   `..` popped off the kernel's name: exactly `<root>/sub/f-kept`).
##
## Every case must be observed (positive control), every record for it must
## be the exact string above, and no record may name a decoy: a decoy is
## precisely what the lexical fold produces.
##
## The root is realpath-resolved so the expected spelling is the one getcwd
## and /proc/self/fd produce.
##
## MOCK POLICY — NO MOCKS. A real C program performs real syscalls under the
## real production shim (built from this checkout by `buildPrivateLinuxShim`)
## launched by the real `io-mon run` CLI, and the real fragment merge produces
## the evidence the assertions read. What is under test is the path the shim
## records for real relative calls through a real symlink; a synthetic record
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

  proc lastComponent(path: string): string =
    ## The final component, ignoring trailing slashes. Not `extractFilename`
    ## of a `parentDir`: both would fold the `..` this test is about.
    var p = path
    while p.len > 1 and p.endsWith("/"):
      p.setLen(p.len - 1)
    let cut = p.rfind('/')
    if cut < 0: p else: p[cut + 1 .. ^1]

  proc recordsNaming(dep: MonitorDepFile; kind: MonitorRecordKind;
                     leaf: string): seq[MonitorRecord] =
    for rec in dep.records:
      if rec.kind == kind and rec.path.lastComponent == leaf:
        result.add rec

suite "Linux shim keeps a `..` that follows a symlink and applies a " &
    "leading `..` to a symlink-free anchor":
  when defined(linux):
    let root = expandFilename(createTempDir("io-mon-dotdot-link-", ""))
    let sub = root / "sub"
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

    # `link` -> `sub/target`, so `link/..` is `sub`. Each name the kernel
    # resolves exists under `sub/`; the same name under `<root>` is the decoy
    # a lexical fold would record.
    createDir(sub / "target")
    createSymlink("sub/target", root / "link")
    createDir(root / "w")
    for name in ["f-open", "f-fd", "f-kept"]:
      writeFile(sub / name, "kernel\n")
      writeFile(root / name, "decoy\n")
    for name in ["d-enum", "d-probe", "d-kept"]:
      createDir(sub / name)
      createDir(root / name)
    writeFile(sub / "d-enum" / "entry.txt", "kernel\n")
    writeFile(root / "d-enum" / "entry.txt", "decoy\n")
    writeFile(sub / "d-kept" / "e-kept", "kernel\n")
    writeFile(root / "d-kept" / "e-kept", "decoy\n")
    writeFile(root / "x-lead", "kernel\n")

    let decoys = @[root / "f-open", root / "d-enum", root / "f-fd",
      root / "d-probe", root / "f-kept", root / "d-kept",
      root / "d-kept" / "e-kept"]

    let ops = @[
      # Relative to the cwd (`<root>`): a `..` after the link.
      "open:link/../f-open",
      "opendir:link/../d-enum",
      # A leading `..` is applied to the cwd.
      "chdir:w",
      "open:../x-lead",
      # A dirfd opened THROUGH the link, then a leading `..` against it.
      "dirfd:../link",
      "openatd:../f-fd",
      "fstatatd:../d-probe",
      # A dirfd whose recorded spelling keeps a `..` after the link.
      "dirfd:../link/../d-kept",
      "openatd:e-kept",
      "openatd:../f-kept"]

    # (kind, leaf, the exact record the shim must produce)
    let expected = @[
      (mrFileOpen, "f-open", root & "/link/../f-open"),
      (mrDirectoryEnumerate, "d-enum", root & "/link/../d-enum"),
      (mrFileOpen, "x-lead", root & "/x-lead"),
      (mrFileOpen, "link", root & "/link"),
      (mrFileOpen, "f-fd", sub & "/f-fd"),
      (mrPathProbe, "d-probe", sub & "/d-probe"),
      (mrFileOpen, "d-kept", root & "/link/../d-kept"),
      (mrFileOpen, "e-kept", root & "/link/../d-kept/e-kept"),
      (mrFileOpen, "f-kept", sub & "/f-kept")]

    proc monitor(tag: string): MonitorDepFile =
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let depfile = root / ("cap-" & tag & ".iomon")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", fixture] &
        ops, env, root)
      checkpoint(tag & " (exit " & $cap.code & "):\n" & cap.output)
      doAssert cap.code == 0, "monitored fixture failed: " & cap.output
      doAssert fileExists(depfile), "no depfile for " & tag
      result = readMonitorDepFile(depfile)

    test "each relative call is recorded as the kernel resolved it":
      let dep = monitor("dotdot")
      for rec in dep.records:
        if rec.path.startsWith(root & "/"):
          checkpoint("  " & $rec.kind & " " & rec.path & " [" & rec.detail &
            "]")
      for (kind, leaf, want) in expected:
        let recs = dep.recordsNaming(kind, leaf)
        checkpoint($kind & " " & leaf & ": " & $recs.len &
          " records, expected " & want)
        # Positive control: the call was observed at all.
        check recs.len > 0
        for rec in recs:
          checkpoint("  " & leaf & " -> " & rec.path)
          check rec.path == want
      # No record may name what the lexical fold produces.
      for rec in dep.records:
        if rec.path in decoys:
          checkpoint("  decoy recorded: " & $rec.kind & " " & rec.path)
        check rec.path notin decoys

    removeDir(root)
  else:
    test "`..` after a symlink is a Linux shim property (no-op here)":
      check true
