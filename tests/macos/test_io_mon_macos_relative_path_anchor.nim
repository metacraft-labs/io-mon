## test_io_mon_macos_relative_path_anchor — a relative path is recorded
## anchored on the cwd (or dirfd) the process had AT THE TIME OF THE CALL.
##
## # The break
##
## Issue: `reprobuild-pm/issues/2026-10-18-macos-shim-records-relative-paths-
## the-engine-anchors-on-the-action-cwd.md`. Spec:
## `reprobuild-pm/spec/Monitor-Hook-Shim.md` § CWD And Path Context — "CWD
## tracking is required for relative path normalization."
##
## The macOS shim stored the caller's path string verbatim (`record.path =
## $path` in recordOpen, recordPathProbe and the other recorders), so after
## `chdir("repo"); open(".git/HEAD")` the evidence named `.git/HEAD`. Only the
## process knew which directory that was relative to, and only at that
## moment. A consumer has nothing better than the action's cwd to resolve it
## against, so Reprobuild keyed a monitored `git -C repo cat-file` on phantom
## inputs `<action-cwd>/.git/HEAD`, `<action-cwd>/.git/objects/...`,
## `<action-cwd>/.mailmap` next to the real `repo/...` paths. The Linux shim
## never had this: `pathForAt` joins a relative path onto the live cwd (or the
## dirfd's directory) when the call is made.
##
## # What is asserted
##
## A fixture starts in `old/`, probes one path there, then chdir()s into
## `new/` and opens / creates / stats / lstats / accesses / fstatats /
## opendirs / renames relative paths — each both for a file that exists and
## one that does not — and finally opens and fstatats paths relative to a
## real directory fd for `dir/`. It also launches programs by relative name —
## posix_spawn of a bare `x-spawn`, execve of `./x-exec` and of a bare
## `x-exec2` (neither call searches PATH, so a bare name is cwd-relative) —
## and connects to an AF_UNIX socket by a relative sun_path. Every record that
## names one of those leaves
## must be ABSOLUTE and sit in the directory the call resolved against:
## `old/` for the probe made before the chdir (anchoring happens at call time,
## not at the end), `new/` after it, `dir/` for the dirfd-relative calls. No
## record made after the chdir may name `old/`. Every leaf must be recorded at
## all, so a shim that records nothing cannot pass.
##
## A leading `..` (`git -C ../repo` opening `../repo/.git/HEAD`) is applied
## to the directory, so the record names the sibling directory, not
## `new/../dir`. A `..` that follows a symlink (`sl/../x`) is NOT collapsed
## lexically — the kernel resolves it beside the link's target — so no record
## may name `new/x`, and the realpath companion must name the target's
## sibling.
##
## The control is posix_spawnp of a bare `x-pathsearch` found in a PATH
## directory while a decoy of the same name sits in the cwd: that name is a
## PATH lookup, not a cwd-relative path, so it must stay as spelled, and no
## record may name the decoy.
##
## A second fixture makes anchoring impossible: it descends, one relative
## mkdir+chdir at a time, below MAXPATHLEN, where neither the cwd nor a
## directory fd opened there has a nameable path, and then makes cwd- and
## dirfd-relative calls. The shim must not guess a directory for them — every
## record keeps the caller's relative spelling, none names the directory the
## process is in by then — and the capture must be downgraded to
## mcIncomplete (the fail-safe), which the first fixture must NOT be.
##
## The root is realpath-resolved so the expected spelling is the one F_GETPATH
## and getcwd produce (no /tmp or /var firmlink difference to explain away).
##
## MOCK POLICY — NO MOCKS. A real C program performs real syscalls under the
## real production shim (built by `scripts/build_shim.sh`), and the real
## fragment merge produces the evidence the assertions read. What is under
## test is what the shim records for real relative-path calls; a synthetic
## record set would assert only what its author believed the shim does.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, tempfiles]
  import macos_backend_toggle
  from build_test_shim import buildPrivateMacosShim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc compileFixture(outDir: string): string =
    result = outDir / "relative_path_ops"
    let src = repoRoot / "tests" / "helpers" / "relative_path_ops.c"
    let (output, code) = execCmdEx(quoteShell(getEnv("CC", "cc")) &
      " -arch arm64 " & quoteShell(src) & " -o " & quoteShell(result))
    doAssert code == 0, "cc failed: " & output

  proc runMonitored(shim, exe: string; args: seq[string]; workingDir,
      scratch, backend, tag: string): MonitorDepFile =
    ## Run `exe args` from `workingDir` under the shim and return the merged
    ## evidence. The concrete root pid is handed to `mergeFragments`, so an
    ## uninjected root reports incomplete rather than an empty "complete" set.
    let fragmentDir = scratch / ("frags-" & tag)
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)
    let p = startProcess(exe, workingDir = workingDir, args = args, env = env,
      options = {poStdErrToStdOut})
    let rootPid = uint64(p.processID)
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(tag & " fixture exit=" & $code & "\n" & output)
    doAssert code == 0, "monitored fixture failed: " & output
    let depfile = scratch / ("cap-" & tag & ".iomon")
    discard mergeFragments(fragmentDir, depfile, expectedRootPid = rootPid)
    result = readMonitorDepFile(depfile)
    var rootStarted = false
    for rec in result.records:
      if rec.kind == mrProcessStart and rec.osPid == rootPid:
        rootStarted = true
    doAssert rootStarted, "the fixture root was not monitored"

  proc recordsNaming(dep: MonitorDepFile; leaf: string): seq[MonitorRecord] =
    ## Every record whose path's last component is `leaf`, whatever its kind:
    ## the raw record, the canonical companion and any fd-attributed read.
    for rec in dep.records:
      if rec.path == leaf or rec.path.endsWith("/" & leaf):
        result.add rec

suite "macOS shim anchors relative paths on the cwd at call time":
  when defined(macosx):
    let shim = buildPrivateMacosShim(repoRoot)
    let root = expandFilename(createTempDir("io-mon-relanchor-", ""))
    let oldDir = root / "old"
    let newDir = root / "new"
    let dirDir = root / "dir"
    let binDir = root / "bin"
    for d in [oldDir, newDir, dirDir, binDir, newDir / "e-enum",
              dirDir / "sub"]:
      createDir(d)
    # `new/sl` -> `dir/sub`, so `sl/../x` resolves to `dir/x`, not `new/x`.
    createSymlink(dirDir / "sub", newDir / "sl")
    let fixture = compileFixture(root)
    # Launch targets: copies of the driver, which exits 0 when given no ops.
    for (dir, name) in [(newDir, "x-spawn"), (newDir, "x-exec"),
                        (newDir, "x-exec2"), (binDir, "x-pathsearch")]:
      copyFileWithPermissions(fixture, dir / name)
    # A decoy the PATH-searching spawn must not be attributed to.
    copyFileWithPermissions(fixture, newDir / "x-pathsearch")
    # Only the PATH-searching control may find its target through PATH.
    putEnv("PATH", binDir & ":" & getEnv("PATH"))

    # Leaves that exist when they are touched. The "a-" leaves never exist.
    for leaf in ["p-open.txt", "p-stat.txt", "p-lstat.txt", "p-access.txt",
                 "p-openat.txt", "p-fstatat.txt", "r-from.txt"]:
      writeFile(newDir / leaf, "present\n")
    for leaf in ["p-openatd.txt", "p-fstatatd.txt", "p-dotdot.txt",
                 "p-symdot.txt"]:
      writeFile(dirDir / leaf, "present\n")

    let ops = @[
      # Before the chdir: resolved against `old/`.
      "stat:a-before.txt",
      "chdir:" & newDir,
      "open:p-open.txt", "open:a-open.txt",
      "create:c-create.txt",
      "stat:p-stat.txt", "stat:a-stat.txt",
      "lstat:p-lstat.txt", "lstat:a-lstat.txt",
      "access:p-access.txt", "access:a-access.txt",
      "openat:p-openat.txt", "openat:a-openat.txt",
      "fstatat:p-fstatat.txt", "fstatat:a-fstatat.txt",
      "opendir:e-enum",
      "rename:r-from.txt>r-to.txt",
      # A leading ".." is applied to the cwd (`git -C ../repo`) …
      "stat:../dir/p-dotdot.txt", "open:../dir/a-dotdot.txt",
      # … but one after a symlink is the kernel's to resolve.
      "stat:sl/../p-symdot.txt",
      # A real directory fd: resolved against `dir/`, not the cwd.
      "dirfd:" & dirDir,
      "openatd:p-openatd.txt", "openatd:a-openatd.txt",
      "fstatatd:p-fstatatd.txt", "fstatatd:a-fstatatd.txt",
      # Programs named relative to the cwd (no PATH search) …
      "spawn:x-spawn", "exec:./x-exec", "exec:x-exec2",
      # … and one PATH lookup, the control.
      "spawnp:x-pathsearch",
      # An AF_UNIX endpoint named relative to the cwd.
      "listen:u.sock", "connect:u.sock"]

    let expectations = @[
      ("a-before.txt", oldDir),
      ("p-open.txt", newDir), ("a-open.txt", newDir),
      ("c-create.txt", newDir),
      ("p-stat.txt", newDir), ("a-stat.txt", newDir),
      ("p-lstat.txt", newDir), ("a-lstat.txt", newDir),
      ("p-access.txt", newDir), ("a-access.txt", newDir),
      ("p-openat.txt", newDir), ("a-openat.txt", newDir),
      ("p-fstatat.txt", newDir), ("a-fstatat.txt", newDir),
      ("e-enum", newDir),
      ("r-to.txt", newDir),
      ("p-dotdot.txt", dirDir), ("a-dotdot.txt", dirDir),
      ("p-openatd.txt", dirDir), ("a-openatd.txt", dirDir),
      ("p-fstatatd.txt", dirDir), ("a-fstatatd.txt", dirDir),
      ("x-spawn", newDir), ("x-exec", newDir), ("x-exec2", newDir),
      ("u.sock", newDir)]

    # The production configuration: interpose AND body-patch. (Interpose
    # alone does not see this fixture's access()/fstatat() at all, so it could
    # not meet the positive control below.)
    test "every relative path is recorded absolute, in the directory the " &
        "call resolved against":
      let dep = runMonitored(shim, fixture, ops, oldDir, root, "both", "anchor")
      for (leaf, expectedDir) in expectations:
        let recs = dep.recordsNaming(leaf)
        checkpoint(leaf & ": " & $recs.len & " records")
        # Positive control: the call was observed at all.
        check recs.len > 0
        for rec in recs:
          checkpoint("  " & $rec.kind & " " & rec.path & " [" &
            rec.detail & "]")
          check rec.path.isAbsolute
          # parentDir folds "..", so check for it separately: none of these
          # paths crosses a symlink, so every ".." must have been applied.
          check "/../" notin rec.path
          check rec.path.parentDir == expectedDir
      # The rename's source travels in the detail; it is a path too.
      var renameSeen = false
      for rec in dep.recordsNaming("r-to.txt"):
        let src = detailToken(rec.detail, "from")
        if src.len > 0:
          renameSeen = true
          check src == newDir / "r-from.txt"
      check renameSeen
      # The connect itself must be among the u.sock records, not just the
      # listener's unlink.
      var connectSeen = false
      for rec in dep.recordsNaming("u.sock"):
        if rec.kind == mrIpcConnect:
          connectSeen = true
      check connectSeen
      # Control: the PATH-searched name is recorded as spelled, and nothing
      # invents a cwd-relative file for it.
      var pathSearchSeen = false
      for rec in dep.records:
        if rec.kind == mrProcessSpawn and rec.path == "x-pathsearch":
          pathSearchSeen = true
        check rec.path != newDir / "x-pathsearch"
      check pathSearchSeen
      # `sl/../p-symdot.txt`: never collapsed lexically onto `new/`, and the
      # realpath companion names the file beside the link's target.
      let symdot = dep.recordsNaming("p-symdot.txt")
      check symdot.len > 0
      var symdotResolved = false
      for rec in symdot:
        checkpoint("  p-symdot " & $rec.kind & " " & rec.path)
        check rec.path.isAbsolute
        check rec.path != newDir / "p-symdot.txt"
        if rec.path == dirDir / "p-symdot.txt":
          symdotResolved = true
      check symdotResolved
      # No false downgrade: every path here was anchorable.
      for rec in dep.records:
        check not (rec.kind == mrEventLoss and
          rec.detail.contains("could not be anchored"))
      # Nothing touched after the chdir may be attributed to the old cwd.
      for rec in dep.records:
        if rec.path.startsWith(oldDir & "/"):
          check rec.path == oldDir / "a-before.txt"

    test "negative companions resolve symlinks before dotdot, or are omitted":
      # Real filesystem operations, not a normalizer-only oracle: require the
      # raw failed call AND a canonical negative key that a later open shares.
      # The driver also requires the real calls to return -1 with ENOENT or
      # ENOTDIR as appropriate: internal resolution must preserve caller errno.
      # Exercise each mechanism independently as well as production's pair.
      createDir(dirDir / "sub" / "inner")
      createSymlink(dirDir / "sub" / "inner", dirDir / "sub" / "again")
      createSymlink(root / "never-created", newDir / "dangling")
      writeFile(newDir / "plain-file", "not a directory")
      for backend in ["interpose", "bodypatch", "both"]:
        var absentOps = @["chdir:" & newDir, "dirfd:" & newDir]
        var leaves: seq[string]
        var spellings: seq[string]
        for op in ["stat", "open", "openatd", "fstatatd"]:
          # Interpose alone cannot see libc's fstatat entry on this host.
          if backend == "interpose" and op == "fstatatd": continue
          for form in ["relative", "absolute", "repeated"]:
            let leaf = "negative-" & backend & "-" & op & "-" & form
            let tail = if form == "repeated": "sl/again/../../" & leaf
                       else: "sl/../" & leaf
            let spelling = if form == "absolute": newDir & "/" & tail
                           else: tail
            leaves.add leaf
            spellings.add newDir & "/" & tail
            absentOps.add op & "!ENOENT:" & spelling
        let absent = runMonitored(shim, fixture, absentOps, oldDir, root,
          backend, "negative-" & backend)
        for i, leaf in leaves:
          var rawSeen, canonicalSeen: bool
          for rec in absent.recordsNaming(leaf):
            checkpoint(backend & " absent " & rec.path & " " & rec.detail)
            check rec.result < 0
            check rec.path != newDir / leaf
            if rec.path == spellings[i]: rawSeen = true
            if rec.path == dirDir / leaf:
              canonicalSeen = true
              check "canon=lexical" in rec.detail
          check rawSeen
          check canonicalSeen

        var presentOps = @["chdir:" & newDir]
        for leaf in leaves:
          writeFile(dirDir / leaf, "now present")
          presentOps.add "open:sl/../" & leaf
        let present = runMonitored(shim, fixture, presentOps, oldDir, root,
          backend, "present-" & backend)
        for leaf in leaves:
          var canonicalSeen = false
          for rec in present.recordsNaming(leaf):
            check rec.path != newDir / leaf
            if rec.path == dirDir / leaf and rec.kind == mrFileOpen:
              check rec.result >= 0
              canonicalSeen = true
          check canonicalSeen

        # Missing, dangling and non-directory prefixes cannot be walked through
        # '..'. A lexical guess would invent a negative probe on new/<leaf>.
        var failedOps = @["chdir:" & newDir]
        var failedPaths: seq[string]
        for prefix in ["missing-prefix", "dangling", "plain-file"]:
          for op in ["stat", "open"]:
            let leaf = "unresolvable-" & backend & "-" & prefix & "-" & op
            let tail = prefix & "/../" & leaf
            failedPaths.add newDir & "/" & tail
            let expectedErrno = if prefix == "plain-file": "ENOTDIR"
                                else: "ENOENT"
            failedOps.add op & "!" & expectedErrno & ":" & tail
        let failed = runMonitored(shim, fixture, failedOps, oldDir, root,
          backend, "unresolvable-" & backend)
        for path in failedPaths:
          let recs = failed.recordsNaming(path.extractFilename)
          check recs.len > 0
          for rec in recs:
            check rec.path == path
            check rec.result < 0
            check "canon=lexical" notin rec.detail

    test "a relative path whose directory cannot be named is not guessed, " &
        "and downgrades the capture":
      # 6 x 200-byte components take the cwd past MAXPATHLEN (1024), so
      # F_GETPATH can name neither it nor a directory fd opened in it.
      let comp = repeat('d', 200)
      var deepOps = @["chdir:" & newDir]
      for _ in 0 ..< 6:
        deepOps.add "mkdir:" & comp
        deepOps.add "chdir:" & comp
      deepOps.add "dirfd:."
      deepOps.add "stat:a-deep.txt"
      # Back to a nameable cwd: a dirfd-relative call must still not be
      # anchored on it.
      deepOps.add "chdir:" & newDir
      deepOps.add "fstatatd:a-deepd.txt"
      deepOps.add "openatd:a-deepd2.txt"
      let dep = runMonitored(shim, fixture, deepOps, oldDir, root, "both",
        "deep")
      for leaf in ["a-deep.txt", "a-deepd.txt", "a-deepd2.txt"]:
        let recs = dep.recordsNaming(leaf)
        checkpoint(leaf & ": " & $recs.len & " records")
        check recs.len > 0
        for rec in recs:
          checkpoint("  " & $rec.kind & " " & rec.path & " [" &
            rec.detail & "]")
          # As spelled: no directory was guessed, in particular not the cwd.
          check rec.path == leaf
      var lossSeen = false
      for rec in dep.records:
        if rec.kind == mrEventLoss and rec.detail.contains("could not be anchored"):
          lossSeen = true
      check lossSeen
      check dep.completeness == mcIncomplete

    # rm(1) walks a tree deeper than MAXPATHLEN; removeDir's absolute paths
    # cannot reach the bottom of the second fixture's descent.
    discard execCmd("rm -rf " & quoteShell(root))
  else:
    test "relative-path anchoring is a macOS shim property (no-op here)":
      check true
