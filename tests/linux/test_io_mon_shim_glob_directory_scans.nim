## glob(3) records every directory it scans and every path it looks up.
##
## WHY. glibc's glob opens, reads and stats directories through internal calls
## (`__opendir`, `__readdir64`, `__fstatat64`) that no LD_PRELOAD interposition
## sees, so a scan made through glob left no evidence at all. Nim's compiler
## finds `*.nimble` files in a project's parent directories with `walkFiles`,
## which is glob on POSIX: adding or removing a `.nimble` file there changes
## how the compile resolves packages, yet nothing the monitor recorded named
## those directories, so the cached compile was never invalidated on Linux
## (reprobuild-pm issue 2026-10-16-io-mon-linux-shim-misses-directory-scans-
## made-through-glob). The macOS backend already records these scans, because
## Darwin's glob reaches the interposed `opendir`.
##
## A scan is PATTERN-SCOPED: glob keeps only the entries that match one
## component of the pattern, so the enumeration carries that component
## (detail `GlobPatternDetailPrefix & <component>`) and a consumer can key on
## the matching entries alone. Without it, every unrelated file created beside
## a project's sources would invalidate each Nim compile in the project
## (reprobuild-pm issue 2026-10-17-nimble-glob-keys-nim-edges-on-the-full-
## membership-of-tracked-directories). Where the component cannot be named
## with certainty the scan must stay a FULL enumeration, because a pattern
## narrower than glob's would drop a dependency.
##
## WHAT THIS TEST GRADES.
##   * `t_glob_records_the_directories_its_pattern_scans`: absolute patterns
##     through `glob` and `glob64` — a wildcard in the last component, one in
##     a middle component (every directory it walks into is scanned), and a
##     wildcard that matches nothing — record a directory enumeration of each
##     directory scanned, scoped to the component matched there. The no-match
##     case is the one Nim's `.nimble` search depends on: the ABSENCE of a
##     match is the input.
##   * `t_uncertain_patterns_stay_full_enumerations`: brace expansion, a
##     bracket expression and a backslash escape each record a full
##     enumeration, never a pattern.
##   * `t_the_working_directory_is_scoped_only_when_spelled_literally`: the
##     working directory opened as "." is scoped for a literal `./` prefix
##     and stays full where "." is matched against a wildcard first
##     component, or was itself the match of one.
##   * `t_glob_records_lookups_of_literal_components`: a pattern without a
##     wildcard is resolved by lstat inside glob; both an existing and an
##     absent name must be recorded as probes.
##   * `t_a_directory_glob_cannot_open_is_probed`: a directory component that
##     does not exist, or is a file, is recorded as a probe of that name.
##   * `t_relative_glob_is_attributed_to_the_working_directory`: `*.txt` scans
##     the working directory, which must be recorded by its absolute path.
##   * `t_glob_results_are_unchanged`: the matches, their order and the
##     returned flags are what an unmonitored run produces, including GLOB_MARK
##     and GLOB_ONLYDIR, which glob answers from what readdir/stat report.
##   * `t_caller_supplied_directory_functions_are_respected`: a caller that
##     passes its own GLOB_ALTDIRFUNC callbacks gets them called, and its glob_t
##     fields back unchanged.
##   * `t_nim_walkfiles_records_the_directory_it_searches`: Nim's `walkFiles`,
##     the call the issue was found with, records the directories it searches.
##
## Mocks: none. Real programs, real shim, real directories.

import std/[algorithm, os, osproc, sequtils, streams, strtabs, strutils,
  unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
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

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let built = run(getEnv("CC", "cc"), @[sourcePath, "-o", result])
  checkpoint(name & " cc: " & built.output)
  doAssert built.code == 0, built.output

proc lossDetails(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss:
      result.add r.detail

proc enumerated(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrDirectoryEnumerate:
      result.add r.path
  result.sort()
  result = result.deduplicate(isSorted = true)

proc scopes(dep: MonitorDepFile; path: string): seq[string] =
  ## How each enumeration of `path` was scoped: the pattern component of a
  ## pattern-scoped one, "full" for any other. Sorted and deduplicated.
  for r in dep.records:
    if r.kind == mrDirectoryEnumerate and r.path == path:
      let pattern = globScanPattern(r.detail)
      result.add(if pattern.len > 0: pattern else: "full")
  result.sort()
  result = result.deduplicate(isSorted = true)

proc probes(dep: MonitorDepFile; path: string): seq[ProbeResult] =
  for r in dep.records:
    if r.kind == mrPathProbe and r.path == path:
      result.add r.probeResult

# `globber MODE PATTERN...` globs each pattern and prints every match, the
# return code and gl_flags, so a monitored and an unmonitored run can be
# compared line for line. MODE selects `glob` or `glob64` and its flags.
const globberSource = """
#define _GNU_SOURCE
#include <glob.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  const char *mode = argv[1];
  int flags = 0;
  if (strstr(mode, "mark")) flags |= GLOB_MARK;
  if (strstr(mode, "onlydir")) flags |= GLOB_ONLYDIR;
  if (strstr(mode, "brace")) flags |= GLOB_BRACE;
  for (int i = 2; i < argc; i++) {
    int rc;
    if (strstr(mode, "glob64")) {
      glob64_t g;
      memset(&g, 0, sizeof(g));
      rc = glob64(argv[i], flags, NULL, &g);
      printf("%s rc=%d flags=%d\n", argv[i], rc, rc == 0 ? g.gl_flags : -1);
      for (size_t k = 0; rc == 0 && k < g.gl_pathc; k++)
        printf("  %s\n", g.gl_pathv[k]);
      if (rc == 0) globfree64(&g);
    } else {
      glob_t g;
      memset(&g, 0, sizeof(g));
      rc = glob(argv[i], flags, NULL, &g);
      printf("%s rc=%d flags=%d\n", argv[i], rc, rc == 0 ? g.gl_flags : -1);
      for (size_t k = 0; rc == 0 && k < g.gl_pathc; k++)
        printf("  %s\n", g.gl_pathv[k]);
      if (rc == 0) globfree(&g);
    }
  }
  return 0;
}
"""

# The caller supplies its own GLOB_ALTDIRFUNC directory functions. They serve
# a virtual directory, so the scan touches no filesystem directory and the
# caller's fields must come back as it set them.
const altDirSource = """
#define _GNU_SOURCE
#include <dirent.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
static int opened, read_calls, closed;
static struct dirent entry;
static void *my_opendir(const char *path) {
  opened++;
  return strcmp(path, "/virtual") == 0 ? (void *)&entry : NULL;
}
static struct dirent *my_readdir(void *d) {
  (void)d;
  if (read_calls++ > 0) return NULL;
  memset(&entry, 0, sizeof(entry));
  strcpy(entry.d_name, "only.nimble");
  entry.d_type = DT_REG;
  return &entry;
}
static void my_closedir(void *d) { (void)d; closed++; }
static int my_stat(const char *p, struct stat *st) {
  (void)p; memset(st, 0, sizeof(*st)); st->st_mode = S_IFREG; return 0;
}
int main(void) {
  glob_t g;
  memset(&g, 0, sizeof(g));
  g.gl_opendir = my_opendir;
  g.gl_readdir = my_readdir;
  g.gl_closedir = my_closedir;
  g.gl_stat = my_stat;
  g.gl_lstat = my_stat;
  int rc = glob("/virtual/*.nimble", GLOB_ALTDIRFUNC, NULL, &g);
  if (rc != 0 || g.gl_pathc != 1) return 2;
  if (strcmp(g.gl_pathv[0], "/virtual/only.nimble") != 0) return 3;
  if (opened != 1 || closed != 1) return 4;
  if ((g.gl_flags & GLOB_ALTDIRFUNC) == 0) return 5;
  if (g.gl_opendir != my_opendir || g.gl_readdir != my_readdir ||
      g.gl_closedir != my_closedir || g.gl_stat != my_stat ||
      g.gl_lstat != my_stat) return 6;
  globfree(&g);
  return 0;
}
"""

suite "io-mon Linux shim records directory scans made through glob":
  let work = getTempDir() / ("io-mon-glob-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"
  block:
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    doAssert cli.code == 0, cli.output
  let shimLib = buildPrivateLinuxShim(repoRoot)
  let globber = buildC(work, "globber", globberSource)
  let altDir = buildC(work, "altdir", altDirSource)

  # The tree every case scans:
  #   tree/project/{a.nimble, src/{m.nim, sub/}, docs/{x.txt}}
  #   tree/project/src/sub/{y.txt}
  #   tree/empty/            (holds no .nimble: the "absent" case)
  let tree = work / "tree"
  let project = tree / "project"
  createDir(project / "src" / "sub")
  createDir(project / "docs")
  createDir(tree / "empty")
  writeFile(project / "a.nimble", "")
  writeFile(project / "src" / "m.nim", "")
  writeFile(project / "src" / "sub" / "y.txt", "")
  writeFile(project / "docs" / "x.txt", "")
  writeFile(project / "notes.txt", "")

  proc monitor(depName: string; args: seq[string]; workingDir = ""):
      tuple[dep: MonitorDepFile; output: string; code: int] =
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / (depName & ".iomon")
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--"] & args, env,
      workingDir)
    checkpoint(depName & " (exit " & $cap.code & "):\n" & cap.output)
    result.output = cap.output
    result.code = cap.code
    doAssert fileExists(depfile), "no depfile for " & depName
    result.dep = readMonitorDepFile(depfile)
    checkpoint(depName & ": " & $result.dep.completeness & "; losses: " &
      $lossDetails(result.dep) & "; enumerated: " & $enumerated(result.dep))

  test "t_glob_records_the_directories_its_pattern_scans":
    for mode in ["glob", "glob64"]:
      let r = monitor("scan-" & mode, @[globber, mode,
        project / "*.nimble",          # last component: scans project
        project / "*" / "*.txt",       # middle component: project and each
                                       # subdirectory it walks into
        tree / "empty" / "*.nimble"])  # no match: the absence is the input
      check r.code == 0
      check r.output.contains(project / "a.nimble")
      check r.output.contains(project / "docs" / "x.txt")
      let dirs = enumerated(r.dep)
      for d in [project, project / "docs", project / "src", tree / "empty"]:
        if d notin dirs:
          checkpoint(mode & ": no directory enumeration of " & d)
        check d in dirs
      # glob never opens a directory the pattern does not name.
      check (project / "src" / "sub") notin dirs
      # Each scan names the component matched in that directory: `project`
      # is matched against `*.nimble` by the first pattern and against the
      # middle `*` by the second, its subdirectories against `*.txt`.
      check r.dep.scopes(project) == @["*", "*.nimble"]
      check r.dep.scopes(project / "docs") == @["*.txt"]
      check r.dep.scopes(project / "src") == @["*.txt"]
      check r.dep.scopes(tree / "empty") == @["*.nimble"]
      check r.dep.completeness == mcComplete

  test "t_uncertain_patterns_stay_full_enumerations":
    # Brace expansion rewrites the pattern before glob opens anything; a
    # bracket expression and a backslash escape need fnmatch's own rules to
    # match. None may be reported as a pattern, but each scan is recorded.
    let brace = monitor("brace", @[globber, "glob-brace",
      project / "{a,notes}*", tree / "empty" / "x{1,2}*"])
    check brace.code == 0
    check brace.output.contains(project / "a.nimble")
    check brace.output.contains(project / "notes.txt")
    check brace.dep.scopes(project) == @["full"]
    check brace.dep.scopes(tree / "empty") == @["full"]
    let classes = monitor("classes", @[globber, "glob",
      project / "[a]*.nimble", project / "docs" / "\\x*"])
    check classes.code == 0
    check classes.output.contains(project / "a.nimble")
    check classes.output.contains(project / "docs" / "x.txt")
    check classes.dep.scopes(project) == @["full"]
    check classes.dep.scopes(project / "docs") == @["full"]
    check classes.dep.completeness == mcComplete

  test "t_glob_records_lookups_of_literal_components":
    let r = monitor("literal", @[globber, "glob",
      project / "a.nimble", project / "missing.nimble"])
    check r.code == 0
    check r.output.contains(project / "a.nimble" & " rc=0")
    check r.output.contains(project / "missing.nimble" & " rc=" &
      $3)  # GLOB_NOMATCH
    check prExistingOther in r.dep.probes(project / "a.nimble") or
      prExistingFile in r.dep.probes(project / "a.nimble")
    check prAbsent in r.dep.probes(project / "missing.nimble")
    check r.dep.completeness == mcComplete

  test "t_a_directory_glob_cannot_open_is_probed":
    # `absent/*.nimble` matches nothing because `absent` does not exist; the
    # result changes when it is created, so its absence must be recorded.
    let r = monitor("unopenable", @[globber, "glob",
      tree / "absent" / "*.nimble", project / "a.nimble" / "*"])
    check r.code == 0
    check prAbsent in r.dep.probes(tree / "absent")
    # A file in a directory position cannot be opened as one, but it exists.
    check prExistingOther in r.dep.probes(project / "a.nimble")
    check prAbsent notin r.dep.probes(project / "a.nimble")
    check r.dep.completeness == mcComplete

  test "t_nim_walkfiles_records_the_directory_it_searches":
    # The case the issue was found with: the Nim compiler looks for a
    # project's `.nimble` file in each parent directory with `walkFiles`.
    let walker = work / "walker"
    writeFile(walker & ".nim", """
import std/os
for dir in [paramStr(1), paramStr(2)]:
  for f in walkFiles(dir / "*.nimble"):
    echo f
""")
    let built = run("nim", @["c", "--hints:off", "--out:" & walker,
      walker & ".nim"])
    checkpoint(built.output)
    doAssert built.code == 0, built.output
    let r = monitor("walkfiles", @[walker, project, tree / "empty"])
    check r.code == 0
    check r.output.contains(project / "a.nimble")
    let dirs = enumerated(r.dep)
    check project in dirs
    check (tree / "empty") in dirs
    check r.dep.scopes(project) == @["*.nimble"]
    check r.dep.scopes(tree / "empty") == @["*.nimble"]
    check r.dep.completeness == mcComplete

  test "t_relative_glob_is_attributed_to_the_working_directory":
    let r = monitor("relative", @[globber, "glob", "*.txt", "src/*.nim"],
      workingDir = project)
    check r.code == 0
    check r.output.contains("  notes.txt")
    check r.output.contains("  src/m.nim")
    let dirs = enumerated(r.dep)
    check project in dirs
    check (project / "src") in dirs
    check r.dep.scopes(project) == @["*.txt"]
    check r.dep.scopes(project / "src") == @["*.nim"]
    check r.dep.completeness == mcComplete

  test "t_the_working_directory_is_scoped_only_when_spelled_literally":
    # glob opens the working directory as "." in three situations: for a
    # relative pattern's literal "./" prefix, as the implicit start of a
    # relative pattern whose FIRST component is a wildcard, and when a
    # wildcard such as `.*` matched the entry "." itself. In the last two
    # "." is matched against a different component than its spelling
    # suggests (`*` for `*/*.nim`, not `*.nim`), so only the first may be
    # scoped. Reporting `*.nim` there would ignore a new subdirectory that
    # holds a `.nim` file: a false cache hit.
    let r = monitor("relative-wildcard", @[globber, "glob", "*/*.nim",
      ".*/*.txt", "./*.nimble"], workingDir = project)
    check r.code == 0
    check r.output.contains("  src/m.nim")
    check r.output.contains("  ./a.nimble")
    check r.dep.scopes(project) == @["*.nimble", "full"]
    check r.dep.scopes(project / "src") == @["*.nim"]
    check r.dep.completeness == mcComplete

  test "t_glob_results_are_unchanged":
    for mode in ["glob", "glob-mark", "glob-onlydir", "glob64-mark-onlydir"]:
      let args = @[mode, project / "*", project / "*" / "*",
                   tree / "*" / "*.nimble", project / "a.nimble",
                   project / "nope*"]
      let plain = run(globber, args)
      let r = monitor("unchanged-" & mode, @[globber] & args)
      check plain.code == 0
      check r.code == 0
      checkpoint("plain:\n" & plain.output)
      check r.output == plain.output

  test "t_caller_supplied_directory_functions_are_respected":
    let r = monitor("altdir", @[altDir])
    check r.code == 0
    check "/virtual" notin enumerated(r.dep)

  removeDir(work)
