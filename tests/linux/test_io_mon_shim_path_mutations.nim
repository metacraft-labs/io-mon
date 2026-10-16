## The Linux shim records the path mutations it used to miss.
##
## WHY. unlink, unlinkat, rmdir, remove, mkdir, mkdirat, symlink, symlinkat,
## truncate and creat change the namespace or a file's bytes without any open
## a hook sees, and the Linux shim interposed none of them: Node's libuv and
## Chromium import every one, so their deletes, directory creations, symlinks
## and truncations reached the kernel with no record and no loss. A mutation
## the monitor misses is an output nobody knows about. The same calls made
## through `syscall(2)` were unclassified, which made the run event-loss.
##
## WHAT THIS TEST GRADES. A host makes each call, through libc and through
## `syscall(2)`, including the *at forms with a directory fd, AT_REMOVEDIR,
## and calls that fail. The host itself checks every return value and errno,
## and exits non-zero on a mismatch; it does so unmonitored, preloaded, and
## under `io-mon run`, so the shim must not change a result. Under `io-mon
## run` the depfile must hold:
##   - an `mrPathMutation` for each successful namespace change, on the
##     absolute path that changed, with the call named in its detail (and a
##     symlink's target);
##   - an `mrFileWrite` for each truncate, and a write-classified open for
##     each creat;
##   - nothing for a call that failed, and no `unsupported nr=` event-loss;
##   - a path relative to a directory fd the shim never saw opened
##     (`dirfd(opendir(...))`) recorded under that directory, not left
##     relative (a consumer would resolve it against its own directory);
##   - a `syscall(2)` probe or open relative to a directory fd recorded under
##     that directory, not under the working directory;
##   - no mutation anywhere but the host's tree (the shim's own fragment
##     directory work is not the host's).
##
## Mocks: none. Real program, real shim, real files.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const mutatorSource = """
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int step = 0;
#define EXPECT_OK(expr) do { ++step; if ((expr) != 0) { \
  fprintf(stderr, "step %d failed: %s (errno %d)\n", step, #expr, errno); \
  return 10 + step; } } while (0)
#define EXPECT_ERRNO(expr, err) do { ++step; errno = 0; \
  long ct_rc = (long)(expr); \
  if (ct_rc != -1 || errno != (err)) { \
    fprintf(stderr, "step %d: %s gave %ld errno %d, wanted -1 errno %d\n", \
            step, #expr, ct_rc, errno, (err)); return 10 + step; } } while (0)

/* main's `dirfd` variable shadows dirfd(3). */
static int dir_fd(DIR *d) { return dirfd(d); }

static int write_file(int fd) {
  if (fd < 0) return -1;
  if (write(fd, "0123456789", 10) != 10) return -1;
  return close(fd);
}

int main(int argc, char **argv) {
  if (argc < 2 || chdir(argv[1]) != 0) return 2;
  int dirfd = open(".", O_DIRECTORY | O_RDONLY);
  if (dirfd < 0) return 3;

  /* libc */
  EXPECT_OK(mkdir("A", 0755));
  EXPECT_ERRNO(mkdir("A", 0755), EEXIST);
  EXPECT_OK(mkdirat(dirfd, "B", 0755));
  EXPECT_OK(write_file(creat("A/f1", 0644)));
  EXPECT_OK(write_file(creat64("A/f2", 0644)));
  EXPECT_ERRNO(creat("nodir/f", 0644), ENOENT);
  EXPECT_OK(truncate("A/f1", 3));
  EXPECT_OK(truncate64("A/f2", 0));
  EXPECT_ERRNO(truncate("nodir/f", 0), ENOENT);
  EXPECT_OK(symlink("f1", "A/s1"));
  EXPECT_OK(symlinkat("f2", dirfd, "A/s2"));
  EXPECT_ERRNO(symlink("f1", "A/s1"), EEXIST);
  EXPECT_OK(unlink("A/s1"));
  EXPECT_OK(unlinkat(dirfd, "A/s2", 0));
  EXPECT_ERRNO(unlink("missing"), ENOENT);
  EXPECT_OK(unlinkat(dirfd, "B", AT_REMOVEDIR));
  EXPECT_OK(mkdir("C", 0755));
  EXPECT_OK(rmdir("C"));
  EXPECT_ERRNO(rmdir("C"), ENOENT);
  EXPECT_OK(remove("A/f2"));
  EXPECT_ERRNO(remove("A/f2"), ENOENT);

  /* Temporary files and directories, which libc creates with its own
     internal open and mkdir. */
  {
    char t1[] = "A/tmpXXXXXX";
    char t2[] = "A/otmpXXXXXX";
    char t3[] = "A/stmpXXXXXX.sfx";
    char t4[] = "A/dtmpXXXXXX";
    char bad[] = "nodir/tmpXXXXXX";
    int fd;
    EXPECT_OK(write_file(mkstemp(t1)));
    EXPECT_OK(write_file(mkostemp(t2, O_CLOEXEC)));
    EXPECT_OK(write_file(mkstemps(t3, 4)));
    ++step; if (mkdtemp(t4) == NULL) return 10 + step;
    EXPECT_ERRNO(mkstemp(bad), ENOENT);
    (void)fd;
    printf("TEMPS %s %s %s %s\n", t1, t2, t3, t4);
  }

  /* A directory fd the shim never saw opened: opendir opens it inside libc. */
  EXPECT_OK(mkdir("D", 0755));
  EXPECT_OK(write_file(creat("D/u", 0644)));
  {
    DIR *d = opendir("D");
    if (d == NULL) return 4;
    EXPECT_OK(unlinkat(dir_fd(d), "u", 0));
    EXPECT_OK(mkdirat(dir_fd(d), "sub", 0755));
    closedir(d);
  }

  /* syscall(2) */
  {
    /* Relative to a directory that is not the working directory. */
    struct stat st;
    int adir = open("A", O_DIRECTORY | O_RDONLY);
    if (adir < 0) return 5;
    EXPECT_OK(syscall(SYS_newfstatat, adir, "f1", &st, 0));
    int fd = (int)syscall(SYS_openat, adir, "f1", O_RDONLY, 0);
    if (fd < 0) return 6;
    close(fd);
    close(adir);
  }
#ifdef SYS_mkdir
  EXPECT_OK(syscall(SYS_mkdir, "R", 0755));
#else
  EXPECT_OK(syscall(SYS_mkdirat, AT_FDCWD, "R", 0755));
#endif
  EXPECT_OK(syscall(SYS_mkdirat, dirfd, "R2", 0755));
#ifdef SYS_creat
  EXPECT_OK(write_file((int)syscall(SYS_creat, "R/rf", 0644)));
#else
  EXPECT_OK(write_file((int)syscall(SYS_openat, AT_FDCWD, "R/rf",
                                    O_CREAT | O_WRONLY | O_TRUNC, 0644)));
#endif
  EXPECT_OK(syscall(SYS_truncate, "R/rf", 5));
#ifdef SYS_symlink
  EXPECT_OK(syscall(SYS_symlink, "rf", "R/rs"));
#else
  EXPECT_OK(syscall(SYS_symlinkat, "rf", AT_FDCWD, "R/rs"));
#endif
  EXPECT_OK(syscall(SYS_symlinkat, "x", dirfd, "R2/rl"));
#ifdef SYS_unlink
  EXPECT_OK(syscall(SYS_unlink, "R/rs"));
  EXPECT_ERRNO(syscall(SYS_unlink, "missing"), ENOENT);
#else
  EXPECT_OK(syscall(SYS_unlinkat, AT_FDCWD, "R/rs", 0));
  EXPECT_ERRNO(syscall(SYS_unlinkat, AT_FDCWD, "missing", 0), ENOENT);
#endif
  EXPECT_OK(syscall(SYS_unlinkat, dirfd, "R2/rl", 0));
#ifdef SYS_rmdir
  EXPECT_OK(syscall(SYS_rmdir, "R2"));
#else
  EXPECT_OK(syscall(SYS_unlinkat, AT_FDCWD, "R2", AT_REMOVEDIR));
#endif
  EXPECT_OK(syscall(SYS_unlinkat, AT_FDCWD, "R/rf", 0));
  close(dirfd);
  printf("mutations ok after %d steps\n", step);
  return 0;
}
"""

proc mutations(dep: MonitorDepFile; path: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrPathMutation and it.path == path)

proc hasDetail(records: seq[MonitorRecord]; detail: string): bool =
  # The writer appends its own tokens (run=...) after the shim's detail.
  records.anyIt(it.detail == detail or it.detail.startsWith(detail & " "))

suite "io-mon Linux shim: path mutations":
  test "t_path_mutations_are_recorded_and_results_preserved":
    let work = expandFilename(getTempDir()) /
      ("io-mon-mutations-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    # This checkout's shim, whatever an enclosing monitor exported.
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0
    let host = work / "mutator"
    writeFile(host & ".c", mutatorSource)
    let cc = run(getEnv("CC", "cc"), @[host & ".c", "-o", host])
    checkpoint(cc.output)
    check cc.code == 0

    var plainEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): plainEnv[k] = v
    plainEnv.del("LD_PRELOAD")

    # Results first: the same host, unmonitored and preloaded, must see the
    # same return values and errno.
    for mode in ["plain", "preloaded"]:
      let tree = work / ("tree-" & mode)
      createDir(tree)
      var env = newStringTable(modeCaseSensitive)
      for k, v in plainEnv: env[k] = v
      if mode == "preloaded":
        env["LD_PRELOAD"] = shimLib
      let res = run(host, @[tree], env)
      checkpoint(mode & ": " & res.output)
      check res.code == 0

    let tree = work / "tree"
    createDir(tree)
    var env = newStringTable(modeCaseSensitive)
    for k, v in plainEnv: env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / "mutations.iomon"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host, tree],
      env)
    checkpoint(cap.output)
    check cap.code == 0
    let dep = readMonitorDepFile(depfile)
    for r in dep.records:
      if r.path.startsWith(tree) or r.kind == mrEventLoss:
        checkpoint($r.kind & " " & $r.observationKind & " " & r.path & " " &
          r.detail)

    # libc
    check dep.mutations(tree / "A").hasDetail("mkdir")
    check dep.mutations(tree / "A").len == 1        # the EEXIST retry is not
    check dep.mutations(tree / "B").anyIt(it.detail.startsWith("mkdirat dirfd="))
    check dep.mutations(tree / "B").anyIt(
      it.detail.startsWith("rmdir unlinkat dirfd=") and "flags=512" in it.detail)
    check dep.mutations(tree / "A" / "s1").hasDetail("symlink target=f1")
    check dep.mutations(tree / "A" / "s1").hasDetail("unlink")
    check dep.mutations(tree / "A" / "s2").anyIt(
      it.detail.startsWith("symlinkat dirfd=") and "target=f2" in it.detail)
    check dep.mutations(tree / "A" / "s2").anyIt(
      it.detail.startsWith("unlinkat dirfd=") and "flags=0" in it.detail)
    check dep.mutations(tree / "C").hasDetail("mkdir")
    check dep.mutations(tree / "C").hasDetail("rmdir")
    check dep.mutations(tree / "C").len == 2        # not the ENOENT retry
    # mkstemp & co. and mkdtemp: the names they chose, from the host's output.
    var temps: seq[string]
    for line in cap.output.splitLines:
      if line.startsWith("TEMPS "):
        temps = line.split(' ')[1 .. ^1]
    check temps.len == 4
    if temps.len == 4:
      for name in temps[0 .. 2]:
        check dep.records.anyIt(it.kind == mrFileOpen and
          it.path == tree / name and it.observationKind == moFileWrite)
        # The write through the descriptor it returned is attributed too.
        check dep.records.anyIt(it.kind == mrFileWrite and
          it.path == tree / name)
      check dep.mutations(tree / temps[3]).hasDetail("mkdir mkdtemp")
    check not dep.records.anyIt(it.path.startsWith(tree / "nodir" / "tmp") and
      it.kind != mrFileOpen)
    check dep.mutations(tree / "D" / "u").anyIt(
      it.detail.startsWith("unlinkat dirfd="))
    check dep.mutations(tree / "D" / "sub").anyIt(
      it.detail.startsWith("mkdirat dirfd="))
    check not dep.records.anyIt(it.path in ["u", "sub"])
    check dep.records.anyIt(it.kind == mrPathProbe and
      it.path == tree / "A" / "f1")
    check dep.records.anyIt(it.kind == mrFileOpen and
      it.path == tree / "A" / "f1" and it.observationKind == moFileOpen)
    check not dep.records.anyIt(it.path == tree / "f1")
    check dep.records.filterIt(it.kind == mrPathMutation).allIt(
      it.path.startsWith(tree & "/"))
    check dep.mutations(tree / "A" / "f2").hasDetail("remove")
    check dep.mutations(tree / "A" / "f2").len == 1
    for name in ["f1", "f2"]:
      check dep.records.anyIt(it.path == tree / "A" / name and
        it.observationKind == moFileWrite and it.kind != mrPathMutation and
        not it.detail.startsWith("truncate"))     # the creat open
      check dep.records.anyIt(it.kind == mrFileWrite and
        it.path == tree / "A" / name and it.detail.startsWith("truncate"))
    # syscall(2)
    check dep.mutations(tree / "R").anyIt(it.detail.startsWith("mkdir"))
    check dep.mutations(tree / "R2").anyIt(it.detail.startsWith("mkdirat"))
    check dep.mutations(tree / "R2").anyIt(it.detail.startsWith("rmdir"))
    check dep.mutations(tree / "R" / "rs").anyIt(
      "target=rf" in it.detail)
    check dep.mutations(tree / "R" / "rs").anyIt(it.detail.startsWith("unlink"))
    check dep.mutations(tree / "R2" / "rl").anyIt(
      it.detail.startsWith("symlinkat") and "target=x" in it.detail)
    check dep.mutations(tree / "R2" / "rl").anyIt(
      it.detail.startsWith("unlinkat"))
    check dep.mutations(tree / "R" / "rf").anyIt(
      it.detail.startsWith("unlinkat"))
    check dep.records.anyIt(it.kind == mrFileWrite and
      it.path == tree / "R" / "rf" and it.detail.startsWith("truncate"))
    check dep.records.anyIt(it.path == tree / "R" / "rf" and
      it.observationKind == moFileWrite and
      not it.detail.startsWith("truncate"))       # the creat
    # Failed calls change nothing. A failed mutation records nothing; a failed
    # creat is a failed open and is recorded exactly as open(O_CREAT) records
    # one, with its failure, never as a mutation or a successful write.
    check not dep.records.anyIt(it.path == tree / "missing")
    check not dep.records.anyIt(it.path == tree / "C" and
      it.kind == mrPathMutation and it.result != 0)
    check dep.records.filterIt(it.path == tree / "nodir" / "f").allIt(
      it.kind == mrFileOpen and it.result < 0)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "unsupported nr=" in it.detail)
    check dep.completeness == mcComplete
    removeDir(work)
