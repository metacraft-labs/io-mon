## File I/O submitted through io_uring must not grade `mcComplete` unobserved.
##
## Property protected: a monitored process that opens and reads an input file
## by submitting IORING_OP_OPENAT / IORING_OP_READ requests to a ring it set up
## itself bypasses every libc and raw-syscall hook (no open(2)/read(2) is ever
## issued). The depfile for that run must therefore either record the input as
## read, or grade the run as not complete (a monitor-loss record), or the
## monitor must have refused the ring so the program never got to use it.
## Reporting a complete run with no trace of the file is a silent input loss.
##
## Real compiler, real shim, real kernel; no mocks. The fixture speaks to the
## ring with raw syscalls and <linux/io_uring.h> only (no liburing), submitting
## without SQPOLL: that is the easiest case, one `io_uring_enter` per batch.
import foreign_preload_isolation

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = getEnv("STACKABLE_HOOKS_SRC",
    repoRoot.parentDir() / "nim-stackable-hooks" / "src")
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  ringReader = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Exit codes: 0 = the file was opened and read through the ring,
 * 77 = the ring is unavailable or refused (setup/enter failed), 1 = other. */
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  struct io_uring_params p;
  memset(&p, 0, sizeof p);
  int rfd = (int)syscall(SYS_io_uring_setup, 4, &p);
  if (rfd < 0) { fprintf(stderr, "setup: %s\n", strerror(errno)); return 77; }
  size_t sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
  size_t cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
  if (p.features & IORING_FEAT_SINGLE_MMAP) {
    if (cqsz > sqsz) sqsz = cqsz;
    cqsz = sqsz;
  }
  char *sq = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                  rfd, IORING_OFF_SQ_RING);
  char *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq :
    mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, rfd,
         IORING_OFF_CQ_RING);
  struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, rfd, IORING_OFF_SQES);
  if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) return 77;
  unsigned *sqtail = (unsigned *)(sq + p.sq_off.tail);
  unsigned *sqmask = (unsigned *)(sq + p.sq_off.ring_mask);
  unsigned *sqarr = (unsigned *)(sq + p.sq_off.array);
  unsigned *cqhead = (unsigned *)(cq + p.cq_off.head);
  unsigned *cqtail = (unsigned *)(cq + p.cq_off.tail);
  unsigned *cqmask = (unsigned *)(cq + p.cq_off.ring_mask);
  struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);

  unsigned t = *sqtail, idx = t & *sqmask;
  memset(&sqes[idx], 0, sizeof sqes[idx]);
  sqes[idx].opcode = IORING_OP_OPENAT;
  sqes[idx].fd = AT_FDCWD;
  sqes[idx].addr = (unsigned long)argv[1];
  sqes[idx].open_flags = O_RDONLY;
  sqes[idx].user_data = 1;
  sqarr[idx] = idx;
  __atomic_store_n(sqtail, t + 1, __ATOMIC_RELEASE);
  if (syscall(SYS_io_uring_enter, rfd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
    return 77;
  unsigned h = *cqhead;
  if (h == __atomic_load_n(cqtail, __ATOMIC_ACQUIRE)) return 1;
  int fd = cqes[h & *cqmask].res;
  *cqhead = h + 1;
  if (fd < 0) return 1;

  static char buf[64];
  t = *sqtail; idx = t & *sqmask;
  memset(&sqes[idx], 0, sizeof sqes[idx]);
  sqes[idx].opcode = IORING_OP_READ;
  sqes[idx].fd = fd;
  sqes[idx].addr = (unsigned long)buf;
  sqes[idx].len = sizeof buf;
  sqes[idx].user_data = 2;
  sqarr[idx] = idx;
  __atomic_store_n(sqtail, t + 1, __ATOMIC_RELEASE);
  if (syscall(SYS_io_uring_enter, rfd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
    return 77;
  h = *cqhead;
  int n = cqes[h & *cqmask].res;
  fprintf(stderr, "read %d bytes through the ring\n", n);
  return n > 0 ? 0 : 1;
}
"""

  plainReaderSrc = """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  if (argc != 2) return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 1;
  ssize_t n = read(fd, buf, sizeof buf);
  close(fd);
  return n > 0 ? 0 : 1;
}
"""

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon Linux io_uring file I/O observation":
  let work = getTempDir() / ("io-mon-linux-io-uring-" & $getCurrentProcessId())
  createDir(work)

  test "a file opened and read through io_uring is recorded or grades the run incomplete":
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0
    let shimLib = buildPrivateLinuxShim(repoRoot)

    let srcPath = work / "ring_reader.c"
    let reader = work / "ring_reader"
    writeFile(srcPath, ringReader)
    let built = run(getEnv("CC", "cc"), @[srcPath, "-o", reader])
    checkpoint(built.output)
    check built.code == 0

    let plainSrc = work / "plain_reader.c"
    let plainReader = work / "plain_reader"
    writeFile(plainSrc, plainReaderSrc)
    let builtPlain = run(getEnv("CC", "cc"), @[plainSrc, "-o", plainReader])
    checkpoint(builtPlain.output)
    check builtPlain.code == 0

    let marker = work / "ring-input-marker.txt"
    writeFile(marker, "input read only through io_uring\n")

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

    # Control: the same input read with open(2)/read(2) under the same monitor
    # must be recorded. Without this, "no record" could be an artefact of the
    # record query or of the monitor not being attached.
    let ctlDepfile = work / "plain.iomon"
    let ctl = run(snoopBin, @["run", "--depfile", ctlDepfile, "--", plainReader,
      marker], childEnv)
    checkpoint(ctl.output)
    check ctl.code == 0
    let ctlDep = readMonitorDepFile(ctlDepfile)
    check ctlDep.records.anyIt(
      (it.kind == mrFileOpen or it.kind == mrFileRead) and marker in it.path)

    # Precondition: the ring must work without the monitor. If it does not,
    # the kernel or sandbox has no io_uring and nothing can be judged.
    let unmon = run(reader, @[marker])
    checkpoint("unmonitored ring reader: " & unmon.output)
    if unmon.code == 77:
      skip()
    else:
      check unmon.code == 0
      let depfile = work / "ring.iomon"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader,
        marker], childEnv)
      checkpoint(cap.output)
      if cap.code == 77:
        # Works unmonitored, refused under the monitor: the monitor closed the
        # gap by refusing the ring. The property holds.
        check true
      else:
        check cap.code == 0
        let dep = readMonitorDepFile(depfile)
        let sawRead = dep.records.anyIt(
          (it.kind == mrFileOpen or it.kind == mrFileRead) and
          marker in it.path)
        let graded = dep.completeness != mcComplete or
          dep.records.anyIt(it.kind == mrEventLoss)
        checkpoint("the program read " & marker & " through io_uring; " &
          "file open/read record present: " & $sawRead &
          "; run graded not complete or event-loss record present: " &
          $graded & "; completeness=" & $dep.completeness &
          "; records=" & $dep.records.len)
        check sawRead or graded
