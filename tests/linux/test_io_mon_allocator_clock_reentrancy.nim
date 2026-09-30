## Real process/allocator integration; no mocks. The C executable interposes
## malloc with a real mutex and clock read, reproducing rustc's lock ordering.
## The second case exercises the actual compiler supplied by the dev shell.
import std/[os, osproc, sequtils, strutils, tempfiles, unittest]
import io_mon

const allocatorHost = """
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
extern void *__libc_malloc(size_t);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int active;
void *malloc(size_t n) {
  if (!active) return __libc_malloc(n);
  pthread_mutex_lock(&lock);
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  void *p = __libc_malloc(n);
  pthread_mutex_unlock(&lock);
  return p;
}
static void *worker(void *unused) {
  for (int i = 0; i < 100; ++i) {
    void *p = malloc(17 + i);
    if (!p) abort();
    free(p);
  }
  return unused;
}
int main(void) {
  pthread_t threads[8];
  active = 1;
  for (int i = 0; i < 8; ++i)
    if (pthread_create(&threads[i], NULL, worker, NULL)) return 2;
  for (int i = 0; i < 8; ++i)
    if (pthread_join(threads[i], NULL)) return 3;
  return 0;
}
"""

suite "Linux allocator clock reentrancy":
  let work = createTempDir("io-mon-allocator-clock-", "")
  defer: removeDir(work)
  let shim = findShimLibrary()
  require shim.len > 0
  require findExe("timeout").len > 0

  test "first clock observation on foreign threads under a host allocator lock":
    let source = work / "allocator.c"
    let binary = work / "allocator"
    writeFile(source, allocatorHost)
    let built = execCmdEx(quoteShell(getEnv("CC", "cc")) &
      " -O0 -fno-builtin-malloc -pthread -rdynamic " &
      quoteShell(source) & " -o " & quoteShell(binary))
    checkpoint(built.output)
    require built.exitCode == 0
    check execCmdEx("timeout 15 " & quoteShell(binary)).exitCode == 0
    let observed = runMonitored(FsSnoopRequest(
      command: @["timeout", "15", binary],
      depFilePath: work / "allocator.iomon", streamMode: fsoNone))
    check observed.exitCode == 0
    check observed.records.anyIt(it.kind == mrTimeRead and
      it.path == "clock_gettime:1")

  test "real rustc target enumeration terminates and records time":
    let rustc = findExe("rustc")
    require rustc.len > 0
    let observed = runMonitored(FsSnoopRequest(
      command: @["timeout", "30", rustc, "--print", "target-list"],
      depFilePath: work / "rustc.iomon", streamMode: fsoNone))
    check observed.exitCode == 0
    check observed.records.anyIt(it.kind == mrTimeRead and
      it.path.startsWith("clock_gettime:"))
