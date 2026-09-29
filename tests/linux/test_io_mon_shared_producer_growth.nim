## Real pthread, filesystem, fork/exec and shared-memory capture; no mocks.
## Every worker probes distinct paths so the shared set must grow. The test
## checks the entire observed path set, not just successful process exit.
import std/[os, osproc, sets, strutils, tempfiles, unittest]
import io_mon

const
  workers = 8
  probes = 2048
  children = 8
  hostSource = """
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static pthread_barrier_t start;
static const char *prefix;
static void probe(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd >= 0 || errno != ENOENT) _exit(20);
}
static void *worker(void *arg) {
  intptr_t id = (intptr_t)arg;
  char path[4096];
  pthread_barrier_wait(&start);
  for (int i = 0; i < 2048; ++i) {
    snprintf(path, sizeof(path), "%s/worker-%ld-%d", prefix, (long)id, i);
    probe(path);
  }
  return NULL;
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  if (strcmp(argv[1], "child") == 0) {
    probe(argv[2]);
    return 0;
  }
  if (strcmp(argv[1], "monitored") == 0) {
    const char *transport = getenv("REPRO_MONITOR_DEP_SHM");
    if (!transport || !strstr(transport, ".shard0")) return 3;
  }
  prefix = argv[2];
  pthread_t threads[8];
  if (pthread_barrier_init(&start, NULL, 9)) return 4;
  for (intptr_t i = 0; i < 8; ++i)
    if (pthread_create(&threads[i], NULL, worker, (void *)i)) return 5;
  pthread_barrier_wait(&start);
  if (strcmp(argv[3], "fork") == 0) {
    for (int i = 0; i < 8; ++i) {
      char path[4096];
      snprintf(path, sizeof(path), "%s/child-%d", prefix, i);
      pid_t child = fork();
      if (child < 0) return 6;
      if (child == 0) {
        execl(argv[0], argv[0], "child", path, "none", (char *)0);
        _exit(7);
      }
      int status = 0;
      if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
          || WEXITSTATUS(status) != 0) return 8;
    }
  }
  for (int i = 0; i < 8; ++i)
    if (pthread_join(threads[i], NULL)) return 9;
  pthread_barrier_destroy(&start);
  return 0;
}
"""

suite "Linux shared producer mapping growth":
  let work = createTempDir("io-mon-producer-growth-", "")
  defer: removeDir(work)
  let source = work / "host.c"
  let binary = work / "host"
  writeFile(source, hostSource)
  let built = execCmdEx(quoteShell(getEnv("CC", "cc")) &
    " -O0 -pthread " & quoteShell(source) & " -o " & quoteShell(binary))
  checkpoint(built.output)
  require built.exitCode == 0
  require findShimLibrary().len > 0
  require findExe("timeout").len > 0

  for mode in ["threads", "fork"]:
    test "complete capture during concurrent growth: " & mode:
      let prefix = work / ("absent-" & mode)
      let native = execCmdEx("timeout 60 " & quoteShell(binary) &
        " native " & quoteShell(prefix) & " " & mode)
      checkpoint(native.output)
      require native.exitCode == 0
      for repetition in 0 ..< 3:
        let observed = runMonitored(FsSnoopRequest(
          command: @["timeout", "60", binary, "monitored", prefix, mode],
          depFilePath: work / (mode & "-" & $repetition & ".iomon"),
          env: @[("REPRO_MONITOR_DEP_SHM_DISABLE", "")],
          streamMode: fsoNone))
        check observed.exitCode == 0
        check observed.depFile.completeness == mcComplete
        var paths = initHashSet[string]()
        for record in observed.records:
          if record.path.startsWith(prefix & "/"):
            paths.incl record.path
        let childCount = if mode == "fork": children else: 0
        check paths.len == workers * probes + childCount
        for worker in 0 ..< workers:
          for index in 0 ..< probes:
            require prefix / ("worker-" & $worker & "-" & $index) in paths
        for child in 0 ..< childCount:
          require prefix / ("child-" & $child) in paths
