## Distinct real Linux shim images must not recurse through preempted helpers.
## Build the production library, copy it to two paths with the production
## basename, and launch a C host through a real shell in both preload orders.
## The host proves both images are resident, resolves each image's own exported
## helper, and checks environment lookup and real file I/O. The parent bounds
## startup, including constructors that run before main. No mocks. This covers
## loader forwarding; the propagation suite checks complete capture separately.
import std/[os, osproc, streams, strtabs, strutils, tempfiles, unittest]
import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const probeSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 4) return 10;
  char *value = getenv("IO_MON_PRELOAD_PROBE");
  if (!value || strcmp(value, "distinct-images")) return 11;
  char *(*lookup)(const char *) = dlsym(RTLD_DEFAULT, "getenv");
  if (!lookup || !(value = lookup("IO_MON_PRELOAD_PROBE")) ||
      strcmp(value, "distinct-images")) return 12;
  void *functions[2] = {0};
  for (int i = 0; i < 2; ++i) {
    void *image = dlopen(argv[i + 1], RTLD_NOW | RTLD_NOLOAD);
    if (!image) return 20 + i;
    functions[i] = dlsym(image, "ct_linux_preload_real_getenv");
    Dl_info owner;
    if (!functions[i] || !dladdr(functions[i], &owner) ||
        strcmp(owner.dli_fname, argv[i + 1])) return 22 + i;
    char *(*own_lookup)(const char *) = functions[i];
    value = own_lookup("IO_MON_PRELOAD_PROBE");
    if (!value || strcmp(value, "distinct-images")) return 24 + i;
    if (dlclose(image)) return 26 + i;
  }
  if (functions[0] == functions[1]) return 28;
  int fd = open(argv[3], O_RDONLY);
  if (fd < 0) return 30;
  char contents[64] = {0};
  ssize_t length = read(fd, contents, sizeof(contents) - 1);
  if (close(fd) || length != 23 ||
      strcmp(contents, "distinct-preload-input\n")) return 31;
  puts("two distinct images: lookup and read passed");
  return 0;
}
"""

suite "Linux distinct preload image ownership":
  test "both preload orders preserve initialization, lookup and host I/O":
    let work = createTempDir("io-mon-distinct-preloads-", "")
    defer: removeDir(work)
    let original = buildPrivateLinuxShim(repoRoot)
    var shims: array[2, string]
    for i in 0 .. 1:
      let dir = work / $i
      createDir(dir)
      shims[i] = dir / "librepro_monitor_shim.so"
      copyFile(original, shims[i])
    let source = work / "probe.c"
    let probe = work / "probe"
    let input = work / "input"
    writeFile(source, probeSource)
    writeFile(input, "distinct-preload-input\n")
    let built = execCmdEx(quoteShellCommand([getEnv("CC", "cc"), source,
      "-o", probe, "-ldl"]))
    checkpoint(built.output)
    require built.exitCode == 0
    for first in 0 .. 1:
      var env = newStringTable(modeCaseSensitive)
      for key, value in envPairs(): env[key] = value
      env["LD_PRELOAD"] = shims[first] & ":" & shims[1 - first]
      env["REPRO_MONITOR_SHIM_LIB"] = shims[first]
      env["IO_MON_PRELOAD_PROBE"] = "distinct-images"
      let child = startProcess("/bin/sh", args = @["-c",
        "exec " & quoteShellCommand([probe, shims[0], shims[1], input])],
        env = env, options = {poStdErrToStdOut})
      try:
        let code = child.waitForExit(30_000)
        if code == -1:
          child.kill()
          discard child.waitForExit()
        let output = child.outputStream.readAll()
        checkpoint("first image " & $first & ": " & output)
        check code == 0
        check "two distinct images: lookup and read passed" in output
      finally:
        child.close()
