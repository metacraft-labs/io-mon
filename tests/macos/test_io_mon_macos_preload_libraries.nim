## Real launch transparency regression, with no mocks. Compile two actual
## dylibs and a C launcher/reader. The child must load both requested libraries,
## retain the monitor exactly once and produce captured input evidence across
## posix_spawn, POSIX_SPAWN_SETEXEC and execve. Test lists with the shim already
## first/last, repeated and absent; exercise interpose and body-patch forwarding. Every
## launch is bounded and killed/reaped on timeout.
import std/[os, osproc, sequtils, streams, strtabs, strutils, tempfiles, unittest]

when defined(macosx):
  import std/posix
  import io_mon
  import build_test_shim, macos_backend_toggle

  const root = currentSourcePath().parentDir.parentDir.parentDir

suite "macOS child preload library preservation":
  when defined(macosx):
    let work = createTempDir("io-mon-preload-libraries-", "")
    defer: removeDir(work)
    let input = expandFilename(work) / "input"
    writeFile(input, "preload-input")
    let cc = getEnv("CC", "cc")
    proc compile(source, output, extra: string) =
      let got = execCmdEx(quoteShell(cc) & " " & extra & " " &
        quoteShell(source) & " -o " & quoteShell(output))
      doAssert got.exitCode == 0, got.output
    var libs: array[2, string]
    for i in 0 .. 1:
      let source = work / ("extra" & $i & ".c")
      libs[i] = work / ("extra" & $i & ".dylib")
      writeFile(source, "int io_mon_extra_" & $i & "(void) { return 42; }\n")
      compile(source, libs[i], "-dynamiclib")
    let source = work / "probe.c"
    let probe = work / "probe"
    writeFile(source, """
#include <dlfcn.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {
  if (argc != 5) return 10;
  if (!strcmp(argv[1], "child")) {
    int (*a)(void) = dlsym(RTLD_DEFAULT, "io_mon_extra_0");
    int (*b)(void) = dlsym(RTLD_DEFAULT, "io_mon_extra_1");
    if (!a || !b || a() != 42 || b() != 42) return 11;
    const char *dyld = getenv("DYLD_INSERT_LIBRARIES");
    const char *shim = getenv("REPRO_MONITOR_SHIM_LIB");
    if (!dyld || !shim) return 12;
    unsigned count = 0;
    for (const char *p = dyld; *p;) {
      const char *end = strchr(p, ':');
      size_t len = end ? (size_t)(end - p) : strlen(p);
      if (len == strlen(shim) && !strncmp(p, shim, len)) ++count;
      if (!end) break;
      p = end + 1;
    }
    if (count != 1 || strncmp(dyld, shim, strlen(shim)) ||
        dyld[strlen(shim)] != ':') return 13;
    const char *first = strstr(dyld, "extra0.dylib");
    const char *second = strstr(dyld, "extra1.dylib");
    if (!first || !second || first >= second) return 22;
    int fd = open(argv[4], O_RDONLY);
    char buf[32] = {0};
    if (fd < 0 || read(fd, buf, sizeof buf) != 13 || close(fd) ||
        strcmp(buf, "preload-input")) return 14;
    puts("extra-libraries-and-read-ok");
    return 0;
  }
  /* Only the child requests the extra libraries, so it cannot inherit their
     symbols from the parent's image. They must really survive propagation. */
  if (setsid() < 0) return 23;
  if (dlsym(RTLD_DEFAULT, "io_mon_extra_0") ||
      dlsym(RTLD_DEFAULT, "io_mon_extra_1")) return 15;
  if (setenv("DYLD_INSERT_LIBRARIES", argv[2], 1)) return 16;
  char *args[] = {argv[0], "child", argv[2], argv[3], argv[4], NULL};
  if (!strcmp(argv[1], "exec")) {
    execve(argv[0], args, environ);
    return 17;
  }
  posix_spawnattr_t attr;
  if (posix_spawnattr_init(&attr)) return 18;
  if (!strcmp(argv[1], "setexec") &&
      posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC)) return 19;
  pid_t pid;
  int result = posix_spawn(&pid, argv[0], NULL, &attr, args, environ);
  posix_spawnattr_destroy(&attr);
  if (result) return 20;
  int status;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return 21;
  return WEXITSTATUS(status);
}
""")
    compile(source, probe, "-O0")
    let shim = buildPrivateMacosShim(root)
    for backend in ["both", "interpose"]:
      for mode in ["spawn", "setexec", "exec"]:
        test "requested dylibs survive " & mode & " with " & backend:
          for i, libraries in [shim & ":" & libs.join(":"),
              libs.join(":") & ":" & shim, libs.join(":"),
              shim & ":" & libs[0] & ":" & shim & ":" & libs[1]]:
            let fragments = work / (backend & "-" & mode & "-" & $i)
            createDir(fragments)
            var env = newStringTable(modeCaseSensitive)
            for k, v in envPairs():
              if not k.startsWith("REPRO_MONITOR_") and
                  k notin ["DYLD_INSERT_LIBRARIES", "CT_SANDBOX_TOOLS_DIR"]:
                env[k] = v
            env["DYLD_INSERT_LIBRARIES"] = shim
            env["REPRO_MONITOR_SHIM_LIB"] = shim
            env["REPRO_MONITOR_FRAGMENT_DIR"] = fragments
            env["REPRO_MONITOR_SESSION"] = "preload-libraries"
            applyMacosBackendToggle(env, backend)
            let child = startProcess(probe,
              args = @[mode, libraries, shim, input], env = env,
              options = {poStdErrToStdOut})
            let pid = uint64(child.processID)
            let code = child.waitForExit(15_000)
            if code == -1:
              if getpgid(Pid(pid)) == Pid(pid):
                discard posix.kill(Pid(-int(pid)), SIGKILL)
              else:
                child.kill()
              discard child.waitForExit()
            let output = child.outputStream.readAll()
            child.close()
            checkpoint("libraries=" & libraries & " exit=" & $code & " " & output)
            check code == 0
            check "extra-libraries-and-read-ok" in output
            let dep = mergeFragments(fragments, fragments & ".iomon",
              currentRunId = "preload-libraries", expectedRootPid = pid)
            check dep.records.anyIt(it.kind == mrFileRead and it.path == input)
            check dep.completeness == mcComplete
  else:
    test "macOS-only library propagation":
      skip()
