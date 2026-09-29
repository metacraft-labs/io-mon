## Real Darwin loader control, with no mocks and no io-mon implementation.
## A benign constructor records executable names through each fixture's actual
## launch path. This determines whether the OS permits DYLD injection without
## deriving the expected result from the monitor under test.

import std/[os, osproc, streams, strtabs, strutils]

proc injectedImages*(probe: string; args: seq[string] = @[]): seq[string] =
  let work = probe.parentDir() / "loader-control"
  createDir(work)
  let source = work / "probe.c"
  let dylib = work / "probe.dylib"
  let evidence = work / "images.txt"
  writeFile(source, """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void record_image(void) {
  const char *path = getenv("IO_MON_LOADER_CONTROL_FILE");
  if (!path) _exit(91);
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) _exit(92);
  char line[1024];
  int n = snprintf(line, sizeof(line), "%s\n", getprogname());
  if (n <= 0 || n >= sizeof(line) || write(fd, line, n) != n) _exit(93);
  close(fd);
}
""")
  let (output, code) = execCmdEx(quoteShell(getEnv("CC", "cc")) &
    " -dynamiclib " & quoteShell(source) & " -o " & quoteShell(dylib))
  doAssert code == 0, "loader control compilation failed: " & output
  removeFile(evidence)
  var env = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): env[k] = v
  env.del("CT_SANDBOX_TOOLS_DIR")
  env.del("REPRO_MONITOR_SHIM_LIB")
  env["DYLD_INSERT_LIBRARIES"] = dylib
  env["IO_MON_LOADER_CONTROL_FILE"] = evidence
  let child = startProcess(probe, args = args, env = env,
    options = {poStdErrToStdOut})
  let childOutput = child.outputStream.readAll()
  let childCode = child.waitForExit()
  child.close()
  doAssert childCode == 0, "loader control failed: " & childOutput
  doAssert fileExists(evidence), "loader control did not load in the parent"
  result = readFile(evidence).strip().splitLines()
  doAssert probe.extractFilename() in result,
    "loader control is missing its parent marker: " & $result
  echo "  independent loader control: ", probe, " ", args, " -> ", result
