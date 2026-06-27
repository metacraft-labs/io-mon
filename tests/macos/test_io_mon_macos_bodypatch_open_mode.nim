## test_io_mon_macos_bodypatch_open_mode — under the default (both mechanisms on),
## a libsystem-internal variadic `O_CREAT` open forwards its `mode` argument
## CORRECTLY, so files are created with the requested permissions and remain
## readable. This locks in the fix for the body-patch nimcache
## `Permission denied` defect.
##
## # The defect this guards against
##
## Apple's libsystem `open`/`open$NOCANCEL` are VARIADIC entries
## (`open(const char *, int, ...)`). On the arm64 Apple platform ABI EVERY
## variadic argument is passed on the STACK, never in an argument register (see
## Apple's "Writing ARM64 Code for Apple Platforms"). A caller that supplies
## `mode` — e.g. libsystem_c's `fopen("…","w")`, which emits
## `movz w8,#0666; str x8,[sp]; bl open$NOCANCEL` — therefore puts `mode` on the
## stack, while register x2 holds an unrelated value.
##
## The body-patch mechanism overwrites the libsystem `open$NOCANCEL` ENTRY so that
## ALL callers (including shared-cache-internal ones like `fopen` that interpose
## never sees) branch to our hook. The previous defect registered the FIXED
## 3-arg `repro_hook_open(path, flags, mode)` there, which read `mode` from x2
## (garbage) and created `O_CREAT` files with a corrupt mode (e.g. `0404`
## instead of `0644`). A compiler's later read of its own just-written nimcache
## `.nim.c` then failed with EACCES. The fix routes the body-patch open/openat
## hooks through the SAME variadic `repro_wrap_open(at)` thunk the interpose
## tuples use, which reads `mode` via `va_arg` (stack-correct).
##
## # What this test asserts
##
## A probe `fopen(out,"w")`s a fresh file under the default (both mechanisms on),
## writes to it, closes it, then `stat`s the result. The test asserts:
##   * the probe exits 0 (the body-patch did not break the open), and
##   * the created file's mode is exactly the umask-default `0666 & ~umask`
##     (typically `0644`) — NOT a corrupt value — and the file is readable back.
## A direct (non-internal) `open(out2, O_CREAT|O_WRONLY, 0640)` probe is also
## checked to cover the explicit-mode path. macOS-only; no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, unittest]
from std/strutils import contains, strip, startsWith, splitLines

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

  proc buildShim(): string =
    ## Build the fat (arm64+arm64e) shim and return its path. Fails loudly.
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc compileModeProbe(work: string): string =
    ## Compile a tiny C program that exercises BOTH the libsystem-internal
    ## variadic O_CREAT open (via fopen, whose `open$NOCANCEL` takes `mode` on
    ## the stack) AND a direct explicit-mode open(2). It prints the resulting
    ## st_mode of each created file, write-then-reads them back to prove the file
    ## is usable, and exits nonzero on any failure so the harness can assert.
    let src = work / "open_mode_probe.c"
    writeFile(src, """
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* Create `path` via fopen("w") — a libsystem-internal variadic O_CREAT open
 * (mode 0666 passed on the stack), the exact shape that corrupted nimcache.
 * Write, close, stat, then reopen-read to confirm the file is usable. */
static int fopen_cycle(const char *path, unsigned *out_mode) {
  unlink(path);
  FILE *f = fopen(path, "w");
  if (!f) { fprintf(stderr, "fopen(%s) failed: %s\n", path, strerror(errno)); return 1; }
  if (fputs("payload\n", f) == EOF) { fprintf(stderr, "fputs failed\n"); fclose(f); return 1; }
  fclose(f);
  struct stat st;
  if (stat(path, &st) != 0) { fprintf(stderr, "stat(%s) failed: %s\n", path, strerror(errno)); return 1; }
  *out_mode = (unsigned)(st.st_mode & 07777);
  /* Prove the file is readable back (the EACCES the defect produced). */
  FILE *r = fopen(path, "r");
  if (!r) { fprintf(stderr, "reopen(%s) failed: %s\n", path, strerror(errno)); return 1; }
  char buf[64]; size_t n = fread(buf, 1, sizeof(buf) - 1, r); buf[n] = 0; fclose(r);
  if (strncmp(buf, "payload", 7) != 0) { fprintf(stderr, "readback mismatch\n"); return 1; }
  return 0;
}

/* Create `path` via a DIRECT open(2) with an explicit mode 0640 — the
 * explicit-mode path (mode also on the stack per the Apple variadic ABI). */
static int open_cycle(const char *path, unsigned *out_mode) {
  unlink(path);
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0640);
  if (fd < 0) { fprintf(stderr, "open(%s) failed: %s\n", path, strerror(errno)); return 1; }
  if (write(fd, "payload\n", 8) != 8) { fprintf(stderr, "write failed\n"); close(fd); return 1; }
  close(fd);
  struct stat st;
  if (stat(path, &st) != 0) { fprintf(stderr, "stat(%s) failed: %s\n", path, strerror(errno)); return 1; }
  *out_mode = (unsigned)(st.st_mode & 07777);
  int rfd = open(path, O_RDONLY);
  if (rfd < 0) { fprintf(stderr, "reopen(%s) failed: %s\n", path, strerror(errno)); return 1; }
  char buf[16]; ssize_t n = read(rfd, buf, sizeof(buf) - 1);
  if (n < 0) { fprintf(stderr, "read failed: %s\n", strerror(errno)); close(rfd); return 1; }
  close(rfd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: %s <fopen-out> <open-out>\n", argv[0]); return 2; }
  /* Deterministic umask so the expected fopen mode is exactly 0666 & ~022. */
  umask(022);
  unsigned fmode = 0, omode = 0;
  if (fopen_cycle(argv[1], &fmode) != 0) return 3;
  if (open_cycle(argv[2], &omode) != 0) return 4;
  /* Emit machine-readable lines for the harness. */
  printf("FOPEN_MODE=%o\n", fmode);
  printf("OPEN_MODE=%o\n", omode);
  return 0;
}
""")
    let bin = work / "open_mode_probe"
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "probe compile failed: " & output
    doAssert fileExists(bin)
    bin

  type ProbeResult = object
    exitCode: int
    fopenMode: string
    openMode: string
    output: string

  proc runProbe(shim, probe, backend, fopenOut, openOut: string): ProbeResult =
    ## Run the mode probe under the shim with the given backend and parse the
    ## reported st_mode of the two created files.
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    applyMacosBackendToggle(env, backend)
    let p = startProcess(probe, args = @[fopenOut, openOut], env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    result.exitCode = code
    result.output = outText
    for line in outText.splitLines():
      if line.startsWith("FOPEN_MODE="):
        result.fopenMode = line["FOPEN_MODE=".len .. ^1].strip()
      elif line.startsWith("OPEN_MODE="):
        result.openMode = line["OPEN_MODE=".len .. ^1].strip()

suite "io-mon macOS body-patch open mode (variadic O_CREAT forwarding)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-openmode-" & $getCurrentProcessId())
    createDir(work)
    let probe = compileModeProbe(work)
    let fopenOut = work / "via_fopen.txt"
    let openOut = work / "via_open.txt"

    test "body-patch ('both') forwards fopen's variadic mode correctly (0644)":
      # The keystone: fopen's libsystem-internal open$NOCANCEL is body-patched,
      # and the stack-passed mode 0666 must survive as 0644 (0666 & ~022), NOT a
      # corrupt value. This is the nimcache 'Permission denied' regression.
      let r = runProbe(shim, probe, "both", fopenOut, openOut)
      checkpoint("[both] exit=" & $r.exitCode & " output=" & r.output)
      check r.exitCode == 0
      check r.fopenMode == "644"
      check r.openMode == "640"
      check fileExists(fopenOut)
      # The created file must be readable back (the EACCES the defect produced).
      check readFile(fopenOut).contains("payload")

    test "interpose backend agrees on the mode (no regression on the legacy path)":
      let r = runProbe(shim, probe, "interpose", fopenOut, openOut)
      checkpoint("[interpose] exit=" & $r.exitCode & " output=" & r.output)
      check r.exitCode == 0
      check r.fopenMode == "644"
      check r.openMode == "640"

    test "bodypatch backend forwards the variadic mode correctly too":
      let r = runProbe(shim, probe, "bodypatch", fopenOut, openOut)
      checkpoint("[bodypatch] exit=" & $r.exitCode & " output=" & r.output)
      check r.exitCode == 0
      check r.fopenMode == "644"
      check r.openMode == "640"

    removeDir(work)
  else:
    test "body-patch open-mode forwarding is macOS-only (no-op on this platform)":
      check true
