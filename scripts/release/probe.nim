## A real file reader/writer for testing the extracted monitor and shim. No mocks.
import std/os
when defined(linux):
  {.passL: "-ldl".}
  {.emit: """
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
static int release_stat_probe(const char *input, const char *link) {
  struct stat st;
  /* The plain-child control can have no exported stat on old glibc. Under
   * LD_PRELOAD these resolve to the shim's public wrappers, exercising the
   * real old-libc forwarding path without replacing or mocking a function. */
  int (*s)(const char *, struct stat *) = dlsym(RTLD_DEFAULT, "stat");
  int (*ls)(const char *, struct stat *) = dlsym(RTLD_DEFAULT, "lstat");
  if (!s || !ls) return 0;
  if (s(input, &st) || !S_ISREG(st.st_mode) || st.st_size != 13) return 41;
  if (ls(input, &st) || !S_ISREG(st.st_mode)) return 42;
  if (symlink(input, link)) return 43;
  int result = 0;
  if (s(link, &st) || !S_ISREG(st.st_mode) || st.st_size != 13) result = 44;
  if (ls(link, &st) || !S_ISLNK(st.st_mode)) result = 45;
  if (unlink(link)) return 46;
  errno = 0;
  if (s(link, &st) != -1 || errno != ENOENT) return 47;
  errno = 0;
  if (ls(link, &st) != -1 || errno != ENOENT) return 48;
  return result;
}
""".}
  proc statProbe(input, link: cstring): cint {.importc: "release_stat_probe", nodecl.}
let args = commandLineParams()
when defined(linux):
  let result = statProbe(args[0].cstring, (args[1] & ".link").cstring)
  if result != 0: quit(result)
writeFile(args[1], readFile(args[0]) & "-captured")
quit(7)
