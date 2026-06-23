## Path helpers vendored into io-mon.
##
## io-mon is a standalone relocation of reprobuild's `repro_monitor_depfile`
## fs-snoop stack. The original sources reached into `repro_core/paths` for the
## single `extendedPath` helper below. To keep io-mon free of any dependency on
## reprobuild, that one proc is vendored here verbatim. (See io-mon's README for
## the relocation rationale and the one-way dependency relationship.)

import std/[strutils]
from std/os import absolutePath

proc extendedPath*(path: string): string =
  ## On Windows, rewrites a path into the `\\?\` extended-length form so
  ## file-system calls bypass the 260-character `MAX_PATH` limit. Returns
  ## `path` unchanged on non-Windows platforms, for the empty string, and
  ## for paths already in `\\?\` / `\\.\` / UNC (`\\`) form.
  ##
  ## Apply this only where a path is handed to a file-system call; never
  ## store, compare, log, or pass it to a child process, because `\\?\`
  ## paths do not compare equal to (and are not understood the same way
  ## as) the ordinary form.
  ##
  ## The body collapses any internal `\\` that results from joining a
  ## directory ending in `\\` with a path component beginning with `/`
  ## (a common quirk on Windows when `~` resolves to `C:\Users\X\` and
  ## the relative path uses forward slashes). The `\\?\` namespace is
  ## strict-canonical — Windows rejects paths with `\\` mid-segment —
  ## so this collapse is mandatory, not cosmetic.
  when defined(windows):
    if path.len == 0 or path.startsWith("\\\\"):
      path
    else:
      var canonical = absolutePath(path).replace('/', '\\')
      while "\\\\" in canonical:
        canonical = canonical.replace("\\\\", "\\")
      "\\\\?\\" & canonical
  else:
    path
