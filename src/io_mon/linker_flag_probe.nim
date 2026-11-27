## io_mon/linker_flag_probe.nim -- the one classification of a path token that
## is a linker flag, not a path.
##
## A linker is given `-lX` flags. When a tool probes for the library a flag
## names, it can open the flag's text itself as a relative path, `-lc` or
## `-lgcc_s`, in the directory it runs from. That open fails, and the failure is
## the linker looking, not the build reading an input. A repo-relative record of
## such a probe reaches the untracked-input judgement as a read of a file that
## does not exist, which withholds a certificate for nothing.
##
## So the capture drops a FAILED open of a bare relative `-l<name>` token at
## capture time. Nothing else is dropped: a failed open of a real path (any
## path containing a slash, or any token not starting with `-l`) is still
## recorded, and so is a successful open of a library file the linker resolved,
## which is an input the build must bind.
##
## Pure, with no imports: the shim calls it on the raw argument before any path
## resolution, and the portable test calls it on literal strings.

proc isLinkerFlagProbe*(token: string): bool =
  ## True for a bare relative token that names a library flag: `-l` followed
  ## by at least one character and no path separator, such as `-lc`,
  ## `-lgcc_s`, or `-l:libfoo.so`. False for an empty token, a bare `-l`,
  ## anything containing `/` or `\`, and any token that is not `-l`-prefixed.
  # Written out rather than with `startsWith`, so the module imports nothing.
  if token.len <= 2 or token[0] != '-' or token[1] != 'l':
    return false
  for ch in token:
    if ch == '/' or ch == '\\':
      return false
  true
