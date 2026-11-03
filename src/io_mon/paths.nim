## Path helpers vendored into io-mon.
##
## io-mon is a standalone relocation of reprobuild's `repro_monitor_depfile`
## fs-snoop stack. The original sources reached into `repro_core/paths` for the
## single `extendedPath` helper below. To keep io-mon free of any dependency on
## reprobuild, that one proc is vendored here verbatim. (See io-mon's README for
## the relocation rationale and the one-way dependency relationship.)
##
## `anchoredRelativePath` and `startsWithParentRef` are io-mon's own: the
## pure join the Linux shim records relative paths with, kept here, free of
## any shim state, so it can be tested on every OS.

import std/[strutils]
from std/os import absolutePath, normalizedPath

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
      var canonical = normalizedPath(absolutePath(path)).replace('/', '\\')
      while "\\\\" in canonical:
        canonical = canonical.replace("\\\\", "\\")
      "\\\\?\\" & canonical
  else:
    path

proc startsWithParentRef*(relative: string): bool {.raises: [].} =
  ## Whether the first component of `relative` that is not `.` is `..`
  ## (`"../x"`, `"./../x"`, `".//.."`). A caller uses it to decide whether
  ## `anchoredRelativePath` will pop components off its anchor, and so
  ## whether that anchor has to be a symlink-free spelling.
  var i = 0
  while i < relative.len:
    while i < relative.len and relative[i] == '/':
      inc i
    let start = i
    while i < relative.len and relative[i] != '/':
      inc i
    let clen = i - start
    if clen == 1 and relative[start] == '.':
      continue
    return clen == 2 and relative[start] == '.' and relative[start + 1] == '.'
  false

proc anchoredRelativePath*(anchor, relative: string;
                           popLeadingParents = true): string {.raises: [].} =
  ## `relative` made absolute against the directory `anchor` names, the way
  ## the kernel resolves it, WITHOUT resolving any symlink. The Linux
  ## counterpart of the macOS shim's `repro_macos_anchored_path`
  ## (`hooks/macos_interpose_runtime.nim`), and the join `pathForAt` uses.
  ## Spec: reprobuild-pm/spec/Monitor-Hook-Shim.md § CWD And Path Context
  ## ("CWD tracking is required for relative path normalization") and
  ## § "Metadata, Probe, And Symlink APIs" ("Relative paths are walked as
  ## spelled: `..` after a link applies to where the link points, not to the
  ## text before it"; "Never pop a symlink component lexically").
  ##
  ## While joining, empty components (`//`) and `.` are squeezed out, and
  ## each LEADING `..` of `relative` removes one component of `anchor`
  ## (`..` at `/` stays at `/`, as the kernel does). That is exact only when
  ## `anchor` names a real directory with no symlink and no `..` in it --
  ## `getcwd`, or the kernel's `/proc/self/fd` name for a directory fd -- so
  ## a caller holding a spelling that may contain one passes
  ## `popLeadingParents = false`, and every `..` is then kept as spelled.
  ## Popping also needs an absolute anchor; a relative one keeps its `..`.
  ##
  ## A `..` that FOLLOWS a component of `relative` is always kept: in
  ## `link/../x` it applies to where `link` points, which only a resolution
  ## of the path (the realpath companion) may decide. Nim's `os./` folds it
  ## lexically, and recorded `<cwd>/x` for a process that read the file
  ## beside the link's target (reprobuild-pm issue 2026-10-21-linux-shim-
  ## folds-dotdot-after-a-symlink-lexically).
  ##
  ## `anchor` is used as spelled apart from its trailing slashes. A trailing
  ## slash on `relative` is kept (it asks for a directory, and `os./` kept
  ## it too). An absolute `relative` is returned unchanged: the anchor does
  ## not apply to it. The result is built in one buffer sized up front.
  if relative.len > 0 and relative[0] == '/':
    return relative
  result = newStringOfCap(anchor.len + relative.len + 1)
  result.add anchor
  while result.len > 1 and result[^1] == '/':
    result.setLen(result.len - 1)
  let absolute = result.len > 0 and result[0] == '/'
  if result == "/":
    # The root is rebuilt as "" while joining, so no "//" appears.
    result.setLen(0)
  var leading = popLeadingParents and absolute
  var i = 0
  while i < relative.len:
    while i < relative.len and relative[i] == '/':
      inc i
    if i >= relative.len:
      break
    let start = i
    while i < relative.len and relative[i] != '/':
      inc i
    let clen = i - start
    if clen == 1 and relative[start] == '.':
      continue
    if leading and clen == 2 and relative[start] == '.' and
        relative[start + 1] == '.':
      var n = result.len
      while n > 0 and result[n - 1] != '/':
        dec n
      if n > 0:
        dec n
      result.setLen(n)
      continue
    leading = false
    if result.len > 0 or absolute:
      result.add '/'
    for k in start ..< i:
      result.add relative[k]
  if result.len == 0:
    if absolute:
      result.add '/'
  elif relative.len > 0 and relative[^1] == '/':
    result.add '/'
