## Probe program for `tests/linux/test_io_mon_foreign_preload_isolation.nim`.
##
## Built twice: with `-d:isolate` it imports `foreign_preload_isolation`
## first, exactly as a live test does; without it, it is the control that
## shows what a test sees when nothing isolates it.
##
## `foreign_preload_probe <name> [<keep>]` prints, for itself and for one child
## (itself, re-run with `child`), whether a library whose file name is `<name>`
## is mapped, whether one named `<keep>` is, its `LD_PRELOAD` and whether the
## isolation hop counter is still visible. The child is started the way an
## io-mon test starts a bare control: with `LD_PRELOAD` removed from the
## environment it is given.
when defined(isolate):
  import foreign_preload_isolation

import std/[os, osproc, strtabs, strutils]

proc mapped(name: string): int =
  if name.len == 0: return 0
  for line in readFile("/proc/self/maps").splitLines():
    let slash = line.find('/')
    if slash >= 0 and line[slash .. ^1].extractFilename == name:
      return 1
  0

proc report(role, name, keep: string) =
  echo role, " mapped=", mapped(name), " keep=", mapped(keep),
    " preload=[", getEnv("LD_PRELOAD"), "]",
    " hops=", (if existsEnv("IO_MON_TEST_FOREIGN_PRELOAD_HOPS"): "set" else: "unset")

let name = paramStr(1)
let keep = if paramCount() >= 2 and paramStr(2) != "child": paramStr(2) else: ""
if paramCount() >= 2 and paramStr(paramCount()) == "child":
  report("child", name, keep)
else:
  report("self", name, keep)
  stdout.flushFile()
  var env = newStringTable(modeCaseSensitive)
  for k, v in envPairs():
    if k != "LD_PRELOAD": env[k] = v
  var args = @[name]
  if keep.len > 0: args.add keep
  args.add "child"
  let p = startProcess(getAppFilename(), args = args, env = env,
    options = {poParentStreams})
  quit(p.waitForExit())
