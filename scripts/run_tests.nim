import std/[os, osproc, strutils, algorithm]

# The directories whose `test_*.nim` files the host should run.
var dirs = @["tests/portable"]
when defined(posix):
  dirs.add "tests/posix"
when defined(macosx):
  dirs.add "tests/macos"
when defined(linux):
  dirs.add "tests/linux"
when defined(windows):
  dirs.add "tests/windows"

let flags = "--path:../nim-stackable-hooks/src --path:tests/helpers"

for dir in dirs:
  if not dirExists(dir): continue
  var files: seq[string] = @[]
  for pc, f in walkDir(dir):
    if pc == pcFile or pc == pcLinkToFile:
      let name = f.extractFilename()
      if name.startsWith("test_") and name.endsWith(".nim"):
        files.add f
  files.sort()
  for f in files:
    echo "=== Running test: " & f & " ==="
    let cmd = "nim c -r " & flags & " " & f
    let exitCode = execCmd(cmd)
    if exitCode != 0:
      echo "=== Test failed: " & f & " ==="
      quit(exitCode)
