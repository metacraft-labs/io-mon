## A real file reader/writer for testing the extracted monitor and shim. No mocks.
import std/os
let args = commandLineParams()
writeFile(args[1], readFile(args[0]) & "-captured")
quit(7)
