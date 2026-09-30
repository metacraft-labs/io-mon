## Real filesystem cleanup after all fixture children have exited; no mocks.
## Windows ARM's translation cache can retain finished x64 images briefly.
## Retry removal only on Windows, and keep persistent cleanup failures fatal.
import std/os
when defined(windows):
  import std/[monotimes, times]

proc removeFixtureTree*(path: string) =
  when defined(windows):
    let deadline = getMonoTime() + initDuration(seconds = 30)
    while true:
      try:
        removeDir(path)
        return
      except OSError:
        if getMonoTime() >= deadline:
          raise
        sleep(25)
  else:
    removeDir(path)
