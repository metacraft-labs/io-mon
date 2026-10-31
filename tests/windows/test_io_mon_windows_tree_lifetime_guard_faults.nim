## test_io_mon_windows_tree_lifetime_guard_faults — the guard's failure modes
## that have no honest trigger on a healthy host.
##
## reprobuild-pm spec/io-mon-Windows-Tree-Lifetime-Guard.md §3 requires every
## way the Windows tree-lifetime guard can fail to FAIL CLOSED with its own
## diagnostic: never silently complete, and never the old blanket marker. F4
## (an inherited job that cannot nest) is provoked for real in
## test_io_mon_windows_tree_lifetime_guard.nim. These four are not:
##
##   F1  CreateJobObjectW fails;
##   F2  the job's limit query fails;
##   F3  the fresh job permits breakaway;
##   F7  the active-process census fails while waiting.
##
## THE SEAM, AND WHY IT IS JUSTIFIED. A healthy Windows 10/11 host does not fail
## to create an unnamed job, and does not fail to query one this process just
## created with full access. There is no outside lever. So this file is
## compiled with `-d:ioMonWindowsJobGuardFaultTest` (the sibling `.nims` sets
## it, for this binary only), which compiles a seam into
## `io_mon/windows_job_guard` that reads `IO_MON_TEST_WINDOWS_JOB_FAULT`.
## The seam does not fabricate a result: it makes the REAL Win32 call fail by
## handing it a real bad argument (a job name that collides with an existing
## event, a buffer one byte short), or, for F3, really sets the breakaway
## limit on the real job. So the diagnostics carry the error codes Windows
## actually returned. It can only make the guard fail, never succeed, and it
## does not exist in any shipped artefact (tests/windows/README.md's rule for
## fault-injection switches).
##
## Each case runs a real monitored root that writes a real file, and asserts:
## the command ran (exit 0, file present), the capture is `mcIncomplete`, the
## ONLY loss is the case's own specific diagnostic, and neither the retired
## blanket marker nor any other guard diagnostic appears.

when not defined(windows):
  {.error: "windows-only test".}
when not defined(ioMonWindowsJobGuardFaultTest):
  {.error: "compile with -d:ioMonWindowsJobGuardFaultTest (the sibling .nims)".}

import std/[os, sequtils, strutils, tempfiles, unittest]

import io_mon

const
  WriterArg = "--guard-fault-writer"
  FaultVar = "IO_MON_TEST_WINDOWS_JOB_FAULT"

if paramCount() == 2 and paramStr(1) == WriterArg:
  writeFile(paramStr(2), "written")
  quit(0)

proc runWithFault(fault: string): tuple[res: MonitorResult; wrote: bool] =
  let dir = createTempDir("io-mon-guard-fault-", "")
  defer: removeDir(dir)
  putEnv(FaultVar, fault)
  try:
    result.res = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), WriterArg, dir / "out.txt"],
      depFilePath: dir / "evidence.iomon"))
  finally:
    delEnv(FaultVar)
  result.wrote = fileExists(dir / "out.txt")

proc losses(res: MonitorResult): seq[string] =
  for r in res.records:
    if r.kind == mrEventLoss: result.add r.detail

template expectOnlyLoss(fault, expectedPrefix: string) =
  let (res, wrote) = runWithFault(fault)
  let found = res.losses
  checkpoint fault & " -> " & $found
  check res.exitCode == 0
  check wrote                              # the command still did its work
  check res.completeness == mcIncomplete   # ...and the capture fails closed
  check found.len == 1
  if found.len == 1:
    check found[0].startsWith(expectedPrefix)
    check " run=" in found[0]
  check found.allIt("no complete tree-lifetime guard" notin it)

suite "Windows tree-lifetime guard failure modes (fault seam)":
  test "the seam is inert without a fault: the same run is complete":
    # The positive control. Without it, every case below could pass because
    # the seam build is simply broken.
    let (res, wrote) = runWithFault("")
    check res.exitCode == 0
    check wrote
    check res.completeness == mcComplete
    check res.losses.len == 0

  test "F1: CreateJobObjectW fails":
    expectOnlyLoss("create", "windows tree-lifetime guard unavailable: " &
      "CreateJobObjectW failed err=6 ")   # ERROR_INVALID_HANDLE

  test "F2: the limit query fails":
    expectOnlyLoss("verify-query", "windows tree-lifetime guard unavailable: " &
      "QueryInformationJobObject(JobObjectExtendedLimitInformation) failed " &
      "err=24 ")                          # ERROR_BAD_LENGTH

  test "F3: a job that permits breakaway is refused":
    expectOnlyLoss("breakaway", "windows tree-lifetime guard unavailable: " &
      "fresh job permits breakaway limit-flags=0x00000800 ")

  test "F7: the active-process census fails":
    expectOnlyLoss("query", "windows tree-lifetime guard failed: " &
      "QueryInformationJobObject(JobObjectBasicAccountingInformation) " &
      "failed err=24 ")
