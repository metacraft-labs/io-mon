## Windows tree-lifetime guard: the Job Object primitives.
##
## Root exit does not prove that a monitored tree has exited: a detached
## descendant can outlive the root and keep reading and writing files after the
## evidence is merged (io-mon-Lossless-Event-Capture §4.1). On Windows the
## kernel tracks that membership for us. A process created by a job member joins
## the job (and every job above it) at creation, so a job that the ROOT joins
## before it executes anything, and that refuses breakaway, contains every
## process the tree will ever create. Its active-process count reaching zero
## after the root has exited therefore proves the tree is empty.
##
## Normative design: `reprobuild-pm/spec/io-mon-Windows-Tree-Lifetime-Guard.md`
## (WG-1..WG-11, failure modes F1..F9). User contract: `docs/usage.md`, "The
## Windows tree-lifetime guard (normative)".
##
## This module holds ONLY the Win32 mechanics: create and verify the job, read
## its census, name its members. The DECISIONS — when the guard runs, how long
## it waits, what a failure means for the capture — live in `fs_snoop`'s
## private `settleMonitorDescendants`, inside the single evidence funnel
## (IoMon-Decomposed-Host-API DH-3). Nothing here can promote a capture: every
## proc reports a fact, and the caller fails closed on anything but a measured
## zero.
##
## Microsoft documentation this follows:
##  * Job Objects —
##    https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
##  * Nested jobs (a job nests under the root's inherited job, Windows 8+) —
##    https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs
##  * CreateJobObjectW —
##    https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw
##  * QueryInformationJobObject —
##    https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject
##  * JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (ActiveProcesses) —
##    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information
##  * JOBOBJECT_BASIC_LIMIT_INFORMATION (the breakaway limit flags) —
##    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
##  * JOBOBJECT_BASIC_PROCESS_ID_LIST —
##    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_process_id_list
##  * CREATE_BREAKAWAY_FROM_JOB —
##    https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags

when not defined(windows):
  {.error: "io_mon/windows_job_guard is Windows-only".}

import std/[monotimes, os, strutils, times, widestrs]
from stackable_hooks/windows_injector import RootJobMembership

type
  HANDLE = pointer
  DWORD = uint32
  BOOL = int32

  JobBasicAccountingInformation {.bycopy.} = object
    ## JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (class 1).
    totalUserTime: int64
    totalKernelTime: int64
    thisPeriodTotalUserTime: int64
    thisPeriodTotalKernelTime: int64
    totalPageFaultCount: DWORD
    totalProcesses: DWORD
    activeProcesses: DWORD
    totalTerminatedProcesses: DWORD

  JobBasicLimitInformation {.bycopy.} = object
    ## JOBOBJECT_BASIC_LIMIT_INFORMATION. `uint` is SIZE_T / ULONG_PTR.
    perProcessUserTimeLimit: int64
    perJobUserTimeLimit: int64
    limitFlags: DWORD
    minimumWorkingSetSize: uint
    maximumWorkingSetSize: uint
    activeProcessLimit: DWORD
    affinity: uint
    priorityClass: DWORD
    schedulingClass: DWORD

  JobIoCounters {.bycopy.} = object
    readOperationCount, writeOperationCount, otherOperationCount: uint64
    readTransferCount, writeTransferCount, otherTransferCount: uint64

  JobExtendedLimitInformation {.bycopy.} = object
    ## JOBOBJECT_EXTENDED_LIMIT_INFORMATION (class 9). The breakaway flags are
    ## "extended" limits, so they are read through this class.
    basicLimitInformation: JobBasicLimitInformation
    ioInfo: JobIoCounters
    processMemoryLimit: uint
    jobMemoryLimit: uint
    peakProcessMemoryUsed: uint
    peakJobMemoryUsed: uint

const
  JobObjectBasicAccountingInformation = 1'i32
  JobObjectBasicProcessIdList = 3'i32
  JobObjectExtendedLimitInformation = 9'i32
  JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800'u32
  JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000'u32
  BreakawayLimitFlags =
    JOB_OBJECT_LIMIT_BREAKAWAY_OK or JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
  ERROR_MORE_DATA = 234'u32
  PROCESS_QUERY_LIMITED_INFORMATION = 0x1000'u32
  ## The JOBOBJECT_BASIC_PROCESS_ID_LIST header: two DWORD counts, then the
  ## ULONG_PTR array. 8 header bytes are one ULONG_PTR slot on x64 and two on
  ## x86, so the list is read as `uint` slots and the ids start after
  ## `PidListHeaderSlots` of them.
  PidListHeaderBytes = 2 * sizeof(DWORD)
  PidListHeaderSlots = PidListHeaderBytes div sizeof(uint)
  PidListInitialCapacity = 64
  ## A hard bound on the growth loop. A job with this many members at the end
  ## of the grace window is already a loss; the cap only stops a pathological
  ## fork storm from making the diagnostic itself unbounded.
  PidListMaxCapacity = 1 shl 16

proc CreateJobObjectW(lpJobAttributes: pointer; lpName: ptr uint16): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc QueryInformationJobObject(hJob: HANDLE; infoClass: int32;
    info: pointer; infoLength: DWORD; returnLength: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetLastError(): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc OpenProcess(desiredAccess: DWORD; inheritHandle: BOOL;
    processId: DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc QueryFullProcessImageNameW(hProcess: HANDLE; flags: DWORD;
    exeName: ptr uint16; size: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc IsProcessInJob(processHandle, jobHandle: HANDLE; result: ptr BOOL): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

when defined(ioMonWindowsJobGuardFaultTest):
  # TEST SEAM — compiled ONLY under `-d:ioMonWindowsJobGuardFaultTest`, so it
  # does not exist in any shipped artefact (the rule in tests/windows/README.md
  # for fault-injection switches). F1, F2, F3 and F7 have no honest trigger on
  # a healthy host. The seam does not FAKE a failure: it makes the REAL Win32
  # call fail by handing it a real bad argument, so the diagnostic carries the
  # error code Windows actually returned. Every fault can only make the guard
  # fail, i.e. make a capture LESS complete; none can produce a clean grade.
  proc CreateEventW(attrs: pointer; manualReset, initialState: BOOL;
      name: ptr uint16): HANDLE
    {.importc, stdcall, dynlib: "kernel32".}
  proc SetInformationJobObject(hJob: HANDLE; infoClass: int32;
      info: pointer; infoLength: DWORD): BOOL
    {.importc, stdcall, dynlib: "kernel32".}

  proc injectedFault(): string =
    getEnv("IO_MON_TEST_WINDOWS_JOB_FAULT")

type
  TreeJob* = object
    ## The job a monitored root is assigned to. Owned by one `MonitorHandle`
    ## and closed by `closeTreeJob`.
    handle*: pointer
      ## The job handle, or nil when none could be established.
    failure*: string
      ## Why no usable job exists (spec F1..F3), without the `run=` token;
      ## empty when `handle` is usable.

  JobQuiescence* = object
    ## The outcome of `waitForTreeJobQuiescence`. `quiesced` is the ONLY
    ## outcome a caller may grade complete on.
    quiesced*: bool
    lossDetail*: string
      ## The loss to record when `quiesced` is false (spec F7 or F9), without
      ## the `run=` token.

proc openTreeJob*(): TreeJob =
  ## Create a fresh, unnamed, non-inheritable job (WG-1) and verify it refuses
  ## breakaway (WG-2). Never raises: a job that cannot be established is a
  ## reported `failure`, which the caller turns into a loss — the command
  ## itself still runs.
  ##
  ## The verification is not configuration. A fresh job has no limits, so the
  ## check can only fail if something set them; it is here so that a later
  ## change which configures the job cannot silently re-open breakaway, which
  ## would turn every proof this guard makes into a non-proof.
  var name: ptr uint16 = nil
  when defined(ioMonWindowsJobGuardFaultTest):
    # F1: an existing EVENT with the job's name makes CreateJobObjectW fail
    # with ERROR_INVALID_HANDLE — a real refusal from the real API.
    var collision: HANDLE = nil
    var nameW: seq[uint16]
    if injectedFault() == "create":
      for c in "Local\\io-mon-job-guard-fault-" & $getCurrentProcessId():
        nameW.add uint16(ord(c))
      nameW.add 0'u16
      name = addr nameW[0]
      collision = CreateEventW(nil, 1, 0, name)
    defer:
      if collision != nil:
        discard CloseHandle(collision)
  let job = CreateJobObjectW(nil, name)
  if job == nil:
    return TreeJob(failure: "windows tree-lifetime guard unavailable: " &
      "CreateJobObjectW failed err=" & $GetLastError())
  when defined(ioMonWindowsJobGuardFaultTest):
    if injectedFault() == "breakaway":
      # F3: really set the breakaway limit, so the verification below reads it
      # back from the kernel.
      var permissive: JobExtendedLimitInformation
      permissive.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK
      discard SetInformationJobObject(job, JobObjectExtendedLimitInformation,
        addr permissive, DWORD(sizeof(permissive)))
  var limits: JobExtendedLimitInformation
  var limitsLength = DWORD(sizeof(limits))
  when defined(ioMonWindowsJobGuardFaultTest):
    # F2: a buffer length the API rejects (ERROR_BAD_LENGTH).
    if injectedFault() == "verify-query":
      limitsLength = DWORD(sizeof(limits) - 1)
  if QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
      addr limits, limitsLength, nil) == 0:
    let err = GetLastError()
    discard CloseHandle(job)
    return TreeJob(failure: "windows tree-lifetime guard unavailable: " &
      "QueryInformationJobObject(JobObjectExtendedLimitInformation) failed " &
      "err=" & $err)
  let flags = limits.basicLimitInformation.limitFlags
  if (flags and BreakawayLimitFlags) != 0:
    discard CloseHandle(job)
    return TreeJob(failure: "windows tree-lifetime guard unavailable: " &
      "fresh job permits breakaway limit-flags=0x" & toHex(flags, 8))
  TreeJob(handle: job)

proc closeTreeJob*(job: var TreeJob) =
  ## Release the job handle. Idempotent. Does NOT terminate members: there is
  ## no JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so a descendant still alive keeps
  ## running in the (now unnamed, unreferenced) job, exactly as a Linux
  ## descendant keeps running after the scan (spec WG-8).
  if job.handle != nil:
    discard CloseHandle(job.handle)
    job.handle = nil

proc assignmentFailure*(error: uint32; membership: RootJobMembership): string =
  ## The F4/F5/F6 diagnostic for a root the launcher could not assign. Kept
  ## here, next to the guard's other diagnostics, so the vocabulary has one
  ## owner.
  case membership
  of rjmInJob:
    "windows tree-lifetime guard unavailable: the root already belongs to a " &
      "job that refused nesting (AssignProcessToJobObject err=" & $error & ")"
  of rjmNotInJob:
    "windows tree-lifetime guard unavailable: AssignProcessToJobObject " &
      "failed err=" & $error
  of rjmUnknown, rjmNotChecked:
    "windows tree-lifetime guard unavailable: AssignProcessToJobObject " &
      "failed err=" & $error & " root-job-membership=unknown"

proc activeProcesses(job: HANDLE; count: var int): uint32 =
  ## Read `ActiveProcesses`. Returns 0 on success, else the Win32 error.
  var info: JobBasicAccountingInformation
  var length = DWORD(sizeof(info))
  when defined(ioMonWindowsJobGuardFaultTest):
    # F7: a buffer length the API rejects (ERROR_BAD_LENGTH).
    if injectedFault() == "query":
      length = DWORD(sizeof(info) - 1)
  if QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
      addr info, length, nil) == 0:
    return GetLastError()
  count = int(info.activeProcesses)
  0

proc sanitizeToken(s: string): string =
  ## Keep a detail token one token: no whitespace, and no `,` or `=` that
  ## would read as a list separator or a second key.
  result = newStringOfCap(s.len)
  for c in s:
    result.add(if c in Whitespace or c in {',', '='}: '_' else: c)

proc memberImage(job: HANDLE; pid: uint64): string =
  ## The image base name of member `pid`, or `unknown` / `exited`. Membership
  ## is re-checked on the opened handle so a pid recycled between the list
  ## query and the open is not mis-named as a member.
  let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, DWORD(pid))
  if process == nil:
    return "unknown"
  defer: discard CloseHandle(process)
  var member: BOOL = 0
  if IsProcessInJob(process, job, addr member) == 0:
    return "unknown"
  if member == 0:
    return "exited"
  var buf: array[1024, uint16]
  var size = DWORD(buf.len - 1)   # in characters, terminator excluded
  if QueryFullProcessImageNameW(process, 0, addr buf[0], addr size) == 0 or
      size == 0:
    return "unknown"
  buf[min(int(size), buf.high)] = 0
  let path = $cast[WideCString](addr buf[0])
  let name = extractFilename(path.replace('\\', '/'))
  if name.len == 0: "unknown" else: sanitizeToken(name)

proc describeMembers(job: HANDLE): string =
  ## `pids=<p,...> images=<i,...>` for the job's current members (spec WG-7),
  ## or `pids=unavailable pid-list-err=<n>` when the list cannot be read.
  var capacity = PidListInitialCapacity
  while true:
    var buf = newSeq[uint](PidListHeaderSlots + capacity)
    let bytes = DWORD(PidListHeaderBytes + capacity * sizeof(uint))
    if QueryInformationJobObject(job, JobObjectBasicProcessIdList,
        addr buf[0], bytes, nil) == 0:
      let err = GetLastError()
      if err == ERROR_MORE_DATA and capacity < PidListMaxCapacity:
        capacity *= 4
        continue
      return "pids=unavailable pid-list-err=" & $err
    let header = cast[ptr array[2, DWORD]](addr buf[0])
    let listed = min(int(header[1]), capacity)
    var pids, images: seq[string]
    for i in 0 ..< listed:
      let pid = uint64(buf[PidListHeaderSlots + i])
      pids.add $pid
      images.add memberImage(job, pid)
    if pids.len == 0:
      # Every member exited between the count and the list. Still a loss: the
      # count was non-zero when the window closed.
      return "pids=none-listed"
    return "pids=" & pids.join(",") & " images=" & images.join(",")

proc waitForTreeJobQuiescence*(job: pointer; graceMs, pollMs: int):
    JobQuiescence =
  ## WG-5/WG-6/WG-7: after the root has exited, poll `ActiveProcesses` until it
  ## reads 0 or the grace window ends. The first query is immediate.
  ##
  ## The COUNT is the proof, not `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`: Microsoft
  ## documents that job completion-port messages "are intended only as
  ## notifications and their delivery to the completion port is not
  ## guaranteed" (JOBOBJECT_ASSOCIATE_COMPLETION_PORT), and a proof cannot rest
  ## on a message that may not arrive. Measured on Windows 11 26200: the count
  ## drops when a member terminates, even while a handle to it stays open.
  let start = getMonoTime()
  while true:
    var active = 0
    let err = activeProcesses(job, active)
    if err != 0:
      return JobQuiescence(lossDetail: "windows tree-lifetime guard failed: " &
        "QueryInformationJobObject(JobObjectBasicAccountingInformation) " &
        "failed err=" & $err)
    if active == 0:
      return JobQuiescence(quiesced: true)
    let elapsedMs = int(inMilliseconds(getMonoTime() - start))
    if elapsedMs >= graceMs:
      return JobQuiescence(lossDetail:
        "windows job descendants still live after root exit active=" &
          $active & " " & describeMembers(job))
    sleep(min(pollMs, graceMs - elapsedMs))
