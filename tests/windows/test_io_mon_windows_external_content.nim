## `mcapExternalContent` on Windows: the content channels that are not file
## reads.
##
## M4 declared this a gap in one line -- "shared-memory, pipe and
## alternate-data-stream content channels are not covered" -- and each of those
## is a way for BYTES to reach a monitored program without a `ReadFile` the
## shim could see. A capture that misses them is not merely less detailed: the
## cache key omits an input, so the next build serves a stale result.
##
## Windows adds a fourth that POSIX does not have in the same form, and it is
## the one a real toolchain hits constantly: a MAPPED VIEW of a file. The bytes
## arrive by page fault, so no read hook anywhere can observe them. That is
## covered here as a genuine `moFileRead` on the underlying path, because
## recording it under any other observation kind would leave the dependency
## visible to inspection and absent from the cache key -- the same distinction
## M4 drew for library loads.
##
## The provenance half is tested in both directions on purpose. A channel a
## monitored process produced itself must NOT downgrade (a normal build makes
## pipes and sections constantly, and downgrading on them would re-run
## everything), while a channel fed from outside the tree MUST. A test that
## only checked one direction would pass against an implementation that always
## answered the same way.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop
import io_mon/types
import io_mon/writer

import windows_channel_fixture

runChannelFixtureIfRequested()

proc runFixture(dir: string; mode: string; arg = ""): MonitorResult =
  var command = @[getAppFilename(), ChannelFixtureFlag, mode]
  if arg.len > 0:
    command.add arg
  var request = FsSnoopRequest(
    command: command,
    depFilePath: dir / (mode & ".rdep"),
    captureChildStdio: true)
  runMonitored(request)

proc channelRecords(res: MonitorResult; chan, role: string):
    seq[MonitorRecord] =
  result = @[]
  for r in res.records:
    if r.kind == mrExternalContent and
        r.detail.contains("chan=" & chan) and r.detail.contains("role=" & role):
      result.add r

proc withTempDir(body: proc(dir: string)) =
  let dir = createTempDir("io_mon_m5_ext_", "")
  try:
    body(dir)
  finally:
    try: removeDir(dir)
    except CatchableError: discard

suite "Windows external content: mapped views of files":

  test "a mapped view is recorded as a READ of the file it maps":
    ## The bytes of a mapped file never pass ReadFile. Before this the whole
    ## access was invisible: a compiler that mmaps a header or an archive
    ## produced no record for it, and the capture still graded complete.
    withTempDir(proc(dir: string) =
      let path = dir / "mapped-input.bin"
      writeFile(path, "mapped-content-0123456789")
      let res = runFixture(dir, "map-file", path)
      check res.exitCode == 0
      var sawMappedRead = false
      for r in res.records:
        if r.kind == mrFileRead and r.detail.startsWith("MapViewOfFile") and
            r.path.toLowerAscii == path.toLowerAscii:
          # `moFileRead` is what makes the bytes part of the cache key rather
          # than a diagnostic.
          check r.observationKind == moFileRead
          sawMappedRead = true
      check sawMappedRead
      check res.completeness == mcComplete)

suite "Windows external content: shared memory":

  test "a section this process created and joined does not downgrade":
    withTempDir(proc(dir: string) =
      let name = "io-mon-m5-intree-" & $getCurrentProcessId()
      let res = runFixture(dir, "shm-inproc", name)
      check res.exitCode == 0
      check channelRecords(res, "shm", "create").len > 0
      check channelRecords(res, "shm", "attach").len > 0
      check externalContentLossCount(res.records) == 0
      check res.completeness == mcComplete)

  test "joining an OUT-OF-TREE section downgrades the capture":
    ## The section is created by this test process, which is not monitored, so
    ## the monitored child's attach has no in-tree create to pair against. Its
    ## contents are an input nothing in the capture describes.
    withTempDir(proc(dir: string) =
      let name = "io-mon-m5-outtree-" & $getCurrentProcessId()
      let section = namedSection(name)
      check section != nil
      defer: closeH(section)
      let res = runFixture(dir, "shm-open", name)
      check res.exitCode == 0
      let attaches = channelRecords(res, "shm", "attach")
      check attaches.len > 0
      var sawName = false
      for r in attaches:
        if r.path == name:
          sawName = true
      check sawName
      check channelRecords(res, "shm", "create").len == 0
      check externalContentLossCount(res.records) >= 1
      check res.completeness == mcIncomplete)

  test "CreateFileMapping over a name ALREADY OWNED out of tree is an attach":
    ## The branch that decides whether a section is an input, tested through the
    ## only call that can be either.
    ##
    ## `OpenFileMapping` can only ever join, so the case above pins nothing
    ## about the distinction. `CreateFileMapping` is the ambiguous one: given a
    ## name that already exists it does NOT fail -- it opens the existing
    ## section and reports ERROR_ALREADY_EXISTS. The same call is therefore both
    ## the producer and the consumer of a shared-memory channel, and the ONLY
    ## thing that tells them apart is that last-error.
    ##
    ## Get it wrong in the `create` direction and the failure is the cardinal
    ## sin rather than a missing detail: an out-of-tree producer's section is
    ## paired against the monitored process's own `role=create` record, nothing
    ## is left unpaired, `externalContentLossCount` stays 0, and the capture
    ## grades `mcComplete` over bytes that arrived from a process it never saw.
    ## Both existing shm cases pass in that state, because both only ever call
    ## `CreateFileMapping` on a FRESH name.
    ##
    ## The owner here is the test process, which is outside the monitored tree
    ## -- the same breakaway-daemon stand-in the rest of the file uses.
    withTempDir(proc(dir: string) =
      let name = "io-mon-m5-preowned-" & $getCurrentProcessId()
      let section = namedSection(name)
      check section != nil
      defer: closeH(section)
      let res = runFixture(dir, "shm-create-existing", name)
      # Non-zero means the section was NOT pre-owned when the child ran, so a
      # record assertion below would be passing for the wrong reason.
      check res.exitCode == 0
      let attaches = channelRecords(res, "shm", "attach")
      var sawName = false
      for r in attaches:
        if r.path == name:
          sawName = true
      check sawName
      for r in channelRecords(res, "shm", "create"):
        if r.path == name:
          checkpoint("a join of a pre-owned section was recorded as a " &
            "create: " & r.detail & " path=" & r.path)
          fail()
      check externalContentLossCount(res.records) >= 1
      check res.completeness == mcIncomplete)

suite "Windows external content: anonymous pipes":

  test "an in-tree pipe pairs its create against its read and does not downgrade":
    ## The pairing key cannot be the pipe's name: on Win11 a `CreatePipe` pair
    ## is UNNAMED (FileNameInfo returns a zero-length name and
    ## NtQueryObject answers STATUS_OBJECT_PATH_INVALID). It is the pair of
    ## pids the kernel WILL name for either end, which is identical in the
    ## producer and the consumer -- that is what makes the merge's
    ## create/read pairing work at all here.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "anon-pipe")
      check res.exitCode == 0
      let creates = channelRecords(res, "localfd", "create")
      let reads = channelRecords(res, "opaque", "read")
      check creates.len > 0
      check reads.len > 0
      # Same identity from both sides, which is the property the merge needs.
      var identities: seq[string] = @[]
      for r in creates:
        check r.path.startsWith("pipe:")
        identities.add r.path
      var pairedRead = false
      for r in reads:
        if r.path in identities:
          pairedRead = true
      check pairedRead
      check externalContentLossCount(res.records) == 0
      check res.completeness == mcComplete)

  test "an INHERITED pipe pairs across two processes on one identity":
    ## The case the in-process test above structurally cannot reach.
    ##
    ## `pipe:<server>:<client>` is claimed to be PROCESS-INDEPENDENT -- that is
    ## the entire reason it was chosen over the fd identity the POSIX arms use,
    ## since a Win11 `CreatePipe` pair is unnamed. When the create and the read
    ## happen in the same process, ANY key looks process-independent, including
    ## one with the caller's own pid baked into it. Only a create in one process
    ## and a read in another can tell them apart.
    ##
    ## The arrangement is also the real one: a launcher creates a pipe, marks an
    ## end inheritable, and spawns a client that reads it -- an inherited pipe
    ## has no `connect` for the IPC machinery to see and no open for the read
    ## hook to name, so the merge has nothing but this identity to pair on. Both
    ## processes are IN TREE here, so the correct answer is a paired read and
    ## `mcComplete`; an identity that differed per process would leave the read
    ## unpaired and downgrade an ordinary build.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "anon-pipe-inherit")
      check res.exitCode == 0
      let creates = channelRecords(res, "localfd", "create")
      let reads = channelRecords(res, "opaque", "read")
      check creates.len > 0
      check reads.len > 0
      # The two ends must be different PROCESSES, or this is the in-process
      # case again wearing a different name.
      var createPids: seq[uint64] = @[]
      var identities: seq[string] = @[]
      for r in creates:
        check r.path.startsWith("pipe:")
        identities.add r.path
        if r.osPid notin createPids:
          createPids.add r.osPid
      var pairedAcrossProcesses = false
      for r in reads:
        if r.path in identities and r.osPid notin createPids:
          pairedAcrossProcesses = true
      check pairedAcrossProcesses
      check externalContentLossCount(res.records) == 0
      check res.completeness == mcComplete)

suite "Windows external content: alternate data streams":

  test "a stream access is classified AND its bytes stay in the read record":
    ## `CreateFileW` always saw `file:stream`; nothing classified it. The
    ## classification is what makes the channel identifiable; the ordinary read
    ## record on the full `file:stream` path is what makes its bytes a
    ## dependency. Both must be present -- the classification alone would be a
    ## diagnostic, and the read alone leaves the channel invisible.
    withTempDir(proc(dir: string) =
      let path = dir / "with-stream.txt"
      writeFile(path, "primary stream")
      let res = runFixture(dir, "ads", path)
      check res.exitCode == 0
      let stream = (path & ":io-mon-m5").toLowerAscii
      var sawAdsWrite = false
      var sawAdsRead = false
      for r in channelRecords(res, "ads", "write"):
        if r.path.toLowerAscii == stream:
          sawAdsWrite = true
      for r in channelRecords(res, "ads", "read"):
        if r.path.toLowerAscii == stream:
          sawAdsRead = true
      check sawAdsWrite
      check sawAdsRead
      var sawStreamOpen = false
      for r in res.records:
        if r.kind in {mrFileOpen, mrFileRead, mrFileWrite} and
            r.path.toLowerAscii == stream:
          sawStreamOpen = true
      check sawStreamOpen
      # An ADS is content on a path the capture already fingerprints, so it is
      # deliberately NOT one of the roles the merge downgrades on.
      check externalContentLossCount(res.records) == 0
      check res.completeness == mcComplete)

suite "Windows external content: what must NOT be classified":

  test "an ordinary file read produces no external-content record":
    ## Over-classification is not a harmless surplus: `chan=shm role=attach`
    ## and `chan=opaque role=read` are downgrade signals, so a rule that fired
    ## on ordinary paths would make every build a conservative re-run.
    withTempDir(proc(dir: string) =
      let path = dir / "ordinary.bin"
      writeFile(path, "no streams, no sections, no pipes")
      let res = runFixture(dir, "map-file", path)
      check res.exitCode == 0
      for r in res.records:
        if r.kind == mrExternalContent:
          checkpoint("unexpected external-content record: " & r.detail &
            " path=" & r.path)
          fail()
      check res.completeness == mcComplete)
