## test_io_mon_observer_attribution_contract — which records name the process
## that made the observation, and does the published reference say so?
##
## THE DEFECT THIS FILE CLOSES (io-mon issue
## `2026-11-09-linux-file-reads-are-recorded-without-the-reading-process.md`).
## On the Linux set transport every `mrFileOpen`, `mrFileRead`, `mrPathProbe`
## and `mrDirectoryEnumerate` record arrives with `osPid = 0`: the dedup key
## (`dep_queue.encodeDepRecordIdentity`) zeroes the observer so that one path
## read by thousands of processes is one set element, and `decodeDepRecord`
## rebuilds the record from that key. The trade-off is deliberate. The
## published reference denied it: `reference/depfile-format.md` listed `osPid`
## as a key field of all four kinds, and `getting_started/overview.md` said
## "Every event records the exact originating `osPid`". A consumer reading the
## reference would expect attribution it can never get on Linux.
##
## So this file holds two things together, and the second is what was red:
##
##   1. THE BEHAVIOUR, per record kind and per transport, measured through the
##      real encoders: the set element (`writer.encodeDepSetElement` →
##      `decodeDepRecord`, the Linux default) and the merge fold every
##      transport runs (`writer.foldObservationIdentity`, which is the only
##      identity step a fragment-file record ever sees).
##   2. THE REFERENCE, read from the published pages and checked against
##      `depIdentityScope` — the one function that decides which kinds drop
##      the observer — so a kind moved across the scope line, or a page edited
##      back to the old claim, reddens here instead of misleading a consumer.
##
## Portable: pure `io_mon/types` + `io_mon/writer` + `io_mon/shm/dep_queue` and
## two Markdown files in this repository. No shim, no shared memory, no
## platform API, so nothing here is mocked.

import std/[os, strutils, unittest]

import io_mon/types
import io_mon/writer
import io_mon/shm/dep_queue

const
  RepoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  DepfileFormatPage = RepoRoot / "docs/site/content/reference/depfile-format.md"
  OverviewPage = RepoRoot / "docs/site/content/getting_started/overview.md"
  AttributionHeading = "### Observer Attribution"

proc observed(kind: MonitorRecordKind): MonitorRecord =
  ## A record as a monitored process would emit it: every observer coordinate
  ## is non-zero and distinct, so a zero after a round trip can only mean the
  ## transport dropped it.
  MonitorRecord(kind: kind, observationKind: moFileRead, seq: 7,
                osPid: 4101, parentOsPid: 4100, threadId: 4102,
                childOsPid: (if kind == mrProcessSpawn: 4103'u64 else: 0'u64),
                path: "/work/probe-input", detail: "run=contract")

proc throughSetTransport(record: MonitorRecord): MonitorRecord =
  ## Encode the element exactly as the Linux shim publishes it, then decode it
  ## exactly as the consumer does.
  var buf = newSeq[byte](16384)
  let n = encodeDepSetElement(record, buf, dseRequireFit)
  check n > 0
  var ok = false
  result = decodeDepRecord(buf.toOpenArray(0, n - 1), ok)
  check ok

proc observerDropped(kind: MonitorRecordKind): bool =
  depIdentityScope(kind) in {disPathScoped, disFactScoped}

proc section(page, heading: string): string =
  ## The body of one `###` section: from its heading to the next heading of
  ## level 3 or higher.
  let start = page.find(heading)
  if start < 0:
    return ""
  var stop = page.len
  for marker in ["\n### ", "\n## ", "\n# "]:
    let next = page.find(marker, start + heading.len)
    if next >= 0 and next < stop:
      stop = next
  page[start ..< stop]

proc taxonomyKeyFields(page: string; kind: MonitorRecordKind): string =
  ## The "Key Fields" cell of `kind`'s row in the Record Taxonomy table, or ""
  ## when the table has no row for it.
  for line in page.splitLines():
    let cells = line.split('|')
    if cells.len >= 4 and cells[1].strip() == "`" & $kind & "`":
      return cells[3].strip()
  ""

suite "observer attribution: behaviour":
  test "the set transport drops the observer of exactly the path- and fact-scoped kinds":
    for kind in MonitorRecordKind:
      let back = throughSetTransport(observed(kind))
      check back.kind == kind
      if observerDropped(kind):
        checkpoint $kind & " is " & $depIdentityScope(kind)
        check back.osPid == 0
        check back.parentOsPid == 0
        check back.threadId == 0
        check back.childOsPid == 0
      else:
        checkpoint $kind & " is process-scoped"
        check back.osPid == 4101
        check back.parentOsPid == 4100
        check back.threadId == 4102

  test "the merge fold drops the observer of the fact-scoped kinds on every transport":
    # Two processes observe the same fact. The fragment transport delivers both
    # with their own pid; the fold must reduce a fact-scoped kind to one
    # observer-less record and must leave every other kind attributed.
    for kind in MonitorRecordKind:
      var second = observed(kind)
      second.osPid = 5101
      second.threadId = 5102
      let folded = foldObservationIdentity(@[observed(kind), second])
      if depIdentityScope(kind) == disFactScoped:
        checkpoint $kind & " is fact-scoped"
        check folded.len == 1
        check folded[0].osPid == 0
        check folded[0].threadId == 0
      else:
        checkpoint $kind & " keeps its observer on the fragment transport"
        check folded.len == 2
        check folded[0].osPid in [4101'u64, 5101'u64]
        check folded[1].osPid in [4101'u64, 5101'u64]
        check folded[0].osPid != folded[1].osPid

suite "observer attribution: the published reference":
  let depfileFormat = readFile(DepfileFormatPage)
  let overview = readFile(OverviewPage)

  test "the taxonomy table does not list osPid as a key field of a kind that drops it":
    for kind in MonitorRecordKind:
      if observerDropped(kind):
        let cell = taxonomyKeyFields(depfileFormat, kind)
        checkpoint $kind & " key fields: " & cell
        check not cell.contains("`osPid`")

  test "the reference names every kind that loses its observer, and its scope":
    let body = section(depfileFormat, AttributionHeading)
    check body.len > 0
    # Every kind that loses its observer must be named. A process-scoped kind
    # may be named too: the section says which records DO carry the pid.
    for kind in MonitorRecordKind:
      if observerDropped(kind):
        let named = body.contains("`" & $kind & "`")
        checkpoint $kind & " named in " & AttributionHeading & ": " & $named
        check named
    # The page has to say which transport loses which kind, or a reader cannot
    # tell the Linux behaviour from the macOS and Windows one.
    check body.contains("set transport")
    check body.contains("fragment")
    check body.contains("REPRO_MONITOR_DEP_SHM_DISABLE")

  test "the overview no longer promises a pid on every event":
    check not overview.contains("Every event records the exact originating")
    check overview.contains("reference/depfile-format")
