# On Linux a file read is recorded without the process that read it

|             |                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                          |
| Recorded    | 2026-11-09                                                                                                    |
| Observed in | io-mon `c9e4dbd`                                                                                              |
| Area        | `src/io_mon/shm/dep_queue.nim` (`encodeDepRecordWithSeq`, `encodeDepRecordIdentity`), the Linux set transport |

## Observed

On Linux every `mrFileOpen`, `mrFileRead`, `mrPathProbe` and
`mrDirectoryEnumerate` record in a capture has `osPid = 0`. The process that
read the file is not in the record, and no other record says which one it
was.

The cause is deliberate. `encodeDepRecordIdentity` builds the nim-shm-gset
element key with the path-scoped kinds' observer fields zeroed (`osPid`,
`parentOsPid`, `threadId`, `childOsPid`: `dropObserver` in
`encodeDepRecordWithSeq`), so that a path read by thousands of processes is
one set element (the dedup that makes the set transport affordable; the
`disPathScoped` arm of `depIdentityScope`). `decodeDepRecord` rebuilds the
record from that key, so the zero is what the merge and every consumer see.
The key of a path-scoped kind also keeps the reader's executable incarnation
(`writer.encodeDepSetElement` appends `setElemImage`), but `decodeDepRecord`
ignores those trailing bytes, so not even the reader's image reaches the
consumer. (The four fact-scoped kinds, `mrLibraryLoad`, `mrEnvRead`,
`mrSysctlRead`, `mrTimeRead`, drop the pid too; `depIdentityScope` argues
that no consumer reads it there. This issue is about the path-scoped kinds.)
macOS and Windows use the fragment-file writer, which keeps the pid. The
repeated-vfork fixture already relies on this (issue
`2026-09-30-linux-shim-runtime-settings-diverge-from-policy.md`: "The new
repeated-vfork fixture incorrectly required a PID on every read").

Measured 2026-11-09 with reprobuild's `internal io monitor` built against
io-mon `c9e4dbd` (reprobuild `372aece603` plus uncommitted M2 work; the
io-mon sources were the pinned flake input, not a sibling checkout). The
probe started `sh -c "./wt-probe; cat probe-input > /dev/null"`, where
`wt-probe` is a `#!` script, and printed the capture with io-mon's own
`readMonitorDepFile` + `renderMonitorRecordText`.

x86_64 Linux (`linux-preload-hooks`), `mcComplete`:

```
#7 file-read pid=0 tid=0 path=/var/tmp/…/w/probe-input detail=run=…  [osPid=0]
#8 file-read pid=0 tid=0 path=/var/tmp/…/w/wt-probe detail=run=…  [osPid=0]
#9 file-read pid=0 tid=0 path=/var/tmp/…/w/wt-probe detail=inherited-fd run=…  [osPid=0]
#28 process-exec pid=2083990 tid=2083990 path=./wt-probe detail=run=…  [osPid=2083990]
#31 process-exec pid=2083992 tid=2083992 path=/usr/bin/cat detail=run=…  [osPid=2083992]
```

The same probe on aarch64 macOS (`macos-interpose-hooks`, a Nix `bash` and
`cat` so that SIP does not hide them), `mcComplete`, names the reader:

```
#52 file-read pid=19938 tid=… path=/private/tmp/…/w/wt-probe result=73  [osPid=19938]
#71 file-read pid=19973 tid=… path=/private/tmp/…/w/probe-input result=5  [osPid=19973]
```

## Expected

The record reference says otherwise. `docs/site/content/reference/depfile-format.md`,
"Record Taxonomy", lists `osPid` as a key field of `mrFileOpen`,
`mrFileRead`, `mrPathProbe` and `mrDirectoryEnumerate`, and
`docs/site/content/getting_started/overview.md`, "Process Lifecycle
Tracking", says "Every event records the exact originating `osPid`,
`parentOsPid`, and `threadId`". The Linux behaviour is a design trade-off
(dedup over attribution), so this is a doc/behaviour mismatch with a cost to
consumers, not a regression:

- the reference should state that on Linux the path-scoped kinds carry no
  observer (`osPid = 0`), and why; and
- a consumer that needs to know which process read a path has no way to get
  it on Linux. Not specified. Proposed: decide whether that is a non-goal (and
  say so in the reference) or whether some reads need attribution.

## Evidence

```sh
printf '#!/bin/sh\nexit 0\n' > wt-probe; chmod +x wt-probe; echo data > probe-input
reprobuild internal io monitor --depfile cap1 \
  --interest file-reads,file-writes,proc,lib -- \
  /bin/sh -c './wt-probe; cat probe-input > /dev/null'
```

Then print `cap1` with a five-line Nim program: `readMonitorDepFile` and
`renderMonitorRecordText` for each record, plus `osPid`. The code claim
(the observer fields are zeroed in the element key and not restored) is
read from `encodeDepRecordWithSeq` and `decodeDepRecord` at `c9e4dbd`.

## Impact

Reprobuild's distributed-execution judge locates a `#!` script started by a
bare name or a relative path by its interpreter's read of the script (issue
`2026-11-09-process-start-image-names-the-interpreter-of-a-script-started-by-name.md`,
route 1). It wants the read by the process the exec or spawn started. On
Linux it cannot tell which process read the file, so it accepts a read of a
path ending in that name by any process (`osPid = 0`). That fails closed: it
can withhold a goal whose processes run a program by name and, separately,
read a file outside the closure that happens to have the same name. No run
has hit this so far (reprobuild-pm `spec/Distributed-Execution-Threat-Model.md`
§7.5b, "What ran is judged by its image").

## Suggested direction

Either of these, each with a cost:

1. Keep reads unattributed and fix the reference (no cost to the transport).
   The consumer keeps its fail-closed match.
2. Fix the interpreter case at its source (the issue above): if the process
   start of an interpreter the kernel started for a script also records the
   script, no consumer needs to attribute a read. This is narrower than
   attributing all reads and does not touch the dedup key.

Putting the pid back into the path-scoped key would undo the dedup the set
transport was chosen for (reprobuild-pm `spec/Dependency-Observation-Attribution.md`,
"The bigger lever: representation, not attribution").

## Related

- `2026-11-09-process-start-image-names-the-interpreter-of-a-script-started-by-name.md`
- reprobuild-pm `spec/Distributed-Execution-Threat-Model.md` §7.5b
