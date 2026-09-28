# Windows ARM64 release capture changes the child's exit code

Observed at `c4f6fe0` with stackable-hooks pinned to `72f5782`, 2026-09-28:
<https://github.com/metacraft-labs/io-mon/actions/runs/36363621856/job/108745731691>.

The [release specification](https://github.com/metacraft-labs/metacraft-specs/blob/50776b8/infrastructure/gosti-io-mon-runquota-releases.md)
requires native Windows ARM64 execution and real file capture. Both the CLI
and shim compile and pass PE architecture checks, but `io-mon run` around
the native read/write probe returns 1 instead of the probe's expected 7,
with no standard-output/error diagnostic. The x64 version of the same test
passes at this commit.

The Windows shim enables its inline backend unconditionally. Its pinned
installer decodes x86 instructions and emits `JMP rel32`; it has no ARM64
implementation. This is a suspected cause, not yet a measured attribution.
Collect a plain-child control, shim debug log and decoded capture before
changing the backend. A compiled ARM64 DLL alone is insufficient release
evidence; do not remove or weaken the functional gate to publish it.

Open issues and deleted issue history were searched after refreshing `dev`
(`279a17b`); no previous record covered this release failure.
