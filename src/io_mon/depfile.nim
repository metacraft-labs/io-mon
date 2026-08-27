## The io-mon **dependency-file format**, as a monitoring-free import surface.
##
## `import io_mon` pulls in the whole package, including `fs_snoop` — the
## capture lifecycle, `MonitorHandle`, and its ARC/ORC-only by-value `=destroy`.
## A consumer that only READS OR WRITES the depfile format (and perhaps LOCATES
## the shim to hand to a subprocess), rather than driving a capture in-process,
## does not need any of that — and must not compile the by-value `=destroy` when
## it is built `--mm:refc` (e.g. CodeTracer's `ct` binary, whose refc build
## rejects the modern destructor signature).
##
## This module is that surface: the format types + wire codec + reader + writer
## + renderers + shim discovery, and NOTHING from `fs_snoop`. io-mon owns the
## format; reprobuild and CodeTracer consume it through here. None of the
## re-exported modules import `fs_snoop`, so the destructor is never dragged in.
##
## If you are driving a capture in-process (`runMonitored`/`startMonitor`/
## `finishMonitor`), import `io_mon` (or `io_mon/fs_snoop`) instead — that is the
## capture surface, and it re-exports everything here.

import io_mon/types
import io_mon/capabilities
import io_mon/codec
import io_mon/writer
import io_mon/reader
import io_mon/render
import io_mon/shim_discovery

export types
export capabilities
export codec
export writer
export reader
export render
export shim_discovery
