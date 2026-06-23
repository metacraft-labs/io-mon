## io-mon — cross-platform filesystem I/O monitoring for Nim.
##
## io-mon is a relocation of reprobuild's `repro_monitor_depfile` fs-snoop
## stack, lifted into a standalone package on top of `nim-stackable-hooks`.
## It captures the read/written file sets of a monitored process tree and
## persists them in the binary RMDF depfile format (reader/writer/render),
## and exposes the `fs_snoop` driver that runs a command under the interpose
## monitor.
##
## This top-level module re-exports the public API of every submodule, so
## downstream code can simply `import io_mon`.

import io_mon/types
import io_mon/capabilities
import io_mon/writer
import io_mon/reader
import io_mon/render
import io_mon/fs_snoop

export types
export capabilities
export writer
export reader
export render
export fs_snoop
