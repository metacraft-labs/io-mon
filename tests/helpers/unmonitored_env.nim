## The environment for a child that must run without any monitor the test
## did not choose: a bare (shim-free) control, an `LD_PRELOAD`-only run of a
## shim under test, or the base a monitored arm adds its own settings to.
##
## Removing `LD_PRELOAD` alone is not enough. `repro test` runs the test under
## an outer monitor, which exports its own `REPRO_MONITOR_*` settings
## (`REPRO_MONITOR_SHIM_LIB`, `REPRO_MONITOR_SESSION`, `REPRO_MONITOR_DEP_SHM`,
## ...). A child that inherits them is not bare, and when
## `REPRO_MONITOR_SHIM_LIB` names a different shim than the one the test
## preloads, the experiment changes: raw-clone children of the private-heap
## stress host hang (reprobuild-pm issue
## 2026-10-20-linux-raw-clone-children-hang-when-monitor-shim-lib-names-another-shim.md).
## So every `REPRO_MONITOR_*` variable is dropped too, and a monitored arm
## sets the ones it needs explicitly (at least `REPRO_MONITOR_SHIM_LIB`);
## `io-mon run` adds the rest.
##
## Only for tests in `repro.nim`'s `isolatesMonitor` list. Their execution
## has no outer monitor shim, so nothing of the outer monitor's is lost by
## removing these variables. A test that still runs under the outer monitor
## would cut that monitor's own settings off from its children.
import std/[os, strtabs, strutils]

const MonitorEnvPrefix* = "REPRO_MONITOR_"
  ## Prefix shared by every monitor setting io-mon and Reprobuild export.

proc unmonitoredEnv*(): StringTableRef =
  ## A copy of this process's environment without `LD_PRELOAD` and without
  ## any variable whose name starts with `MonitorEnvPrefix`.
  result = newStringTable(modeCaseSensitive)
  for key, value in envPairs():
    if key == "LD_PRELOAD" or key.startsWith(MonitorEnvPrefix):
      continue
    result[key] = value
