## Discovery of the monitor shim shared library.
##
## This is pure path resolution — it names where `librepro_monitor_shim.{so,
## dylib,dll}` can be found and honours the `REPRO_MONITOR_SHIM_LIB` operator
## pin. It carries **no** dependency on `MonitorHandle`, the capture lifecycle,
## or the shared-memory transport, so it can be imported by a consumer that only
## wants to LOCATE the shim (to hand its path to a subprocess `io-mon run`)
## without dragging in `fs_snoop` and its by-value `=destroy`. That matters for
## a `--mm:refc` consumer such as CodeTracer's `ct` binary, which reads the
## depfile format and locates the shim but must never compile the ARC/ORC-only
## destructor. `fs_snoop` re-exports this module, so existing `import io_mon`
## consumers are unaffected.

import std/[os]
import io_mon/paths

const ShimLibOverrideEnv* = "REPRO_MONITOR_SHIM_LIB"
  ## Operator override for the shim shared-library path — see
  ## ``findShimLibrary``.

proc candidateShimLibraries(): seq[string] =
  ## The DISCOVERY candidates only. The ``REPRO_MONITOR_SHIM_LIB`` override is
  ## deliberately NOT in this list: an override is a pin, not a first guess, so
  ## it is handled separately in ``findShimLibrary`` where a miss can be made
  ## fatal instead of silently falling through to a different shim.
  let appDir = getAppDir()
  # Windows: the shim builds as a .dll instead of a .dylib; probe both so the
  # same lookup logic works on either platform without runtime branching at
  # every call site.
  when defined(windows):
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.dll",
      appDir / "librepro_monitor_shim.dll",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dll"
    ]
  elif defined(linux):
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.so",
      appDir / "librepro_monitor_shim.so",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.so"
    ]
  else:
    result = @[
      appDir / ".." / "lib" / "librepro_monitor_shim.dylib",
      getCurrentDir() / "build" / "lib" / "librepro_monitor_shim.dylib"
    ]

proc findShimLibrary*(): string =
  ## **Public since M9.R.13c.2** — the build engine's ``monitoredAction``
  ## now seeds ``REPRO_MONITOR_SHIM_LIB`` on the action's env at wrap
  ## time, so the daemon-spawned ``repro internal fs-snoop`` subprocess
  ## resolves the shim without inheriting the user's shell environment.
  ##
  ## Lookup order:
  ##   1. ``$REPRO_MONITOR_SHIM_LIB`` env override (operator pin).
  ##   2. ``<appDir>/../lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (canonical build layout — what ``just build`` produces).
  ##   3. ``<appDir>/librepro_monitor_shim.{dll,so}`` (Windows-only
  ##      side-by-side install layout).
  ##   4. ``<cwd>/build/lib/librepro_monitor_shim.{dll,so,dylib}``
  ##      (running from the repo root with a freshly built tree).
  ##
  ## Returns the absolute path of the first existing discovery candidate, or the
  ## empty string when no candidate exists.
  ##
  ## **The override is honoured or the call FAILS — it is never ignored.** A set
  ## ``REPRO_MONITOR_SHIM_LIB`` that does not name an existing file raises
  ## ``IOError`` instead of falling through to a discovered shim. Falling
  ## through would silently capture a run with a DIFFERENT shim than the
  ## operator pinned — a stale pin or a typo'd path would produce a capture
  ## whose provenance is not the one that was asked for, with no diagnostic and
  ## a cheerful ``mcComplete``. The override exists precisely so a specific shim
  ## build is used; "honoured first" has to mean honoured, not preferred.
  let override = getEnv(ShimLibOverrideEnv)
  if override.len > 0:
    if not fileExists(extendedPath(override)):
      raise newException(IOError,
        ShimLibOverrideEnv & " is set to \"" & override &
          "\" but no such file exists; refusing to fall back to a discovered " &
          "shim because the capture would then come from a shim the operator " &
          "did not pin (unset " & ShimLibOverrideEnv & " to use discovery)")
    return absolutePath(override)
  for candidate in candidateShimLibraries():
    if candidate.len > 0 and fileExists(extendedPath(candidate)):
      return absolutePath(candidate)
  ""
