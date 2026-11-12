## test_io_mon_child_env_unset — `FsSnoopRequest.unsetEnv` removes a name from
## the hosting process's environment before the monitored child inherits it.
##
## WHY THIS FILE EXISTS. A host that composes an action's environment can keep
## one variable (a build-tool selection such as `CC`) away from an inheriting
## child only if io-mon can remove it. Copying the host environment into
## `request.env` instead would hand io-mon's needle-prune invariant a second
## route into the child (see `childEnv`), so the removal is a filter on the
## host copy and nothing else.
##
## The properties held here, against the real `childEnv` and the real process
## environment (no mocks, nothing mutated process-globally):
##   * a host name listed in `unsetEnv` is absent from the child table;
##   * every other host name still arrives, so the filter is not a blanket drop;
##   * a name listed in both `unsetEnv` and `request.env` takes the `env` value.
##
## `childEnv` is deliberately unexported, so this file `include`s the module,
## as `test_io_mon_child_env_layering.nim` does.

import std/[strtabs, unittest]

include io_mon/fs_snoop

proc hostNames(exclude: openArray[string]): seq[string] =
  ## Host variables this test can name without touching the injection channel
  ## or the caller's `PATH`.
  for key, _ in envPairs():
    if key.len == 0 or key.startsWith("REPRO_MONITOR_") or key == "PATH":
      continue
    if key in exclude:
      continue
    result.add(key)

suite "io-mon child environment: unsetEnv removes a host name":
  test "a host name listed in unsetEnv is absent, and the others still arrive":
    let names = hostNames([])
    require names.len >= 2
    let removed = names[0]
    let kept = names[1]
    let request = FsSnoopRequest(unsetEnv: @[removed])
    let composed = childEnv(request, @[("REPRO_MONITOR_SESSION", "run-1")])
    check not composed.hasKey(removed)
    check composed.hasKey(kept)
    check composed[kept] == getEnv(kept)
    check composed["REPRO_MONITOR_SESSION"] == "run-1"

  test "a name the caller removes and also sets takes the env value":
    let names = hostNames([])
    require names.len >= 1
    let name = names[0]
    let request = FsSnoopRequest(unsetEnv: @[name],
      env: @[(name, "declared-by-the-caller")])
    let composed = childEnv(request, @[])
    check composed[name] == "declared-by-the-caller"

  test "unsetEnv matches by name exactly, and an absent name changes nothing":
    let names = hostNames([])
    require names.len >= 1
    let name = names[0]
    let request = FsSnoopRequest(
      unsetEnv: @[name & "_NOT_A_HOST_NAME"])
    let composed = childEnv(request, @[])
    check composed.hasKey(name)
    check composed[name] == getEnv(name)
