## test_io_mon_cli_interest_flag — the `run --interest` flag, and the reason it
## had to exist: WITHOUT it an out-of-process consumer had no way at all to ask
## for a reduced event-interest set.
##
## WHY THIS FILE EXISTS
## --------------------
## `docs/contributors/event-interest-filter.md` §3 says the shim learns the
## interest set from `REPRO_MONITOR_INTEREST` on the child spawn. It does — but
## `childEnv` writes that variable AFTER `request.env` and after the injected
## pairs, because io-mon's injection must WIN over anything a caller supplies
## (that layering rule is `test_io_mon_child_env_layering.nim`'s subject, and it
## is a correctness rule: a caller must not be able to disarm monitoring). The
## consequence nobody had written down is that the variable is io-mon's OWN
## channel to the shim and is NOT an input a caller can set. An out-of-process
## consumer — reprobuild's build engine, which spawns `repro internal io
## monitor` — could put `REPRO_MONITOR_INTEREST` in that process's environment
## all it liked; `parseRun` accepted no interest flag, so the request carried
## `{}` -> `FullInterest`, and `childEnv` then wrote `FullInterest` straight
## over the request. The engine's reduction was live when it hosted io-mon
## in-process and dead when it spawned the CLI, for the same action.
##
## So the property under test is not "the flag parses". It is **the value the
## caller asked for is the value the child is told**, across the whole
## parse -> `FsSnoopRequest.interest` -> `childEnv` chain — the exact chain the
## request used to be dropped in the middle of. Every case below asserts the
## composed CHILD ENVIRONMENT, not just the parsed field, because asserting the
## field alone is what would have passed on the broken code had it existed:
## `FsSnoopRequest.interest` was already there and already honoured on the
## in-process path.
##
## No mocks: this drives the real argument parser and the real `childEnv`
## against the real process environment. Portable on purpose — `childEnv` has
## one body that all three arms call and the parser is platform-independent, so
## the rule holds wherever the suite runs.
##
## `parseFsSnoopCommand` and `childEnv` are deliberately unexported, so this
## file `include`s the module, exactly as `test_io_mon_child_env_layering.nim`
## and `test_io_mon_windows_child_env_block.nim` do.

import std/[strtabs, unittest]

include io_mon/fs_snoop

const
  BuildEdge = {ecFileDeps, ecProcessTree, ecLibraryLoads}
  BuildEdgeTokens = "file,proc,lib"
  AllTokens = "file,proc,lib,nondet,ipc"

## Assertion helpers are TEMPLATES, never procs: a failing `check` inside a
## plain `proc` prints "Check failed" and the enclosing case still reports
## `[OK]`, because `unittest`'s failure flag is bound per test body.
template childInterest(argv: seq[string]): string =
  ## Parse `argv` the way `runFsSnoopCli` does, then compose the child
  ## environment the way all three spawn arms do, and read back the one
  ## variable the shim consults at init.
  childEnv(parseFsSnoopCommand(argv).request, @[])["REPRO_MONITOR_INTEREST"]

template parsedInterest(argv: seq[string]): set[EventCategory] =
  parseFsSnoopCommand(argv).request.interest

suite "io-mon CLI event-interest flag":
  test "with no flag the child is told FullInterest — every existing caller is unchanged":
    # The back-compat contract stated in `parseInterestFlag`'s doc comment and
    # in docs/usage.md. `interest` is left zero (`{}`), and `normalizeInterest`
    # inside `interestToTokens` widens it, so "unset" and "all" reach the shim
    # as the same non-empty token list — the shim can still tell them apart
    # from a genuinely absent variable.
    check parsedInterest(@["run", "--depfile", "d.iomon", "--", "true"]) == {}
    check childInterest(@["run", "--depfile", "d.iomon", "--", "true"]) ==
      AllTokens

  test "the requested set reaches the child — space form":
    # THE PRIMARY ASSERTION. Deleting the `--interest` arm from `parseRun`
    # leaves this reading `AllTokens`.
    let argv = @["run", "--interest", BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    check childInterest(argv) == BuildEdgeTokens

  test "the requested set reaches the child — `--interest=` form":
    let argv = @["run", "--interest=" & BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    check childInterest(argv) == BuildEdgeTokens

  test "the flag works on the `run`-less legacy form reprobuild used to use":
    # `repro internal io monitor` dispatched the verb itself before delegating,
    # so the bare `--depfile … -- <cmd>` grammar is still accepted. The flag has
    # to reach the same parser on that path or the fix covers only half the
    # callers.
    let argv = @["--interest", BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    check childInterest(argv) == BuildEdgeTokens

  test "a single category is honoured, not widened":
    # Guards the boundary the codec makes easy to get wrong: `{ecFileDeps}` is a
    # legitimate reduced set and must NOT be confused with the `{}` that means
    # "unset".
    let argv = @["run", "--interest", "file", "--", "true"]
    check parsedInterest(argv) == {ecFileDeps}
    check childInterest(argv) == "file"

  test "the flag beats a caller-supplied REPRO_MONITOR_INTEREST in request.env":
    # The layering rule that made the flag necessary, asserted from the other
    # side. A caller cannot reach the shim through the environment — io-mon's
    # injection overwrites the variable — so the flag is the ONLY channel, and
    # a caller trying both must get the flag's answer rather than a race
    # between two mechanisms.
    var parsed = parseFsSnoopCommand(@["run", "--interest", BuildEdgeTokens,
                                       "--", "true"])
    parsed.request.env.add(("REPRO_MONITOR_INTEREST", "nondet,ipc"))
    check childEnv(parsed.request, @[])["REPRO_MONITOR_INTEREST"] ==
      BuildEdgeTokens

  test "an explicitly empty value means the same as an absent flag":
    check childInterest(@["run", "--interest", "", "--", "true"]) == AllTokens
    check childInterest(@["run", "--interest", "   ", "--", "true"]) == AllTokens

  test "an unknown token beside a known one is ignored (forward-compat)":
    # A newer consumer naming a category this build does not have must not fail
    # the run; the host-side filter is the source of truth either way
    # (event-interest-filter.md §5).
    check parsedInterest(@["run", "--interest", "file,quantum,lib",
                           "--", "true"]) == {ecFileDeps, ecLibraryLoads}

  test "a value naming NO known token is refused, not widened to all":
    # The operator-typo case. Silently widening it would hand back
    # `FullInterest` and discard the caller's reduction without a word — the
    # very failure this flag exists to end — so it is a hard parse error, the
    # same class as `--events bogus`.
    expect ValueError:
      discard parseFsSnoopCommand(@["run", "--interest", "flie,prcO",
                                    "--", "true"])
    # …and the diagnostic names the vocabulary, so the typo is fixable from the
    # message alone.
    try:
      discard parseFsSnoopCommand(@["run", "--interest", "flie", "--", "true"])
      check false        # unreachable: the line above must raise
    except ValueError as err:
      check AllTokens in err.msg

  test "--interest still requires a value":
    expect ValueError:
      discard parseFsSnoopCommand(@["run", "--interest"])
