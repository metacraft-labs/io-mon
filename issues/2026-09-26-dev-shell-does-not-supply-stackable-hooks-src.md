# The dev shell does not supply `STACKABLE_HOOKS_SRC`, so the build depends on a sibling checkout that nothing guarantees

|             |                                                                               |
| ----------- | ----------------------------------------------------------------------------- |
| Status      | open                                                                          |
| Recorded    | 2026-09-26                                                                    |
| Observed in | io-mon @ `dba85e0`                                                            |
| Area        | `flake.nix` (`devShells.default`), `Justfile`, `config.nims`, `io_mon.nimble` |

## Observed

io-mon resolves `nim-stackable-hooks` through **two independent channels**, and
only one of them is supplied by the flake:

| channel                             | read by                                                                                            | supplied by                                     |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `STACKABLE_HOOKS_SRC`               | `packages.default` only (`flake.nix`: `STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src"`) | the flake input                                 |
| `--path:../nim-stackable-hooks/src` | every `nim c` under `just` / `nimble` — `config.nims` and `io_mon.nimble`'s `test` task            | a sibling checkout that must already be on disk |

`devShells.default` does **not** set `STACKABLE_HOOKS_SRC`. The `Justfile`
therefore takes its own default —

```
stackable_hooks_src := env_var_or_default("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src")
```

— and `config.nims` adds `--path:../nim-stackable-hooks/src` unconditionally. So
inside `nix develop`, with the flake input fully realised in the store, a build
still resolves the library from `../nim-stackable-hooks` and ignores the pin
entirely.

The consequence: `nix develop` succeeds, and then `just build` / `just test`
fails with `cannot open file: stackable_hooks/...` on any machine where the
sibling directory is absent — a fresh clone, a one-off checkout, a contributor
who is not using the multi-repo workspace. The dev shell advertises a complete
environment and does not provide one.

## Expected

Not specified. Proposed: entering the dev shell should be sufficient to build,
with the sibling checkout used **when present** and the pinned flake input used
otherwise.

The sibling-first fallback is deliberate and should stay — it is how a developer
edits io-mon and nim-stackable-hooks together, and `io_mon.nimble` says so:

> In this `repo`-managed multi-repo workspace, sibling checkouts are resolved by
> path […] Deliberately NOT a git dependency: a `requires "https://…/nim-stackable-hooks"`
> would fight the sibling checkout the workspace already provides.

`config.nims` already documents the shape the fix should take, for a different
dependency:

> a consumer building io-mon from a read-only store path (Nix flake input)
> overrides that with `$SHM_QUEUE_SRC` — mirrors how `scripts/build_shim.sh`
> resolves `STACKABLE_HOOKS_SRC`. The path is added even when the dir is absent
> so a clear "cannot open file: shm_queue/ring" surfaces rather than a silent
> wrong build.

`SHM_QUEUE_SRC` and `SHM_GSET_SRC` are read by `config.nims` with a sibling
default; `STACKABLE_HOOKS_SRC` is the one that is _not_, and it is also the one
the dev shell does not export.

## Evidence

- `flake.nix`: `STACKABLE_HOOKS_SRC` appears once, inside
  `packages.default`. `devShells.default` lists packages only and sets no
  environment.
- `Justfile` line 3 (`env_var_or_default`) and line 11 (the value passed to
  `scripts/build_shim.sh`).
- `config.nims`: `switch("path", "../nim-stackable-hooks/src")` is a literal,
  while `shmQueueSrc` / `shmGSetSrc` are `getEnv(...)` with sibling defaults.
- `io_mon.nimble`, `runTestDirs`: `let flags = "--path:../nim-stackable-hooks/src --path:tests/helpers"`.
- Measured consequence of the split, in CI: the flake pin was bumped twice —
  `flake.lock` and then `flake.nix`'s url (`3aaa2bd`, to `72f57824`) — and
  `Test (nix, linux-x64)` stayed red both times with
  `cannot open file: stackable_hooks/windows_env_block`, because that job runs
  `just test` in the dev shell and so reads the sibling channel. Pinning the
  sibling entry in `.github/sibling-repos` is what turned it green (red → pass,
  21m06s). That is the two-channel split demonstrated end to end.
- Inferred, not measured: that a fresh clone with no sibling fails at
  `just build`. The mechanism is the literal `--path` above and the failure mode
  `config.nims` itself predicts for the sibling deps it _does_ make overridable.

## What keeps it honest today

`.github/sibling-repos` now pins `nim-stackable-hooks!=72f578249e9d8bbca8e3705c8a41ed5085c05bf9`
— the same revision `flake.nix` pins `stackable-hooks-src` to. That does not
close this gap; it makes the two channels **agree about which revision** they
resolve, so a build cannot silently compile against one library while the flake
claims another. The alignment has to be maintained by hand: whoever moves the
flake pin must move the sibling entry with it, and vice versa. That coupling is
the cost of leaving this open.

## Suggested direction

Give `STACKABLE_HOOKS_SRC` the same treatment `SHM_QUEUE_SRC` already has, in
both places:

- `config.nims`: `getEnv("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src")`
  instead of the literal, and the same for `io_mon.nimble`'s `test` flags, so
  `nim c` honours the variable wherever it is set.
- `flake.nix`: export `STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src"`
  from `devShells.default` **only as a fallback** — the sibling must still win
  when it exists, or the paired-editing workflow above breaks. "Sibling if
  present, else the pinned input" is the required order, and a shellHook that
  sets the variable only when `../nim-stackable-hooks/src` is missing is the
  smallest way to express it.

Trade-off to state rather than hide: making the dev shell set the variable means
a developer who _does_ have a sibling gets different behaviour depending on
whether it is on disk, which is exactly the implicitness this file complains
about. The alternative — always use the pin, never the sibling — is cleaner but
deletes the paired-editing workflow the nimble file deliberately preserves. A
third option is to keep the fallback but have the shell **print** which of the
two it selected, so the choice is visible rather than inferred.

Deliberately **not** done in this pass: `flake.nix` and the dev shell are being
edited concurrently for the macOS `strace` guard, and this is a robustness
improvement rather than the cause of any current CI failure.

## Related

- `2026-09-26-workspace-lock-forward-carry-freezes-sibling-pins.md` — why the
  sibling channel was pinned to a stale revision, which is how this split was
  discovered.
- `2026-09-26-devshell-pulls-linux-only-strace-on-macos.md` — the other open
  defect in the same dev shell.
- `3aaa2bd` — the flake url pin whose revision the sibling entry now mirrors.
