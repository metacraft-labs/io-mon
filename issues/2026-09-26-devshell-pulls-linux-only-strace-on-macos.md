# The dev shell pulls Linux-only `strace` unconditionally, so it cannot be entered on macOS

|             |                                                                                                                   |
| ----------- | ----------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                              |
| Recorded    | 2026-09-26                                                                                                        |
| Observed in | io-mon @ `61d2f11`, still unguarded at `a3edfab` (introduced by `914959b`, 2026-08-16)                            |
| Area        | `flake.nix` (`perSystem.devShells.default.packages`), CI jobs `Build (macos-arm64)` and `Test (nix, macos-arm64)` |

## Observed

`Build (macos-arm64)` and `Test (nix, macos-arm64)` both die in
`Setup Dev Environment`, before any io-mon source is compiled, because the
`aarch64-darwin` dev shell does not evaluate:

```
error:
       … while calling the 'derivationStrict' builtin
       … while evaluating derivation 'nix-shell'
       … while evaluating attribute 'nativeBuildInputs' of derivation 'nix-shell'

       error: Refusing to evaluate package 'strace-7.0' in
         /nix/store/h9wn92hv33sizprch7fcp16lfs1k3w5j-source/pkgs/by-name/st/strace/package.nix:55
         because it is not available on the requested hostPlatform:
         hostPlatform.system = "aarch64-darwin"
         package.meta.platforms = [ "aarch64-linux" "arc-linux" … "x86_64-linux" ]
         package.meta.badPlatforms = [ ]
##[error]Process completed with exit code 1.
```

`meta.platforms` for `strace` is Linux-only in its entirety, so there is no
Darwin system on which this shell can be entered.

Both macOS jobs fail identically and at the same step. Neither reaches
`just build` or `just test`, so **macOS has no build or test signal at all** —
not a failing one, an absent one.

## Expected

The dev shell must be enterable on every system `flake.nix` declares. `systems`
lists `x86_64-darwin` and `aarch64-darwin` alongside the two Linux systems, and
`.github/workflows/ci.yml` runs `Build` and `Test (nix)` legs on
`[self-hosted, macos, arm64]` — so macOS is a supported host by this repo's own
declarations, not an aspiration.

Not specified beyond that. Proposed: a platform-conditional shell package set,
so a Linux-only tool is offered only where it exists.

The tool is genuinely Linux-only and genuinely required _on Linux_: the comment
beside `pkgs.strace` in `flake.nix` records why it was added — it is the ground
truth for `tests/linux/test_io_mon_library_load_closure.nim`, which compares the
loader closure io-mon claims to observe against the one the kernel actually
opened, and CI failed with `Could not find command: 'strace'` without it. That
test lives in `tests/linux/`, which `io_mon.nimble`'s `selectedTestDirs()`
selects only `when defined(linux)`. So nothing on a macOS host consumes `strace`,
and its presence in the shared package list is load-bearing for exactly one
platform.

## Evidence

- CI run `36235385746` on `io-mon@61d2f11` (push to `dev`), jobs
  `Build (macos-arm64)` (`108386091034`) and `Test (nix, macos-arm64)`
  (`108386091042`). The quoted text is from the `Setup Dev Environment` step of
  both.
- The same run's `Lint` and `Build (linux-x64)` are green, which locates the
  fault in the Darwin evaluation rather than in the shell definition as a whole.
- `git log -1 --format=%as 914959b` → `2026-08-16`, subject _"Provide strace in
  the dev shell, so the loader-closure ground truth can run"_. That commit adds
  `pkgs.strace` to `devShells.default.packages` with no `stdenv.isLinux` guard,
  and is an ancestor of `origin/dev`. `git log -S'pkgs.strace' -- flake.nix`
  reports it as the only commit that introduces the string, so no later commit
  has narrowed it.
- Inferred, not measured: that every macOS CI job since 2026-08-16 has failed
  this way. The mechanism is a deterministic evaluation refusal and the run at
  `61d2f11` and at `2aae454` fail identically, but individual runs in between
  were not enumerated.

## Suggested direction

Gate the Linux-only entries rather than the whole list, e.g. a
`lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.strace ]` appended to
`packages`. Cheap, and it keeps the Linux shell byte-identical.

The trade-off to state rather than hide: a macOS shell without `strace` cannot
run the Linux loader-closure oracle, which is correct — `selectedTestDirs()`
never selects `tests/linux/` there. But the same list also pins
`cmake`/`ninja`/`cargo`/`rustc` for the §4.5(h) real-build completeness oracle,
and those _are_ available on Darwin, so the guard must name `strace`
specifically and not be widened to "skip the tooling on macOS".

An alternative is `meta.badPlatforms`-style tolerance
(`NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM`), which the error message itself suggests.
It is worse here: it would make the shell evaluate and then fail later, at the
point something tried to realise a derivation that cannot build, and it needs
`--impure` at every call site.

## Related

- `tests/linux/test_io_mon_library_load_closure.nim` — the consumer of `strace`,
  and the reason the entry exists.
- `flake.nix`'s own comment block above `pkgs.cmake` — the same
  "pin the tool the gate depends on" argument, for tools that are cross-platform.
- Filed alongside a separate fix for the stale `nim-stackable-hooks` sibling pin
  that reddened `Test (nix, linux-x64)` in the same run. The two are
  independent: this one is an evaluation refusal on Darwin only, that one a
  missing module on every platform's compile.
