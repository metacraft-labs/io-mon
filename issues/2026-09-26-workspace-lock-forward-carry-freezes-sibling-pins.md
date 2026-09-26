# The workspace-lock forward carry freezes sibling pins, and nothing in the merge flow ever thaws them

|             |                                                                         |
| ----------- | ----------------------------------------------------------------------- |
| Status      | open                                                                    |
| Recorded    | 2026-09-26                                                              |
| Observed in | io-mon @ `dba85e0` (mechanism present since the workflow was added)     |
| Area        | `.github/workflows/publish-workspace-lock.yml`, `.github/sibling-repos` |

## Observed

The sibling revision CI compiles against is decided by the workspace lock
published for the mainline commit, and that lock is produced by **copying the
previous tip's sibling set verbatim**. It is never re-resolved. So a sibling pin,
once wrong, stays wrong for every subsequent commit of this repo.

Measured. For io-mon `61d2f11`, `clone-siblings` reported:

```
Resolved workspace-lock commit for io-mon: 61d2f11a057bae9063b2a59157124d3125d340f9
Sibling resolution for io-mon (workspace lock io-mon@61d2f11a…):
  metacraft-labs/nim-stackable-hooks -> 25bf49e4ca78d4042a7f4851f5a7d4953c296741 (lock)
  metacraft-labs/nim-shm-queue       -> 5a8e43b52fa202859658692c9f8432967f3971ea (lock)
```

`25bf49e4` is _"windows: stop freeing the remote path buffer under a live
LoadLibraryW"_. It predates `6a53408` _"Windows injector: an explicit child
environment"_, which is where `src/stackable_hooks/windows_env_block.nim` and
`runWithMonitorShim`'s `env` parameter arrived. Every io-mon commit from then
until the `!=` override inherited that revision, and `Test (nix, linux-x64)`
died on every one of them with:

```
tests/portable/test_io_mon_windows_child_env_block.nim(41, 23)
  Error: cannot open file: stackable_hooks/windows_env_block
```

Because `nimble test` aborts at the first failing file, the rest of
`tests/portable/` and the **whole** of `tests/linux/` never executed in CI
either — so the freeze cost far more coverage than the one test it named.

## Expected

Not specified. Proposed: a mainline commit's published lock should name the
sibling revisions that commit is actually built and tested against, or the
resolution should fail loudly when it cannot.

The workflow is not unaware of this — it states the limitation itself, in
`publish-workspace-lock.yml`'s `on:` comment:

> The DELIBERATE limitation shared by any forward carry: if a pushed commit
> BUMPED a sibling, the carried set predates that bump. Re-lock such a commit
> through the `workflow_dispatch` path below.

So the behaviour is a documented trade-off, not an oversight, and this issue is
about its **cost** rather than its existence. Two properties turn an accepted
limitation into a recurring outage:

1. **Nothing signals that a re-lock is needed.** The remedy is a manual
   `workflow_dispatch` backfill that someone has to know to run. No job fails,
   no warning is printed, and the carried pin looks identical to a correct one
   in the log — it is annotated `(lock)`, the same as a freshly resolved pin.
2. **The symptom is maximally misleading.** It surfaces as a _portable_ test
   that cannot compile in CI while passing on every developer machine, because
   a developer's `../nim-stackable-hooks` is a live `dev` checkout that has the
   module. The natural reading is "our test is broken", not "CI is compiling a
   three-week-old library".

## Evidence

- `.github/workflows/publish-workspace-lock.yml`, the `push:` trigger comment
  (quoted above) and the _"WHAT IT PUBLISHES"_ section: _"An EXISTING lock
  record, re-anchored onto the mainline commit: every sibling pin copied
  verbatim, and precisely one field changed — the record's own coordinate, the
  entry naming this repo, whose revision moves to the mainline SHA."_
- `clone-siblings` output for `61d2f11`, quoted above, from CI run `36235385746`,
  job `Test (nix, linux-x64)` (`108386091031`).
- The published record itself,
  `locks/dev/io-mon/61d2f11a057bae9063b2a59157124d3125d340f9.xml` in
  `metacraft-labs/metacraft-manifests@latest`:
  `<project name="nim-stackable-hooks" … revision="25bf49e4ca78d4042a7f4851f5a7d4953c296741" …/>`
- **Two lock records exist for the same io-mon commit and they disagree.** For
  `61d2f11`, `locks/dev/io-mon/…​.xml` pins `25bf49e4` while
  `locks/codetracer/io-mon/…​.toml` pins `37234e9f` — the correct one.
  `clone-siblings` resolved the `dev`-project record. Which record wins is
  decided outside this repo, but it means a correct pin for this very commit
  already existed and was not the one used.
- io-mon's own committed `repro.lock` named `37234e9f` for nim-stackable-hooks
  throughout, so the repo's two channels disagreed with each other the whole
  time.
- Worked example of the misdiagnosis this invites: the failure was twice
  attributed to the **flake** pin, and `flake.lock` and then `flake.nix`'s url
  were both bumped (`3aaa2bd`). Neither changed the job, because the flake input
  reaches only `packages.default` through `STACKABLE_HOOKS_SRC` while
  `Test (nix)` runs `just`/`nimble` in the dev shell and takes
  `--path:../nim-stackable-hooks/src`. Only pinning the sibling entry turned the
  job green (`Test (nix, linux-x64)`, red → pass in 21m06s). See
  `2026-09-26-dev-shell-does-not-supply-stackable-hooks-src.md` for the
  two-channel split.

## Current mitigation, and the trap in removing it

`.github/sibling-repos` now carries an acknowledged override:

```
nim-stackable-hooks!=72f578249e9d8bbca8e3705c8a41ed5085c05bf9
```

`72f57824` is the revision `flake.nix` pins `stackable-hooks-src` to, so the two
channels name one commit.

**Removal condition:** drop the `!=` back to a bare name only once a re-locked
mainline commit pins `72f57824` or later. Until then a bare name silently
reinstates `25bf49e4` — it does not fall back to something reasonable, and it
does not warn. That is the trap, and it is why the entry carries its reasoning
inline rather than only here.

Note also that the override is per-sibling by design. It protects
`nim-stackable-hooks` and `nim-shm-gset`; `nim-shm-queue` is still resolved from
the carried set and will freeze the same way if it is ever bumped.

## Suggested direction

Options, with their costs — none is obviously right, which is why this is filed
rather than fixed:

- **Re-lock on merge.** Have the publisher re-resolve the sibling set from the
  merged commit's own `repro.lock` instead of carrying the predecessor's. Most
  correct; it makes `repro.lock` the single source of truth for both channels.
  Cost: the publisher currently _cannot invent a pin_ by design ("this workflow
  creates no lock, resolves no sibling"), so this is a change of its contract,
  not a tweak.
- **Detect and warn.** Compare the carried set against the committed
  `repro.lock` and annotate or fail when they disagree. Cheap, keeps the
  forward carry as-is, and would have caught this on the first commit after the
  bump. Cost: does not fix anything by itself.
- **Set `on-lock-override: error`** in the `setup-dev-env` call. Both overrides
  in `.github/sibling-repos` are now acknowledged with `!=`, so this is
  reachable today. It closes the _next_ unacknowledged drift rather than this
  one.

Deliberately **not** done in this pass: editing the workflow. It is shared CI
machinery with other work in flight, and the override plus this record leave the
situation strictly better and fully documented.

## Related

- `2026-09-26-dev-shell-does-not-supply-stackable-hooks-src.md` — the other half
  of why the flake pin could not fix this, and why the two channels must agree.
- `.github/sibling-repos` — carries the override and its removal condition.
- `3aaa2bd` — the flake url pin; correct on its own terms, and the reason
  `72f57824` is the revision both channels now name.
