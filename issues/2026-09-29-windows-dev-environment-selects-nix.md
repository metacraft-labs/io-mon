# io-mon dev environment selects Nix provisioning on Windows

|             |                                                   |
| ----------- | ------------------------------------------------- |
| Status      | open                                              |
| Recorded    | 2026-09-29                                        |
| Observed in | io-mon `d7f0453`, Reprobuild bootstrap `90dc4321` |
| Area        | repro.nim tool provisioning                       |

Windows x64 [job 109133838129](https://github.com/metacraft-labs/io-mon/actions/runs/36482692577/job/109133838129)
passes `repro test` and executes all five isolated injection programs again.
The following `dev-exec just build` fails during provider compilation with
`bakForeignProvision is not supported on Windows` for six Nix provisioning
edges. No product compilation occurs in that step.

The [shared dev environment contract](../../metacraft-dev-guidelines/policies/ci-shared-dev-env.md)
requires arbitrary commands to use the product's declared development
environment. The current recipe declares no provisioning default. The CI
wrapper supplies PATH provisioning for direct build/test commands, masking
the missing Windows default; arbitrary commands use the normal recipe default.
Declare PATH provisioning on Windows to match the existing Windows toolchain
bootstrap, while retaining POSIX provisioning and all cross-checks.

Refreshed dev `279a17b`, verified ancestry and searched open/deleted issues
before recording. The full job log is `/tmp/io-mon-d7-windows-repro.log`.

## Follow-up at `0f3a186`

The first repair, `1aeab2c`, placed `defaultToolProvisioning(path)` inside a
`when` block in `package io_mon`. Windows CI now stops compiling the recipe:
`Error: undeclared identifier: defaultToolProvisioning`
([job 109147056800](https://github.com/metacraft-labs/io-mon/actions/runs/36487095851/job/109147056800)).
The package DSL handles this declaration as a direct package-body node; it
does not rewrite one nested inside `when`. Use a direct declaration with a
conditional argument, as RunQuota and Gosti already do. POSIX uses Nix and
Windows uses its configured PATH toolchain. Validate Windows recipe extraction
as well as its arbitrary dev-environment commands before closing this issue.

The local macOS check did not compile the Windows-only branch and therefore
did not expose the error. The issue is reopened from history, not duplicated.

## Archive provisioning required at `31b7f72`

Windows job
[109333051380](https://github.com/metacraft-labs/io-mon/actions/runs/36546120504/job/109333051380)
passes the complete graph and repeated isolated tests, then `dev-exec just
build` fails with `Requested command not found: 'just'`. Declaring Just is
insufficient in PATH mode: this worker does not have it. Both the recipe
default and direct Windows CI commands now use the declared archive tool
store, while POSIX retains Nix. Select the source bootstrap that retains its
Windows lease daemon and the Reprobuild catalog with the Windows sleep tool.
No cross-check is removed.

At `eb4451a`, Windows job `109349391811` completes setup and archive-provisioned
build, then fails only the host-session test program in the 91-action graph.
Its private production-shim build calls Bash, which reports `dirname: command
not found` and `mkdir: command not found`. A Windows cmd built-in does not
supply those commands to Bash. Declare the pinned `install-file` provider on
Windows and on the shim/test actions: its PortableGit `usr/bin` supplies the
GNU utilities, as in Reprobuild's existing runtime-closure packaging graph.
Keep the real private source build and every session/capture assertion.
