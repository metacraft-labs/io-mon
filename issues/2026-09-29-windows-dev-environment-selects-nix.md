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
