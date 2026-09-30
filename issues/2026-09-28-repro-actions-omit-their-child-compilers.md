# Reprobuild actions omit their child compilers

Status: open. Recorded 2026-09-28.

At io-mon `73e4792`, [macOS job 109024094922](https://github.com/metacraft-labs/io-mon/actions/runs/36450606215/job/109024094922) passes source bootstrap, then the shim script fails with `nim: command not found` and test builds fail with `clang: command not found`.

The recipe declares both packages in `uses`, but the shell action references only its shell and `buildNimUnittest` references only Nim. Neither declares the compiler it spawns. Test execution also compiles real fixtures and invokes Bash.

[Dependency-Provisioning-In-Build-Graph](../../reprobuild-specs/Dependency-Provisioning-In-Build-Graph.md) requires downstream actions to depend on the tools they consume. Attach the platform compiler to test builds, and attach Nim, the compiler and Bash to actions that build fixtures or the shim. Preserve the full monitored test catalog.

Fetched `origin/dev` at `279a17b`, confirmed it is already an ancestor of this branch, and searched current and deleted issues before recording.
