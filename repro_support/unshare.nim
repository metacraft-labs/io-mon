## util-linux's `unshare(1)`, which the Linux tests that need an unprivileged
## user namespace run (tests/helpers/userns_requirement.nim). The selected
## Reprobuild stdlib has no `unshare` package, and an action that declares
## tool refs gets only their directories on PATH, so without this package
## `findExe("unshare")` failed under `repro test` and those cases skipped as
## "no unshare on PATH".
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package unshare:
  provisioning:
    nixPackage "nixpkgs#util-linux", executablePath = "bin/unshare",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
