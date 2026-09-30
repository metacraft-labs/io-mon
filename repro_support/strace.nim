## Independent syscall observer used by the Linux loader-closure tests.
## The selected Reprobuild stdlib has no strace package, so declare its Nix
## realization here instead of depending on an ambient host installation.
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package strace:
  provisioning:
    nixPackage "nixpkgs#strace", executablePath = "bin/strace",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
