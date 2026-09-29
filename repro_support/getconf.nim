## The Linux shim uses getconf to select its glibc heap and symbol versions.
## Keep the probe available inside the shim build and test action environments.
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package getconf:
  provisioning:
    nixPackage "nixpkgs#glibc.bin", executablePath = "bin/getconf",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
