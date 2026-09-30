## Clang invokes lipo to combine the shim's arm64 and arm64e objects.
## This package also supplies Mach-O nm for the standalone symbol checks.
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package cctools:
  provisioning:
    nixPackage "nixpkgs#darwin.cctools", executablePath = "bin/lipo",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
