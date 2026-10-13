## Linux shim publication uses canonical coreutils rename and empty-dir cleanup.
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package mv:
  provisioning:
    nixPackage "nixpkgs#coreutils", executablePath = "bin/mv",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash

package rmdir:
  provisioning:
    nixPackage "nixpkgs#coreutils", executablePath = "bin/rmdir",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
