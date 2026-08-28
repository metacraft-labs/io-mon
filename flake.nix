{
  description = "Filesystem and process monitoring library and tools";

  inputs = {
    nixos-modules.url = "github:metacraft-labs/nixos-modules";
    nixpkgs.follows = "nixos-modules/nixpkgs-unstable";
    flake-parts.follows = "nixos-modules/flake-parts";
    git-hooks.follows = "nixos-modules/git-hooks-nix";
    stackable-hooks-src = {
      url = "github:metacraft-labs/nim-stackable-hooks";
      flake = false;
    };
  };

  outputs =
    inputs@{ flake-parts, nixos-modules, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        nixos-modules.modules.flake.git-hooks
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, config, ... }:
        let
          version = builtins.replaceStrings [ "\n" "\r" ] [ "" "" ] (builtins.readFile ./version.txt);
        in
        {
          pre-commit.settings.hooks = {
            shellcheck.enable = true;
            nixfmt.enable = true;
            check-license = {
              enable = true;
              name = "Check License File";
              entry = "bash -c 'if [ ! -f LICENSE ] && [ ! -f LICENSE-APACHE ] && [ ! -f LICENSE-MIT ]; then echo \"Error: No license file (LICENSE, LICENSE-APACHE, LICENSE-MIT) found in repository root!\"; exit 1; fi'";
              files = "^$";
              pass_filenames = false;
            };
          };

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "io-mon";
            inherit version;
            src = ./.;

            nativeBuildInputs = [
              pkgs.just
              pkgs.nim2
            ];

            STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src";

            buildPhase = ''
              runHook preBuild
              just build
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/lib"
              if [ -f build/bin/io-mon ]; then
                install -m755 build/bin/io-mon "$out/bin/io-mon"
              fi
              for lib in build/lib/*; do
                [ -e "$lib" ] || continue
                install -m755 "$lib" "$out/lib/$(basename "$lib")"
              done
              runHook postInstall
            '';
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ config.pre-commit.devShell ];
            packages = [
              pkgs.just
              pkgs.nim2
              pkgs.nimble
              pkgs.git
              pkgs.nixfmt
              # tests/linux/test_io_mon_library_load_closure.nim derives its
              # ground truth from `strace -f -e trace=openat`: the loader
              # closure io-mon claims to observe is compared against the one
              # the kernel actually opened. Without strace in the shell that
              # comparison cannot run, and CI failed with "Could not find
              # command: 'strace'" while it passed on developer machines that
              # happened to have it on PATH.
              pkgs.strace
              # The §4.5(h) REAL-BUILD COMPLETENESS ORACLE
              # (`just test-realbuild-oracle`, tests/realbuild/run_oracle.sh) —
              # the cardinal-sin gate: it drives real cmake+ninja and cargo
              # builds under the shim and checks io-mon's captured input set
              # against the toolchain's OWN dependency data (`ninja -t deps`,
              # cargo/rustc `--emit=dep-info`) and against `strace -f`.
              #
              # These were left to the AMBIENT environment, and the result was a
              # documented `just` target that could not run from ANY shell:
              # measured, `just test-realbuild-oracle` exited 2 with
              # "missing required tool(s) from the ambient environment: cmake
              # cargo rustc" in io-mon's own devShell AND in a bare workspace
              # shell. The script also pulled ninja in with
              # `nix shell nixpkgs#ninja`, a MUTABLE FLAKE-REGISTRY lookup that
              # resolves against whatever nixpkgs the machine last synced.
              #
              # Pinning them is not merely convenience. The oracle's verdict is
              # a comparison against the toolchain's own dep data, so the
              # toolchain is part of the EXPERIMENT: an unpinned cmake/rustc/
              # ninja means the gate measures a different thing on every
              # machine, and a capture gap could appear or vanish with a
              # compiler bump rather than with an io-mon change.
              pkgs.cmake
              pkgs.ninja
              pkgs.cargo
              pkgs.rustc
            ];
          };
        };
    };
}
