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
            ];
          };
        };
    };
}
