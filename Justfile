# Standard Justfile for io-mon

stackable_hooks_src := env_var_or_default("STACKABLE_HOOKS_SRC", "../nim-stackable-hooks/src")
build_mode          := env_var_or_default("IO_MON_BUILD_MODE", "debug")

# Default target: build all components
build: build-shim build-snoop

# Build the injected shim shared library
build-shim:
    IO_MON_BUILD_MODE={{build_mode}} STACKABLE_HOOKS_SRC={{stackable_hooks_src}} scripts/build_shim.sh

# Build the standalone io-mon CLI
build-snoop:
    nim c --path:{{stackable_hooks_src}} --path:src --threads:on --out:build/bin/io-mon cmd/io_mon_snoop.nim

# Run the test suite
test:
    nimble test

# Real-build completeness oracle (§4.5(h)) — fast fixtures + class-(a) gate.
# The heavier B/C/D differentials run with: tests/realbuild/run_oracle.sh --full
#
# Needs io-mon's OWN devShell: the real builds it drives use cc, cmake, ninja,
# cargo, rustc (+ strace for --full), and those are pinned in this repo's
# flake.nix, not in the workspace shell. Run it as
#   nix develop <io-mon> -c just test-realbuild-oracle
# From a shell without them the script aborts naming the missing tool, so an
# environment gap can never be misread as an io-mon capture gap.
test-realbuild-oracle:
    tests/realbuild/run_oracle.sh --fast

# Run portable tests only
test-portable:
    nimble testPortable

# Run platform tests only
test-platform:
    nimble testPlatform

# Lint all files
lint: lint-nix

# Format all files
format: format-nix

# Internal lint recipes
lint-nix:
    nixfmt --check flake.nix

# Internal format recipes
format-nix:
    nixfmt flake.nix

# Short aliases
alias t := test
alias fmt := format
