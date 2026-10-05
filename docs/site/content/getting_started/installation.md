---
title: Installation
description: Install io-mon via quick bootstrap script, apt, rpm, brew, scoop, nix, pre-compiled binaries, or from source.
section: getting_started
order: 2
---

# Installation

`io-mon` is distributed through multiple package managers, official release binaries, and a platform-detecting installer script.

---

## Quick Installation Script

The fastest way to install the latest pre-compiled release of `io-mon` is with the Metacraft installer script:

### Linux & macOS

```bash
curl -fsSL https://install-package.metacraft-labs.com/io-mon/sh | sh
```

### Windows (PowerShell)

```powershell
irm https://install-package.metacraft-labs.com/io-mon/pwsh | iex
```

The script detects your host architecture and operating system, downloads the matching release archive, verifies checksums, and places the `io-mon` binary and its interposition shims into your local path.

---

## Package Managers

Official packages are maintained across major platforms.

### Debian / Ubuntu (`apt`)

Add the Metacraft APT repository and install `metacraft-io-mon`:

```bash
# Add the repository signing key and source list
curl -fsSL https://deb.metacraft-labs.com/KEY.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/metacraft.gpg
echo "deb [signed-by=/etc/apt/keyrings/metacraft.gpg] https://deb.metacraft-labs.com stable main" | sudo tee /etc/apt/sources.list.d/metacraft.list

# Update and install
sudo apt-get update
sudo apt-get install metacraft-io-mon
```

### Fedora / RHEL (`rpm`)

Configure the RPM repository and install with `dnf`:

```bash
sudo dnf config-manager --add-repo https://rpm.metacraft-labs.com/metacraft.repo
sudo dnf install metacraft-io-mon
```

### macOS Homebrew

Install via the official Metacraft Homebrew tap:

```bash
brew tap metacraft-labs/metacraft
brew install io-mon
```

### Windows Scoop

Install using Scoop on Windows:

```powershell
scoop bucket add metacraft https://github.com/metacraft-labs/scoop-bucket.git
scoop install io-mon
```

### Nix

Install directly via Flakes:

```bash
nix profile install github:metacraft-labs/nixpkgs#io-mon
```

Or enter a temporary development shell:

```bash
nix shell github:metacraft-labs/nixpkgs#io-mon
```

---

## GitHub Releases

Standalone release binaries and companion shim libraries for Linux (x86_64, aarch64), macOS (Apple Silicon, Intel), and Windows (x86_64) are available directly on GitHub:

👉 [metacraft-labs/io-mon Releases](https://github.com/metacraft-labs/io-mon/releases)

Each archive contains:

- `io-mon` executable
- `librepro_monitor_shim.so` (Linux), `librepro_monitor_shim.dylib` (macOS), or `repro_monitor_shim.dll` (Windows)

---

## Building from Source

To compile `io-mon` directly from source, ensure you have [Nim 2.0+](https://nim-lang.org/) and a C compiler installed.

Clone the repository and build:

```bash
git clone https://github.com/metacraft-labs/io-mon.git
cd io-mon

# Build the CLI and default shims using just
just build
```

The resulting binaries will be placed in `build/bin/io-mon` and `build/lib/`.
