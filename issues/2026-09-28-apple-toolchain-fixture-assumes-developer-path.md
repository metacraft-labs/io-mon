# Toolchain fixture rejects the pinned Nix Clang path

- Status: open
- Observed in: io-mon `26e7f08`, full native macOS catalog

## Observed and planned repair

At 26e7f08, xcrun resolves the pinned Clang under /nix/store. The resolver succeeds and the compiler is outside SIP prefixes, but the test requires Developer in its filename. Verify the compiler identity by executing it, preserving file existence and SIP assertions. Expectation: resolveAppleToolchainTool documents xcrun resolution; no spec requires a path substring.

Refreshed origin/dev and origin/agents; searched open issues and issue history
for the fixture names and failing expressions before recording.
