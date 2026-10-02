# Reprobuild omits the optional macOS Python startup control

## Observed in

io-mon `2b0bd752877c0cd555a00a1b0f65785f0c2b6f9f`, macOS ARM64,
2026-10-02. The native `just test` reports 491 passing assertions. The
Reprobuild graph reports 182 successful actions, including 69 executed test
programs, but only 490 passing assertions. Its readdir INODE64 fixture prints:

```text
[SKIPPED] a real python3 STARTS under the shim (encodings import works)
```

The action environment lacks `python3`; `repro.nim` does not declare that
tool. The same real Python startup case passes in the native dev-shell run.
The local Reprobuild binary is built at
`c14b1e618d7c4b64476d89792e80b8e8f10b8a52`; direct mode preserves normal
monitoring of graph actions. This optional skip predates the release work.

## Expected and proposed change

The test header explicitly makes the Python control optional when no
interpreter is available; mandatory execution is not currently specified.
Proposed: declare Python in the controlled macOS test environment and require
its availability there. This would make the documented end-to-end startup
control reliable while preserving the existing real directory-byte and
capture assertions. Do not report this graph as executing that Python case
until its output proves it ran.

## Evidence

`tests/macos/test_io_mon_macos_readdir_inode64.nim` calls `findRealPython`
and `skip()` when the result is empty. The native and Reprobuild outputs
have the same passing case names except this one. Local evidence is
`/tmp/io-mon-011-local-gates.log` and `/tmp/io-mon-011-repro.json`.

## Archive search

Fetched `origin/agents` and confirmed it still names `2b0bd75`. Searched
open and resolved issue history for Python, readdir and `findRealPython`;
no existing issue records this optional-control provisioning gap.
