# The codec's memory safety is graded by nothing: no sanitizer runs in CI

| | |
|---|---|
| Status | open |
| Recorded | 2026-09-24 |
| Observed in | io-mon @ `2717ce8` |
| Area | `src/io_mon/codec.nim` (`writeString`, `toBytes`), CI |

*This is the first issue filed in this repo, so the archive search required by
[recording-issues.md](../../metacraft-dev-guidelines/policies/recording-issues.md)
had nothing to search. Recorded rather than silently skipped.*

## Observed

`writeString`'s **destination sizing** is checked by no test in the tree.

Measured while reviewing the string-body bulk copy (merged as PR #25). Mutation
`m02` grows the write length by one byte:

```
heap-buffer-overflow WRITE of size 33, 0 bytes after a 144-byte region
  in writeString <- encodeFrame
```

Against that mutant the **whole suite is green** — all 51 pre-existing files,
plus both new wire-format test files. Byte-identity checks pass too, and they
cannot do otherwise: the extra byte is the NUL terminator, so the logical
contents are unchanged and there is no output for any oracle to compare.

Only ASan sees it, and **no sanitizer job runs in io-mon CI at all**. Two
further mutations are in the same position — `m09` (bounds check removed) and
`m10` (off-by-one) are both reached through the negative wire oracle, and `m09`
only reddens by OOM/crash rather than by a verdict.

## Expected

A memory-safety defect in the codec should be caught by something that runs
without a reviewer choosing to run it. `readString`'s **correctness** is graded
— its bounds check has a case, and `detaillen_one_byte_past_the_payload`
separates a slack bound from a correct one by verdict. Its **memory safety**,
and `writeString`'s sizing, are not.

## Evidence

- `m02` green across 53 files; ASan reports the overflow.
- `m09`, `m10`: OOB reads, caught only under ASan.
- No sanitizer arm exists in `.github/workflows/`.

## Suggested direction

An ASan/UBSan CI arm over the portable test tier.

**It requires `-d:useMalloc`** — without it ASan sees none of Nim's
allocations, because the per-thread regions are not malloc'd. Note the
irony: that is the same flag whose `{.error.}` guard caused the mainline
regression fixed in #29, so the arm must pass it explicitly rather than
inherit it.

## Why this is not urgent

The write-side length is `value.len`, one expression above the `copyMem` — it
is **not file-controlled**, unlike `readString`'s `length`, which comes off the
wire and is why that bounds check is load-bearing. The shape is also
pre-existing: `toBytes` has had it since `eb3aece`. This is a coverage gap, not
a live vulnerability.

## Related

- PR #25 — the string-body bulk copy whose review found this.
- Issue #26 / PR #29 — the `-d:useMalloc` guard regression, same flag.
