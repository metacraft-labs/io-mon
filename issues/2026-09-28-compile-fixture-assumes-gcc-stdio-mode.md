# Compiler fixture assumes every compiler opens its output with w+

- Status: open
- Observed in: io-mon `26e7f08`, full native macOS catalog

## Observed and planned repair

At 26e7f08 on macOS, Clang produces the correct object and write record without a read-open record. The test assumes the GCC assembler uses w+. Keep the compiler output-write assertion and exercise both sides of w+ with a real explicit stdio fixture. Expectation: the filesystem monitoring spec classifies actual operations; it does not prescribe a compiler implementation.

Refreshed origin/dev and origin/agents; searched open issues and issue history
for the fixture names and failing expressions before recording.
