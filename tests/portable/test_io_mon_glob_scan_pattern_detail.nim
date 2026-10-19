## `globScanPattern` reads back exactly what a backend wrote, and nothing
## else.
##
## WHY. A pattern-scoped enumeration lets a consumer key an action on the
## entries that match the pattern instead of the whole listing. A parser that
## returned a pattern for a record that was NOT scoped, or returned the wrong
## one, would narrow a dependency the action really had: a false cache hit. So
## every doubtful detail must read as "full" (""). The writer appends its own
## tokens (`run=<id>`) to every detail, which is why the parser is token-based
## and a prefix match is not enough.
##
## Mocks: none; the parser is a pure function over the detail text.

import std/unittest

import io_mon/types

suite "pattern-scoped enumeration detail":
  test "t_the_written_detail_reads_back_as_its_pattern":
    check globScanPattern(GlobPatternDetailPrefix & "*.nimble") == "*.nimble"
    check globScanPattern(GlobPatternDetailPrefix & "a?b*") == "a?b*"

  test "t_tokens_the_writer_appends_are_not_part_of_the_pattern":
    check globScanPattern(GlobPatternDetailPrefix & "*.nimble run=17.5-3-1") ==
      "*.nimble"
    check globScanPattern(GlobPatternDetailPrefix &
      "* run=1 nested-run=2") == "*"

  test "t_anything_else_reads_as_a_full_enumeration":
    for detail in ["", "glob", "glob run=1", "scandir", "readdir",
                   "glob pattern=", "glob pattern= run=1",
                   "pattern=*.nimble", "scandir pattern=*.nimble",
                   "globber pattern=*.nimble",
                   # two patterns are ambiguous: neither may narrow the key
                   "glob pattern=*.nimble pattern=*",
                   # outside the contract: a matcher that knows only
                   # literals, `*` and `?` would reject names glob accepted
                   "glob pattern=a/*.nimble", "glob pattern=[ab]*",
                   "glob pattern=\\*.nimble"]:
      checkpoint(detail)
      check globScanPattern(detail) == ""
