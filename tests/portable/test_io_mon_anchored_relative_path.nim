## `anchoredRelativePath` joins a relative path onto its anchor directory the
## way the kernel resolves it, without folding a `..` that follows a
## component of the caller's path.
##
## WHY. The Linux shim's `pathForAt` records every relative open, probe,
## enumeration and mutation through this join. It used Nim's `os./`, which
## folds every `..` lexically, so `link/../file` (with `link -> sub/target`)
## was recorded `<root>/file` while the kernel opened `<root>/sub/file`
## (reprobuild-pm issue 2026-10-21-linux-shim-folds-dotdot-after-a-symlink-
## lexically; spec reprobuild-pm/spec/Monitor-Hook-Shim.md § "Metadata,
## Probe, And Symlink APIs": "`..` after a link applies to where the link
## points"). Only a LEADING `..` may be applied to the anchor, and only when
## the anchor is symlink-free; the live shim behaviour is covered by
## tests/linux/test_io_mon_linux_dotdot_after_symlink.nim.
##
## Mocks: none; the join is a pure function over two strings.

import std/unittest

import io_mon/paths

suite "anchoredRelativePath":
  test "t_a_dotdot_after_a_component_is_kept":
    check anchoredRelativePath("/r", "link/../file") == "/r/link/../file"
    check anchoredRelativePath("/r", "a/b/../../c") == "/r/a/b/../../c"
    check anchoredRelativePath("/r", "../a/../b") == "/a/../b"

  test "t_a_leading_dotdot_run_pops_the_anchor":
    check anchoredRelativePath("/r/w", "../x") == "/r/x"
    check anchoredRelativePath("/r/w/v", "../../x") == "/r/x"
    check anchoredRelativePath("/r/w", "./.././x") == "/r/x"
    check anchoredRelativePath("/r/w", "..") == "/r"
    check anchoredRelativePath("/r/w", "../..") == "/"

  test "t_dotdot_at_the_root_stays_at_the_root":
    # `os./` gave "/../x" here; the kernel resolves "/.." to "/".
    check anchoredRelativePath("/", "../x") == "/x"
    check anchoredRelativePath("/r", "../../../x") == "/x"
    check anchoredRelativePath("/", "..") == "/"

  test "t_empty_components_and_dots_are_squeezed":
    check anchoredRelativePath("/r", "a//b") == "/r/a/b"
    check anchoredRelativePath("/r", "./a/./b/.") == "/r/a/b"
    check anchoredRelativePath("/r", ".") == "/r"
    check anchoredRelativePath("/r/", "a") == "/r/a"
    check anchoredRelativePath("/", "a") == "/a"

  test "t_a_trailing_slash_is_kept":
    check anchoredRelativePath("/r", "refs/") == "/r/refs/"
    check anchoredRelativePath("/r/w", "../") == "/r/"
    check anchoredRelativePath("/r", "a/./") == "/r/a/"
    check anchoredRelativePath("/r/w", "../../") == "/"

  test "t_without_popping_every_dotdot_is_kept":
    # The anchor may end in a symlink (a dirfd's recorded spelling).
    check anchoredRelativePath("/r/link", "../f",
      popLeadingParents = false) == "/r/link/../f"
    check anchoredRelativePath("/r/link/../d", "e",
      popLeadingParents = false) == "/r/link/../d/e"
    check anchoredRelativePath("/r/link/../d", "e") == "/r/link/../d/e"

  test "t_a_relative_anchor_is_never_popped":
    check anchoredRelativePath("rel", "../x") == "rel/../x"
    check anchoredRelativePath("", "a/b") == "a/b"

  test "t_an_absolute_relative_part_is_returned_unchanged":
    check anchoredRelativePath("/r", "/abs/../x") == "/abs/../x"

  test "t_startsWithParentRef_sees_through_dots_and_slashes":
    check startsWithParentRef("../x")
    check startsWithParentRef("./../x")
    check startsWithParentRef(".//..")
    check startsWithParentRef("..")
    check not startsWithParentRef("link/../x")
    check not startsWithParentRef("..x")
    check not startsWithParentRef(".")
    check not startsWithParentRef("")
    check not startsWithParentRef("x")
