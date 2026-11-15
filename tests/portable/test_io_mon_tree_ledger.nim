## test_io_mon_tree_ledger — the tree ledger's names and directory listing
## (`io_mon/tree_ledger`), which the macOS tree-lifetime guard reads to find
## live processes whose argument/environment area no longer names the run.
## The live behaviour is pinned by case 10 of
## tests/macos/test_io_mon_macos_tree_lifetime_guard.nim; this file pins the
## pure parts on every OS.
import std/[os, tempfiles, unittest]
import io_mon/tree_ledger

suite "tree ledger":
  test "a name round-trips its (pid, start) identity":
    var e: TreeLedgerEntry
    check parseTreeLedgerName(treeLedgerName(4242, 1793328262003506'u64), e)
    check e == (4242, 1793328262003506'u64)
    check parseTreeLedgerName(treeLedgerName(7, 0), e)
    check e == (7, 0'u64)

  test "a pid-namespace marker round-trips and is never read as an entry":
    var ino = 0'u64
    check parseTreeLedgerPidNsName(treeLedgerPidNsName(4026531836'u64), ino)
    check ino == 4026531836'u64
    var e: TreeLedgerEntry
    check not parseTreeLedgerName(treeLedgerPidNsName(4026531836'u64), e)
    for name in ["repro-tree-pidns-.iomon-tree", "repro-tree-pidns-0.iomon-tree",
                 "repro-tree-pidns-x.iomon-tree", "repro-tree-12-34.iomon-tree"]:
      check not parseTreeLedgerPidNsName(name, ino)
    let dir = createTempDir("io-mon-tree-ledger-ns-", "")
    defer: removeDir(dir)
    writeFile(dir / treeLedgerPidNsName(9), "")
    writeFile(dir / treeLedgerPidNsName(3), "")
    writeFile(dir / treeLedgerName(12, 34), "")
    var inodes: seq[uint64]
    check readTreeLedgerPidNamespaces(dir, inodes)
    check inodes == @[3'u64, 9'u64]
    var entries: seq[TreeLedgerEntry]
    check readTreeLedger(dir, entries)
    check entries == @[(12, 34'u64)]
    check not readTreeLedgerPidNamespaces(dir / "missing", inodes)

  test "a pid-namespace link target names its inode":
    for (text, want) in [("pid:[4026531836]", 4026531836'u64),
                         ("pid:[]", 0'u64), ("pid:[12", 0'u64), ("", 0'u64)]:
      var buf = newSeq[char](text.len)
      for i, c in text: buf[i] = c
      check parsePidNamespaceLink(buf, buf.len) == want

  test "anything else is not an entry":
    var e: TreeLedgerEntry
    for name in ["repro-monitor-1-2.iomon-frag", "repro-tree-1-2.iomon-frag",
                 "repro-tree--2.iomon-tree", "repro-tree-1-.iomon-tree",
                 "repro-tree-0-5.iomon-tree", "repro-tree-x-5.iomon-tree",
                 "repro-tree-1-5-6.iomon-tree", "repro-tree-15.iomon-tree"]:
      check not parseTreeLedgerName(name, e)

  test "the listing is sorted, ignores other files, and fails on no dir":
    let dir = createTempDir("io-mon-tree-ledger-", "")
    defer: removeDir(dir)
    for (pid, start) in [(30, 5'u64), (4, 9'u64), (30, 1'u64)]:
      writeFile(dir / treeLedgerName(pid, start), "")
    writeFile(dir / "repro-monitor-4-1.iomon-frag", "x")
    createDir(dir / treeLedgerName(99, 1))   # a directory is not an entry
    var entries: seq[TreeLedgerEntry]
    check readTreeLedger(dir, entries)
    check entries == @[(4, 9'u64), (30, 1'u64), (30, 5'u64)]
    check not readTreeLedger(dir / "missing", entries)
    check entries.len == 0
    check not readTreeLedger("", entries)

  when defined(posix):
    test "marking is idempotent and reports a real failure":
      let dir = createTempDir("io-mon-tree-ledger-mark-", "")
      defer: removeDir(dir)
      check markTreeLedger(dir, 12, 34) == 0
      check markTreeLedger(dir, 12, 34) == 0
      var entries: seq[TreeLedgerEntry]
      check readTreeLedger(dir, entries)
      check entries == @[(12, 34'u64)]
      check markTreeLedger(dir / "missing", 12, 34) != 0
