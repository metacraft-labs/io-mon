## test_io_mon_userns_requirement: a refused unprivileged user namespace is
## a skip on a developer's host and a failure on a run that sets
## `IO_MON_TEST_REQUIRE_USERNS=1` (`tests/helpers/userns_requirement.nim`).
##
## The pid-namespace cases of test_io_mon_linux_tree_ledger skipped on every
## hosted Ubuntu CI run, because that image refuses unprivileged user
## namespaces, and nothing let CI fail them instead (reprobuild-pm issue
## 2026-11-26-io-mon-pid-namespace-tree-ledger-tests-skip-on-the-hosted-ubuntu-runner-ci-yml-selects).
## CI now sets the switch. This test proves the switch works, against a real
## kernel refusal rather than a stand-in.
##
## A probe program that uses the helper exactly as the namespace-dependent
## tests do (`usernsRefusal`, then `skipOrRequireUserns`) is compiled and run
## inside a user namespace whose `user.max_user_namespaces` is 0, so the
## kernel refuses the nested `unshare --user` the probe makes (ENOSPC, see
## user_namespaces(7) and
## https://man7.org/linux/man-pages/man7/user_namespaces.7.html "Limits on
## the number of user namespaces"). The outer namespace's root owns that
## limit, so no host setting changes. The probe runs as that namespace's
## root; the helper's decision does not depend on the uid.
##
## Cases:
##  1. refused, switch unset: the probe's case is `[SKIPPED]`, it names the
##     refusal, and the program exits 0;
##  2. refused, `IO_MON_TEST_REQUIRE_USERNS=1`: the case is `[FAILED]`, names
##     the refusal and the switch, and the program exits non-zero;
##  3. refused, `IO_MON_TEST_REQUIRE_USERNS=0`: as 1;
##  4. a malformed value fails the case rather than leaving the skip in place;
##  5. control: not refused, switch set: the case is `[OK]`, so the switch
##     does not fail a host that grants namespaces.
##
## This test itself needs an unprivileged user namespace to make the refusing
## one, so where the host refuses that it skips, or fails under the switch,
## through the same helper.
##
## Mocks: none. A real compiled probe, real `unshare(1)`, a real kernel limit.
import std/[os, osproc, streams, strtabs, strutils, tempfiles, unittest]
import userns_requirement

const helpersDir = currentSourcePath().parentDir().parentDir() / "helpers"

const probeSource = """
import std/unittest
import userns_requirement

suite "probe":
  test "needs a user namespace":
    let refusal = usernsRefusal()
    if refusal.len > 0:
      skipOrRequireUserns(refusal)
    else:
      check true
"""

# Refuses every nested user namespace inside the one it runs in, then runs
# the probe there: root of the new namespace owns `user.max_user_namespaces`.
const refuseNested =
  "echo 0 > /proc/sys/user/max_user_namespaces && exec \"$@\""

suite "IO_MON_TEST_REQUIRE_USERNS":
  let work = createTempDir("io-mon-userns-requirement-", "")
  let probe = work / "probe"
  block:
    writeFile(work / "probe.nim", probeSource)
    let nim = findExe("nim")
    doAssert nim.len > 0, "nim is required to build the probe"
    let (output, code) = execCmdEx(quoteShell(nim) & " c --hints:off" &
      " --path:" & quoteShell(helpersDir) &
      " --nimcache:" & quoteShell(work / "nimcache") &
      " --out:" & quoteShell(probe) & " " & quoteShell(work / "probe.nim"))
    doAssert code == 0, "probe compilation failed: " & output

  proc runProbe(switch: string; refused: bool): tuple[output: string,
                                                    code: int] =
    ## Run the probe with `IO_MON_TEST_REQUIRE_USERNS` set to `switch`
    ## (removed when empty), in a namespace that refuses nested user
    ## namespaces when `refused`.
    let env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      if key != RequireUsernsEnv: env[key] = value
    if switch.len > 0: env[RequireUsernsEnv] = switch
    let (exe, args) =
      if refused:
        (findExe("unshare"), @["--user", "--map-root-user", "sh", "-c",
          refuseNested, "sh", probe])
      else:
        (probe, newSeq[string]())
    let p = startProcess(exe, args = args, env = env,
      options = {poStdErrToStdOut})
    try:
      result.output = p.outputStream.readAll()
      result.code = p.waitForExit()
    finally:
      p.close()
    checkpoint("switch='" & switch & "' refused=" & $refused & " exit " &
      $result.code & ":\n" & result.output)

  # The refusing namespace is itself an unprivileged user namespace.
  let setupRefusal = usernsRefusal()

  template requireSetup(body: untyped) =
    if setupRefusal.len > 0:
      skipOrRequireUserns(setupRefusal)
    else:
      body

  test "1. a refused namespace is an explicit skip by default":
    requireSetup:
      let r = runProbe("", refused = true)
      check r.code == 0
      check "[SKIPPED] needs a user namespace" in r.output
      check "SKIP: unprivileged namespaces are unavailable" in r.output
      check "[FAILED]" notin r.output

  test "2. under IO_MON_TEST_REQUIRE_USERNS=1 it fails and names the cause":
    requireSetup:
      let r = runProbe("1", refused = true)
      check r.code != 0
      check "[FAILED] needs a user namespace" in r.output
      check "[SKIPPED]" notin r.output
      check "IO_MON_TEST_REQUIRE_USERNS=1, so this run must provide " &
        "unprivileged user namespaces" in r.output
      check "unprivileged namespaces are unavailable" in r.output

  test "3. IO_MON_TEST_REQUIRE_USERNS=0 keeps the skip":
    requireSetup:
      let r = runProbe("0", refused = true)
      check r.code == 0
      check "[SKIPPED] needs a user namespace" in r.output

  test "4. a malformed IO_MON_TEST_REQUIRE_USERNS fails the case":
    requireSetup:
      let r = runProbe("yes", refused = true)
      check r.code != 0
      check "[SKIPPED]" notin r.output
      check "IO_MON_TEST_REQUIRE_USERNS must be 1, 0 or unset, not 'yes'" in
        r.output

  test "5. control: a host that grants namespaces passes under the switch":
    requireSetup:
      let r = runProbe("1", refused = false)
      check r.code == 0
      check "[OK] needs a user namespace" in r.output

  removeDir(work)
