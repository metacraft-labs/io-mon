## Whether a Linux test may skip because this host refuses unprivileged user
## namespaces, or must fail.
##
## Several Linux tests need an unprivileged user namespace: the pid-namespace
## cases of `test_io_mon_linux_tree_ledger`, the `/bin/sh` swap of
## `test_io_mon_uninjectable_image_entry` and the overlay layout of
## `test_io_mon_inline_site_table`. On a developer's host that refuses them
## (Ubuntu 24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, and a
## container may set `user.max_user_namespaces=0`) they report an explicit
## skip with the reason.
##
## In CI that skip is wrong: the lane is meant to check these cases, and a
## refused namespace there is a defect of the runner configuration, not a
## platform limit. The hosted Ubuntu runner skipped all four tree-ledger
## cases on every Linux run until the workflow lifted the restriction
## (reprobuild-pm issue
## 2026-11-26-io-mon-pid-namespace-tree-ledger-tests-skip-on-the-hosted-ubuntu-runner-ci-yml-selects).
## A lane that guarantees unprivileged user namespaces sets
## `IO_MON_TEST_REQUIRE_USERNS=1`, and then the same refusal is a failure
## that names its cause, so a later runner change cannot bring the skips back
## unnoticed.
##
## The kernel interface is documented in user_namespaces(7):
## https://man7.org/linux/man-pages/man7/user_namespaces.7.html

import std/[os, osproc, streams, strutils]

const RequireUsernsEnv* = "IO_MON_TEST_REQUIRE_USERNS"
  ## `1`: this run guarantees unprivileged user namespaces, and a refusal
  ## fails the test. Unset, empty or `0`: a refusal is an explicit skip.

proc usernsRequired*(): bool =
  ## Whether `RequireUsernsEnv` asks for unprivileged user namespaces.
  ## Raises `ValueError` on any other value, so a misspelt setting cannot
  ## quietly leave the skips in place.
  let value = getEnv(RequireUsernsEnv).strip()
  case value
  of "", "0": false
  of "1": true
  else:
    raise newException(ValueError, RequireUsernsEnv & " must be 1, 0 or " &
      "unset, not '" & value & "'")

proc usernsRefusal*(extra: openArray[string] = []): string =
  ## Empty when this process may create a user namespace (plus the `extra`
  ## `unshare(1)` flags) as an unprivileged user and run a command in it;
  ## otherwise why it may not. A mount namespace should be asked for with
  ## `--propagation slave`: util-linux defaults to private, and a private copy
  ## keeps every host mount it copied mounted until the namespace ends,
  ## because the host's unmount never reaches it (and, locked by the user
  ## namespace, nothing inside can unmount it either).
  let unshare = findExe("unshare")
  if unshare.len == 0:
    return "no unshare on PATH"
  let p = startProcess(unshare, args = @["--user", "--map-root-user"] &
    @extra & @["true"], options = {poStdErrToStdOut})
  try:
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    if code != 0:
      result = "unprivileged namespaces are unavailable: " &
        output.strip() & " (unshare exit " & $code & ")"
  finally:
    p.close()

template skipOrRequireUserns*(reason: string) =
  ## Ends the current `unittest` test because unprivileged user namespaces
  ## are refused for `reason`: an explicit skip with the reason, or, when
  ## `usernsRequired()`, a failure with it. Use only inside a `test` body,
  ## and do not call `skip()` after it: that would turn the failure back into
  ## a skip.
  let why = reason
  if usernsRequired():
    checkpoint(RequireUsernsEnv & "=1, so this run must provide " &
      "unprivileged user namespaces, but: " & why)
    fail()
  else:
    echo "    SKIP: ", why
    skip()
