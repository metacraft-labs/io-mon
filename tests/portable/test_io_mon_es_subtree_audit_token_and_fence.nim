## test_io_mon_es_subtree_audit_token_and_fence — the EndpointSecurity
## process-subtree view keys members on the audit token, holds what a
## cross-client view cannot yet resolve, and is closed by an end-of-capture
## fence that never finalizes a capture as complete while it could have lost
## events.
##
## Governing text: reprobuild-pm spec/MacOS-EndpointSecurity-Backend.md
## §"4. Process-subtree filtering" and §"5.1 The end-of-capture fence"
## (amended 2026-11-16, review finding R17-08). Written as the adversarial test
## for reprobuild-pm issue
## issues/2026-11-16-io-mon-es-process-tree-keys-on-bare-pid-and-has-no-capture-fence.md:
## against the earlier pid-keyed `EsProcessTree` the reuse, late-event and
## held-event cases fail (a pid cannot tell the out-of-tree process that
## reuses a member's pid from that member, and an event seen before its FORK on
## another client was rejected and lost with no sequence gap to report it).
##
## Pure and SDK-free: it drives the production `EsProcessTree` procs the ES
## message pump calls, with the lifecycle and file events a client would
## deliver written out as calls. No mocks. The seed race and the marker itself
## need the entitled client and are outside what a portable test can show.

import foreign_preload_isolation

import std/[strutils, unittest]
import io_mon/types
import io_mon/backends/endpoint_security

proc tok(pid: uint64; pidversion: uint32): EsAuditToken =
  EsAuditToken(pid: pid, pidversion: pidversion)

let helper = tok(500, 1)
let root = tok(1000, 7)
let child = tok(1100, 3)

proc openRec(pid: uint64; path: string): MonitorRecord =
  esOpenRecord(pid, 1000, path, 0'u32)

suite "ES subtree view — identity is the audit token, not the pid":
  test "an out-of-tree process reusing an exited member's pid is rejected":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onFork(root, child)
    view.onExit(child)
    # The exited member is retained until the fence ...
    check view.inSubtree(child)
    # ... and a later process that inherits pid 1100 has a new pidversion.
    let reuser = tok(1100, 4)
    check not view.inSubtree(reuser)
    check view.filterEvent(reuser, openRec(1100, "/etc/passwd")) == efReject

  test "a late event of an exited member is still admitted before the fence":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onFork(root, child)
    view.onExit(child)
    check view.filterEvent(child, openRec(1100, "/src/a.c")) == efAdmit

  test "an exec target with a new token stays in the subtree":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onFork(root, child)
    let postExec = tok(1100, 9)       # same pid, token changed by the exec
    discard view.onExec(child, postExec)
    check view.inSubtree(postExec)
    check view.filterEvent(postExec, openRec(1100, "/usr/bin/cc")) == efAdmit

  test "an exec by a non-member does not admit its target":
    var view = initEsProcessTree(helper)
    discard view.onExec(tok(4242, 1), tok(4242, 2))
    check not view.inSubtree(tok(4242, 2))

  test "the action root is admitted by its FORK from the seeded helper":
    var view = initEsProcessTree(helper)
    check not view.inSubtree(root)
    discard view.onFork(helper, root)
    check view.inSubtree(root)

suite "ES subtree view — events are held until their lifecycle stream resolves them":
  test "a cross-client view holds a child's event that precedes its FORK":
    # Client B delivers the child's file event before client A (the lifecycle
    # stream this view is built from) delivers the FORK.
    var view = initEsProcessTree(helper, holdUnknown = true)
    discard view.onFork(helper, root)
    let early = openRec(1100, "/src/early.h")
    check view.filterEvent(child, early) == efHold
    check view.heldCount == 1
    let released = view.onFork(root, child)
    check released.len == 1
    check released[0].path == "/src/early.h"
    check view.heldCount == 0

  test "an admission releases only its own token's held events, in arrival order":
    var view = initEsProcessTree(helper, holdUnknown = true)
    discard view.onFork(helper, root)
    let stranger = tok(7777, 1)       # an out-of-tree process on the host
    check view.filterEvent(child, openRec(1100, "/src/a1")) == efHold
    check view.filterEvent(stranger, openRec(7777, "/tmp/other")) == efHold
    check view.filterEvent(child, openRec(1100, "/src/a2")) == efHold
    let released = view.onFork(root, child)
    check released.len == 2
    check released[0].path == "/src/a1"
    check released[1].path == "/src/a2"
    check view.heldCount == 1         # the stranger's event is still held
    check not view.inSubtree(stranger)

  test "an exec on the lifecycle stream releases the target's held event":
    var view = initEsProcessTree(helper, holdUnknown = true)
    discard view.onFork(helper, root)
    let postExec = tok(1000, 8)
    check view.filterEvent(postExec, openRec(1000, "/src/x.c")) == efHold
    let released = view.onExec(root, postExec)
    check released.len == 1 and released[0].path == "/src/x.c"

  test "a same-client view rejects an unknown token (its stream is ordered)":
    var view = initEsProcessTree(helper)
    check view.filterEvent(child, openRec(1100, "/x")) == efReject
    check view.heldCount == 0

  test "the fence discards events still unresolved, and later ones are rejected":
    var view = initEsProcessTree(helper, holdUnknown = true)
    discard view.onFork(helper, root)
    let stranger = tok(7777, 1)
    check view.filterEvent(stranger, openRec(7777, "/tmp/other")) == efHold
    view.onExit(root)
    view.onExit(helper)
    check view.closeAtFence(markerDelivered = true).len == 0
    check view.heldCount == 0
    check view.filterEvent(stranger, openRec(7777, "/tmp/other2")) == efReject

suite "ES subtree view — the end-of-capture fence":
  test "a capture whose members all exited and whose marker arrived is complete":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onFork(root, child)
    view.onExit(child)
    view.onExit(root)
    view.onExit(helper)
    check view.allMembersExited
    check view.closeAtFence(markerDelivered = true).len == 0
    check view.fenced

  test "a fenced view is closed: it admits nothing and rejects every event":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    view.onExit(root)
    view.onExit(helper)
    check view.closeAtFence(markerDelivered = true).len == 0
    discard view.onFork(root, child)
    check not view.inSubtree(child)
    check view.filterEvent(root, openRec(1000, "/late")) == efReject
    check view.closeAtFence(markerDelivered = true).len == 0

  test "a cross-client view with a live member AND unresolved held events is incomplete":
    var view = initEsProcessTree(helper, holdUnknown = true)
    discard view.onFork(helper, root)
    check view.filterEvent(tok(7777, 1), openRec(7777, "/tmp/other")) == efHold
    view.onExit(helper)               # root never exits: still live
    let loss = view.closeAtFence(markerDelivered = true)
    check loss.len == 1
    check loss[0].kind == mrEventLoss
    check "1000/7" in loss[0].detail
    check view.heldCount == 0
    check not view.inSubtree(root)    # closed: no token is a member any more

  test "isLive tracks EXIT; a non-member is not live":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    check view.isLive(root)
    view.onExit(root)
    check not view.isLive(root)
    check view.inSubtree(root)
    check not view.isLive(tok(4242, 1))

  test "a member still live at the fence makes the capture incomplete":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onFork(root, child)  # e.g. a daemonized compiler server
    view.onExit(root)
    view.onExit(helper)
    check not view.allMembersExited
    let loss = view.closeAtFence(markerDelivered = true)
    check loss.len == 1
    check loss[0].kind == mrEventLoss
    check loss[0].observationKind == moEventLoss
    check "1100/3" in loss[0].detail

  test "a marker not delivered within the wait makes the capture incomplete":
    var view = initEsProcessTree(helper)
    view.onExit(helper)
    let loss = view.closeAtFence(markerDelivered = false)
    check loss.len == 1
    check loss[0].kind == mrEventLoss
    check "marker" in loss[0].detail

  test "an EXIT after a chain of execs finishes every token in the chain":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    let second = tok(1000, 8)
    let third = tok(1000, 9)
    discard view.onExec(root, second)
    discard view.onExec(second, third)
    view.onExit(third)
    view.onExit(helper)
    check view.allMembersExited

  test "an EXIT naming a superseded pre-exec token leaves the capture incomplete":
    # ES names the current token on EXIT; if it ever named the old one, the
    # post-exec token stays live and the fence must say so, not pass.
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    discard view.onExec(root, tok(1000, 8))
    view.onExit(root)
    view.onExit(helper)
    check not view.allMembersExited
    check view.closeAtFence(markerDelivered = true).len == 1

  test "an EXIT under the post-exec token also finishes the pre-exec token":
    var view = initEsProcessTree(helper)
    discard view.onFork(helper, root)
    let postExec = tok(1000, 8)
    discard view.onExec(root, postExec)
    view.onExit(postExec)
    view.onExit(helper)
    check view.allMembersExited
    check view.closeAtFence(markerDelivered = true).len == 0
