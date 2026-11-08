## test_io_mon_winsock_connect_outcome — which Winsock `connect` outcomes the
## Windows shim records as a connection (`mrIpcConnect`) rather than as an
## attempt that reached nobody (`mrConnectAttempt`).
##
## WHY A UNIT TEST. The live arm is `tests/windows/test_io_mon_windows_ipc_connect.nim`
## (made, in-flight and refused connects through the real injected shim). One
## outcome cannot be driven there: WSAEINTR, a blocking call that returned
## early. It could not be provoked from a live Winsock 2 program (see the
## header of `src/io_mon/winsock_connect.nim` for what was tried), so the rule
## the snoops call is pinned here, on every OS, with no mock: it is the
## production function itself.
##
## THE PROPERTY: an interrupted connect is in flight, exactly
## like WSAEWOULDBLOCK. Before, it was neither a peer nor an attempt and left
## no record at all, so a connection a signal-like interruption cut short was
## invisible to the capture.

import std/unittest

import io_mon/winsock_connect

suite "Winsock connect outcome":
  test "a made connect reached a peer":
    check socketConnectReachedPeer(0, 0'u32)

  test "an in-flight non-blocking connect may reach a peer":
    check socketConnectReachedPeer(-1, WSAEWOULDBLOCK)
    check socketConnectReachedPeer(-1, WSAEINPROGRESS)

  test "an interrupted connect (WSAEINTR) may reach a peer":
    check socketConnectReachedPeer(-1, WSAEINTR)

  test "a refused or unreachable connect reached nobody":
    check not socketConnectReachedPeer(-1, 10061'u32)   # WSAECONNREFUSED
    check not socketConnectReachedPeer(-1, 10051'u32)   # WSAENETUNREACH
    check not socketConnectReachedPeer(-1, 10060'u32)   # WSAETIMEDOUT

  test "an attempt is named only after an error that implies the address was read":
    for err in [WSAECONNREFUSED, WSAENETUNREACH, WSAEHOSTUNREACH,
                WSAETIMEDOUT, WSAEACCES, WSAEADDRNOTAVAIL]:
      check winsockConnectFailureReadAddress(err)
    # The address may be unreadable after these, and reading it would crash
    # the monitored program.
    check not winsockConnectFailureReadAddress(WSAEFAULT)
    check not winsockConnectFailureReadAddress(WSAEINVAL)
    check not winsockConnectFailureReadAddress(10050'u32)   # WSAENETDOWN
    check not winsockConnectFailureReadAddress(10038'u32)   # WSAENOTSOCK
