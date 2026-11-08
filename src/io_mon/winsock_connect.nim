## Which outcomes of a Winsock `connect` / `WSAConnect` may reach a peer.
##
## Used by the Windows shim's connect snoops (`shim/windows_interpose.nim`) to
## choose between an `mrIpcConnect` (a peer may have been reached) and an
## `mrConnectAttempt` (nobody was). Kept in its own pure module, with no
## Windows import, so the rule is unit-tested on every OS
## (`tests/portable/test_io_mon_winsock_connect_outcome.nim`): one of its
## outcomes, WSAEINTR, could not be provoked from a live Winsock 2 program, so no
## end-to-end test pins it. Measured on Windows 11 (2026-11-08) against a
## blocking connect to a closed loopback port: `closesocket` from another thread
## ends it with WSAENOTSOCK, and `QueueUserAPC` or `CancelSynchronousIo` on the
## blocked thread do not interrupt it (it ends with WSAECONNREFUSED after ~2 s).

const
  WSAEINTR* = 10004'u32
  WSAEWOULDBLOCK* = 10035'u32
  WSAEINPROGRESS* = 10036'u32
    ## Winsock error codes:
    ## https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2

func socketConnectReachedPeer*(rc: int32; wsaError: uint32): bool
    {.inline, raises: [].} =
  ## Did this `connect`/`WSAConnect` call actually reach a peer?
  ##
  ## THE SAME RULE `classifyOpenedPath` STATES FOR PIPES, applied to the socket
  ## arm: only a connect that reached somebody is recorded. An `mrIpcConnect`
  ## naming an UNKNOWN peer is a downgrade signal -- the merge cannot prove the
  ## peer was in-tree, so the whole capture grades `mcIncomplete` and the action
  ## loses its cache publication. Emitting one for a connect that was REFUSED
  ## means a connection that never happened costs a build its cache hit: a
  ## false re-run, which is the failure direction this machinery exists to
  ## avoid. Windows programs probe localhost constantly (daemon discovery,
  ## sccache and language-server probes, "is the server already up?" checks),
  ## and every one of those probes ends in WSAECONNREFUSED by design. (A
  ## refused AF_INET/AF_INET6 connect IS recorded, as an `mrConnectAttempt` —
  ## a kind the merge never derives a loss from; see `emitConnectAttempt`.)
  ##
  ## IN-FLIGHT CONNECTS ARE RECORDED, deliberately, matching the macOS arm's
  ## `EInProgress` case. A non-blocking `connect` returns SOCKET_ERROR with
  ## WSAEWOULDBLOCK (the Winsock spelling of EINPROGRESS; WSAEINPROGRESS is the
  ## WinSock 1.1 blocking-call form and is accepted for completeness) and then
  ## COMPLETES asynchronously -- that is the ordinary shape of an async client
  ## talking to a daemon, so treating it as "reached nobody" would be a silent
  ## false skip over a real peer. The two errors are not symmetric in cost: an
  ## in-flight connect that later fails costs a conservative re-run, while a
  ## refused connect recorded as a peer costs one too, and an in-flight connect
  ## NOT recorded costs a false `mcComplete` over content that arrived from an
  ## out-of-tree daemon. Only the last of those is unrecoverable, so the guard
  ## is drawn to include exactly the states in which a peer may yet be reached.
  ##
  ## AN INTERRUPTED CONNECT IS RECORDED TOO. WSAEINTR ("a blocking operation
  ## was interrupted",
  ## https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)
  ## says only that the CALL returned early, not that the connection request
  ## was withdrawn: on POSIX the same interruption is defined to leave the
  ## connection to be "established asynchronously"
  ## (https://pubs.opengroup.org/onlinepubs/9799919799/functions/connect.html),
  ## and nothing in the Winsock contract promises the opposite. By the
  ## asymmetry above it is therefore in flight. Before, it was neither a peer
  ## nor an attempt, so it left no record at all: a connection a program made
  ## on a host whose network nothing else confines could go unseen.
  ##
  ## `GetLastError` is the source of `wsaError`: `WSAGetLastError` is documented
  ## as returning the same thread-local value, and the snoops already capture it
  ## immediately after `callNext` before anything can clobber it.
  if rc == 0:
    return true
  wsaError == WSAEWOULDBLOCK or wsaError == WSAEINPROGRESS or
    wsaError == WSAEINTR

const
  WSAEACCES* = 10013'u32
  WSAEAFNOSUPPORT* = 10047'u32
  WSAEADDRINUSE* = 10048'u32
  WSAEADDRNOTAVAIL* = 10049'u32
  WSAENETUNREACH* = 10051'u32
  WSAECONNABORTED* = 10053'u32
  WSAECONNRESET* = 10054'u32
  WSAEISCONN* = 10056'u32
  WSAETIMEDOUT* = 10060'u32
  WSAECONNREFUSED* = 10061'u32
  WSAEHOSTDOWN* = 10064'u32
  WSAEHOSTUNREACH* = 10065'u32
  WSAEFAULT* = 10014'u32
  WSAEINVAL* = 10022'u32

func winsockConnectFailureReadAddress*(wsaError: uint32): bool
    {.inline, raises: [].} =
  ## Whether a `connect`/`WSAConnect` that failed with `wsaError` must have
  ## read the caller's address, so that the snoop may read it too to name
  ## the destination of an `mrConnectAttempt`.
  ##
  ## Only errors the transport returns about the destination qualify: a
  ## refused, unreachable, timed-out, reset or aborted connection, an address
  ## the host cannot use, and an access denial. WSAEFAULT (the address or
  ## its length is not readable) and WSAEINVAL (a bad length or socket
  ## state) are excluded because reading the address after them would turn
  ## an error return into an access violation in the monitored program, which
  ## no `except` catches. WSAENETDOWN is excluded too: it reports the network
  ## subsystem, and Winsock may return it before looking at the address.
  ## WSAEISCONN is excluded because it says the socket IS connected: the
  ## non-blocking idiom (connect, wait, connect again) gets it once the
  ## connection was made, and the first call was already recorded as a
  ## connection (WSAEWOULDBLOCK is in flight), so an attempt record would
  ## claim that a connection which was made reached nobody.
  ## Unlisted errors are not recorded: a missed attempt costs one piece of
  ## evidence, a wrong read costs the program.
  wsaError in [WSAECONNREFUSED, WSAENETUNREACH, WSAEHOSTUNREACH,
    WSAETIMEDOUT, WSAEACCES, WSAEADDRNOTAVAIL, WSAEADDRINUSE,
    WSAEAFNOSUPPORT, WSAECONNRESET, WSAECONNABORTED, WSAEHOSTDOWN]
