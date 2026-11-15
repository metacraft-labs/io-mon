## Which failures of a POSIX `connect(2)` prove that the kernel read the
## caller's address.
##
## The Linux and macOS shims record a failed AF_INET/AF_INET6 connect as an
## `mrConnectAttempt` naming its destination, so they read the caller's
## `sockaddr` after the call returned. That read is safe only when the kernel
## has already copied the address: then the pointer and `addrlen` bytes behind
## it were readable when the call ran. Both kernels look up the descriptor and
## copy the address in before the protocol sees the call (Linux
## `__sys_connect_file` after `move_addr_to_kernel`,
## https://github.com/torvalds/linux/blob/master/net/socket.c; XNU `connect_nocancel`
## after `getsockaddr`,
## https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_syscalls.c),
## so an error the PROTOCOL returns implies the copy succeeded.
##
## The errors that can come from the steps before it are left out on purpose:
## EFAULT (the address is unreadable), EINVAL (a bad `addrlen`, rejected
## before the copy), EBADF and ENOTSOCK (the descriptor is looked up first, so
## nothing about the address was checked). Reading the address after any of
## those would turn a defined error return into a crash in the monitored
## program, for example `connect(fd, (struct sockaddr *)8, 16)`. Unlisted
## errors are not recorded either: a missed attempt costs one piece of
## evidence, a wrong read costs the program.
##
## EISCONN is left out for another reason: it says the socket IS connected.
## The non-blocking idiom (connect, poll for writability, connect again)
## gets it on the second call after the connection was made, and the first
## call was already recorded as a connection (EINPROGRESS is in flight). An
## attempt record for it would claim that a connection which was made
## reached nobody.

when defined(posix):
  var
    ECONNREFUSED_C {.importc: "ECONNREFUSED", header: "<errno.h>".}: cint
    ENETUNREACH_C {.importc: "ENETUNREACH", header: "<errno.h>".}: cint
    EHOSTUNREACH_C {.importc: "EHOSTUNREACH", header: "<errno.h>".}: cint
    ETIMEDOUT_C {.importc: "ETIMEDOUT", header: "<errno.h>".}: cint
    EACCES_C {.importc: "EACCES", header: "<errno.h>".}: cint
    EPERM_C {.importc: "EPERM", header: "<errno.h>".}: cint
    EADDRNOTAVAIL_C {.importc: "EADDRNOTAVAIL", header: "<errno.h>".}: cint
    EADDRINUSE_C {.importc: "EADDRINUSE", header: "<errno.h>".}: cint
    EAFNOSUPPORT_C {.importc: "EAFNOSUPPORT", header: "<errno.h>".}: cint
    ECONNRESET_C {.importc: "ECONNRESET", header: "<errno.h>".}: cint
    ECONNABORTED_C {.importc: "ECONNABORTED", header: "<errno.h>".}: cint
    ENETDOWN_C {.importc: "ENETDOWN", header: "<errno.h>".}: cint
    EHOSTDOWN_C {.importc: "EHOSTDOWN", header: "<errno.h>".}: cint

  proc connectFailureReadAddress*(err: cint): bool {.raises: [].} =
    ## Whether a `connect(2)` that failed with `err` had its address copied in
    ## by the kernel (see the module comment). Covers a refused or unreachable
    ## destination, a timeout, a sandbox or firewall denial (EACCES, EPERM),
    ## an address the host cannot use, and a reset or aborted handshake.
    err == ECONNREFUSED_C or err == ENETUNREACH_C or err == EHOSTUNREACH_C or
      err == ETIMEDOUT_C or err == EACCES_C or err == EPERM_C or
      err == EADDRNOTAVAIL_C or err == EADDRINUSE_C or
      err == EAFNOSUPPORT_C or err == ECONNRESET_C or
      err == ECONNABORTED_C or err == ENETDOWN_C or err == EHOSTDOWN_C
