// Raw Mach RPC client. Runs UNDER io-mon. Looks up the service via the
// bootstrap server (bootstrap_look_up -> mach_msg), sends the marker path, and
// receives the file bytes the server read. NO connect(2), NO socket, NO spawn:
// the only IPC primitives are bootstrap_look_up + mach_msg, none of which the
// io-mon shim hooks. The returned bytes are folded into client output.
#include "mach_msg.h"
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <path> <service>\n", argv[0]); return 2; }

    mach_port_t svc = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, argv[2], &svc);
    if (kr) { fprintf(stderr, "look_up %d\n", kr); return 1; }

    mach_port_t reply = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
    if (kr) { fprintf(stderr, "alloc reply %d\n", kr); return 1; }

    r2_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.path, argv[1], sizeof(req.path) - 1);
    req.hdr.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    req.hdr.msgh_remote_port = svc;     // to the server
    req.hdr.msgh_local_port = reply;    // send-once reply right
    req.hdr.msgh_size = sizeof(req);
    req.hdr.msgh_id = 1;

    // Receive buffer needs room for the kernel-appended trailer.
    union {
        r2_reply_t rep;
        char pad[sizeof(r2_reply_t) + MAX_TRAILER_SIZE];
    } u;
    r2_reply_t *rep = &u.rep;
    memset(&u, 0, sizeof(u));
    // Send request, then receive reply.
    kr = mach_msg(&req.hdr, MACH_SEND_MSG, sizeof(req), 0, MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr) { fprintf(stderr, "send %d\n", kr); return 1; }
    rep->hdr.msgh_local_port = reply;
    rep->hdr.msgh_size = sizeof(u);
    kr = mach_msg(&rep->hdr, MACH_RCV_MSG, 0, sizeof(u), reply,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr) { fprintf(stderr, "recv %d\n", kr); return 1; }

    rep->data[sizeof(rep->data) - 1] = 0;
    printf("client got via Mach IPC: %s", rep->data);  // real data dependency
    return 0;
}
