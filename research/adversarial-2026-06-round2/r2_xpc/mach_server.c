// Raw Mach RPC server. Registers a bootstrap service name, then loops receiving
// requests over mach_msg. Each request carries a marker path; the server opens
// and reads the file (the breakaway file read) and returns the bytes to the
// client's send-once reply port. Started OUTSIDE any io-mon-monitored tree.
#include "mach_msg.h"
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <service>\n", argv[0]); return 2; }
    mach_port_t svc = MACH_PORT_NULL;
    kern_return_t kr =
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &svc);
    if (kr) { fprintf(stderr, "allocate %d\n", kr); return 1; }
    kr = mach_port_insert_right(mach_task_self(), svc, svc,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr) { fprintf(stderr, "insert %d\n", kr); return 1; }
    kr = bootstrap_register(bootstrap_port, argv[1], svc);
    if (kr) { fprintf(stderr, "register %d\n", kr); return 1; }
    fprintf(stderr, "mach_server ready: %s\n", argv[1]);
    fflush(stderr);

    for (;;) {
        // Receive buffer must include room for the kernel-appended trailer,
        // otherwise mach_msg returns MACH_RCV_TOO_LARGE (0x10004004).
        union {
            r2_request_t req;
            char pad[sizeof(r2_request_t) + MAX_TRAILER_SIZE];
        } u;
        r2_request_t *rp = &u.req;
        memset(&u, 0, sizeof(u));
        rp->hdr.msgh_local_port = svc;
        rp->hdr.msgh_size = sizeof(u);
        kr = mach_msg(&rp->hdr, MACH_RCV_MSG, 0, sizeof(u), svc,
                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr) { fprintf(stderr, "rcv %d\n", kr); continue; }
        r2_request_t req = *rp;

        req.path[sizeof(req.path) - 1] = 0;
        r2_reply_t rep;
        memset(&rep, 0, sizeof(rep));
        size_t n = 0;
        FILE *f = fopen(req.path, "r");          // <-- breakaway file read
        fprintf(stderr, "server: path='%s' fopen=%p\n", req.path, (void*)f);
        fflush(stderr);
        if (f) { n = fread(rep.data, 1, sizeof(rep.data) - 1, f); fclose(f); }
        rep.data[n] = 0;
        rep.len = (mach_msg_size_t)n;

        rep.hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        rep.hdr.msgh_remote_port = req.hdr.msgh_remote_port; // reply port
        rep.hdr.msgh_local_port = MACH_PORT_NULL;
        rep.hdr.msgh_size = sizeof(rep);
        rep.hdr.msgh_id = req.hdr.msgh_id + 100;
        kr = mach_msg(&rep.hdr, MACH_SEND_MSG, sizeof(rep), 0,
                      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr) fprintf(stderr, "snd %d\n", kr);
    }
    return 0;
}
