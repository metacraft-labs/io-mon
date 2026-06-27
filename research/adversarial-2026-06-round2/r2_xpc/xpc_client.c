// XPC client: runs UNDER io-mon. Sends a marker path to the launchd-registered
// service over a Mach service connection (NO connect(2), NO socket). Receives
// the file bytes the service read and folds them into its own output -- a real
// data dependency on the marker file that io-mon never sees.
#include <xpc/xpc.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

static const char *SERVICE = "com.example.r2xpc.reader";

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
    xpc_connection_t conn = xpc_connection_create_mach_service(SERVICE, NULL, 0);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t e){ (void)e; });
    xpc_connection_resume(conn);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "path", argv[1]);
    xpc_object_t reply =
        xpc_connection_send_message_with_reply_sync(conn, msg);

    int rc = 1;
    if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
        const char *data = xpc_dictionary_get_string(reply, "data");
        // Fold the bytes into client output: a genuine dependency on the marker.
        printf("client got via XPC: %s", data ? data : "(null)");
        rc = 0;
    } else {
        char *d = xpc_copy_description(reply);
        fprintf(stderr, "xpc error: %s\n", d ? d : "?");
        rc = 1;
    }
    return rc;
}
