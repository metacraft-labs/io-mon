// XPC service: a launchd-registered MachService that reads a file on behalf of
// a client and returns its bytes. Started BY LAUNCHD (xpcproxy), entirely
// OUTSIDE any io-mon-monitored process tree. The file read happens here.
#include <xpc/xpc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *SERVICE = "com.example.r2xpc.reader";

static void handle_message(xpc_connection_t peer, xpc_object_t msg) {
    if (xpc_get_type(msg) != XPC_TYPE_DICTIONARY) return;
    const char *path = xpc_dictionary_get_string(msg, "path");
    char buf[4096];
    size_t n = 0;
    if (path) {
        FILE *f = fopen(path, "r");           // <-- the breakaway file read
        if (f) { n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f); }
    }
    buf[n] = 0;
    xpc_object_t reply = xpc_dictionary_create_reply(msg);
    if (reply) {
        xpc_dictionary_set_string(reply, "data", buf);
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);
    }
}

int main(void) {
    xpc_connection_t listener = xpc_connection_create_mach_service(
        SERVICE, NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t conn = (xpc_connection_t)peer;
        xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            if (xpc_get_type(event) == XPC_TYPE_DICTIONARY)
                handle_message(conn, event);
        });
        xpc_connection_resume(conn);
    });
    xpc_connection_resume(listener);
    dispatch_main();
    return 0;
}
