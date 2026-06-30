// Shared Mach RPC message layout for the breakaway repro.
#ifndef R2_MACH_MSG_H
#define R2_MACH_MSG_H
#include <mach/mach.h>

#define R2_SERVICE_NAME "com.example.r2xpc.machreader"

typedef struct {
    mach_msg_header_t hdr;
    char path[1024];
} r2_request_t;

typedef struct {
    mach_msg_header_t hdr;
    mach_msg_size_t len;
    char data[4096];
} r2_reply_t;

#endif
