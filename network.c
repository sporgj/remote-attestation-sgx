#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/net.h>

#include "att.h"
#include "log.h"

// TODO fix string
static const char *addr = SERVER_ADDR, *port = SERVER_PORT;
static mbedtls_net_context _conn, *conn = &_conn;

int client_init() {
    int ret = -1;
    mbedtls_net_init(conn);

    log_debug("Connecting to %s:%s", addr, port);

    ret = mbedtls_net_connect(conn, addr, port, MBEDTLS_NET_PROTO_TCP);
    if (ret) {
        log_error("mbedtls_net_connect() ret=%d", ret);
    }

    return ret;
}

int client_stop() {
    mbedtls_net_free(conn);
    return 0;
}

int client_send_receive(int len, att_type_t tp, att_code_t status, void *ptr) {
    int ret = -1, nbytes;
    att_ack_t ack;
    /* get the header information */
    att_hdr_t _send_hdr = {0}, _recv_hdr = {0}, *send_hdr = &_send_hdr,
              *recv_hdr = &_recv_hdr;
    void *payload = ptr;
    char *recv_payload = NULL;

    send_hdr->tlen = len;
    send_hdr->type = tp;
    send_hdr->status = status;

    /* start sending the data */
    log_debug("sending %s (len=%d)", att_type_2_str(tp), len);
    ret =
        mbedtls_net_send(conn, (void *)send_hdr, (nbytes = sizeof(att_hdr_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_send() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    /* get the status of the message */
    ret = mbedtls_net_recv(conn, (uint8_t *)&ack, (nbytes = sizeof(att_ack_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    log_debug("ACK_OK");

    if (ack != ATT_ACK_OK) {
        log_error("att_ack FAIL %#x != OK:%#x", ack, ATT_ACK_OK);
        goto out;
    }

    /* now send the actual payload */
    if (len) {
        ret = mbedtls_net_send(conn, payload, (nbytes = len));
        if (ret != nbytes) {
            log_error("mbedtls_net_send() tried=%d, actual=%d", nbytes, ret);
            goto out;
        }

        log_debug("payload1");
    }

    /* wait for the response */
    ret =
        mbedtls_net_recv(conn, (char *)recv_hdr, (nbytes = sizeof(att_hdr_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    log_debug("recv_hdr (%d)", recv_hdr->tlen);

    /* allocate the buffer */
    len = recv_hdr->tlen;
    if (len && ((recv_payload = (char *)calloc(1, len)) == NULL)) {
        log_fatal("allocation error");
        goto out;
    }

    /* tell him we got it ok */
    ack = ATT_ACK_OK;
    ret = mbedtls_net_send(conn, (uint8_t *)&ack, (nbytes = sizeof(att_ack_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_send() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    log_debug("ACK_OK");

    /* if we have anything to receive, copy it into the buffer */
    if (len) {
        ret = mbedtls_net_recv(conn, recv_payload, (nbytes = len));
        if (ret != nbytes) {
            log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
            goto out;
        }

        log_debug("recv_hdr");
    }

    ret = 0;
out:
    if (recv_payload) {
        free(recv_payload);
    }

    return ret;
}
