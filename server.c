#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/net.h>

#include "att.h"
#include "log.h"

#define STR_VALUE(name) #name

#define BUF_SIZE 1024

static mbedtls_net_context _ssock, *ssock = &_ssock;

static int handler(mbedtls_net_context *conn) {
    int ret = -1, nbytes, len;
    uint8_t *recv_payload = NULL, *send_payload = NULL;
    att_ack_t ack = ATT_ACK_OK;
    /* get the header information */
    att_hdr_t _send_hdr = {0}, _recv_hdr = {0}, *send_hdr = &_send_hdr,
              *recv_hdr = &_recv_hdr;

    log_info("Hello client_fd = %d", conn->fd);

repeat:
    /* receive the request */
    ret =
        mbedtls_net_recv(conn, (void *)recv_hdr, (nbytes = sizeof(att_hdr_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    fprintf(stderr, "wow (%d)", (int)(recv_hdr->tlen));

    /* allocate the buffer */
    len = recv_hdr->tlen;
    if (len && ((recv_payload = (char *)calloc(1, len)) == NULL)) {
        log_fatal("allocation error");
        goto out;
    }

    fprintf(stderr, "wow (%d)", (int)(recv_hdr->tlen));
    /* tell him we got it */
    ret = mbedtls_net_send(conn, (uint8_t *)&ack, (nbytes = sizeof(att_ack_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_send() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    /* if we have anything to receive, copy it into the buffer */
    if (len) {
        ret = mbedtls_net_recv(conn, recv_payload, (nbytes = len));
        if (ret != nbytes) {
            log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
            goto out;
        }
    }

    /* process it now */
    ret = process_message(recv_hdr, recv_payload, send_hdr, &send_payload);

    att_type_t tp = send_hdr->type;
    log_debug("responding %s (len=%d)", att_type_2_str(tp), len);
    ret =
        mbedtls_net_send(conn, (void *)send_hdr, (nbytes = sizeof(att_hdr_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_send() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    ack = ATT_ACK_OK;
    ret = mbedtls_net_recv(conn, (uint8_t *)&ack, (nbytes = sizeof(att_ack_t)));
    if (ret != nbytes) {
        log_error("mbedtls_net_recv() tried=%d, actual=%d", nbytes, ret);
        goto out;
    }

    if (ack != ATT_ACK_OK) {
        log_error("att_ack FAIL %#x != OK:%#x", ack, ATT_ACK_OK);
        goto out;
    }

    /* free the payload */
    if (recv_payload) {
        free(recv_payload);
        recv_payload = NULL;
    }

    if (send_payload) {
        free(send_payload);
        send_payload = NULL;
    }

    goto repeat;

    ret = 0;
out:
    if (recv_payload) {
        free(recv_payload);
    }

    if (send_payload) {
        free(send_payload);
    }

    return ret;
}

static int server_init() {
    int ret = -1;

    mbedtls_net_init(ssock);
    ret = mbedtls_net_bind(ssock, SERVER_ADDR, SERVER_PORT,
                           MBEDTLS_NET_PROTO_TCP);
    if (ret) {
        log_error("mbedtls_net_bind() ret=%#x", ret);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static void server_listen() {
    mbedtls_net_context conn, *new_conn;

    log_info("Listening on port=%s", SERVER_PORT);
    do {
        int ret = mbedtls_net_accept(ssock, &conn, NULL, 0, NULL);
        if (ret < 0) {
            log_error("mbedtls_net_accept() ret=%d", ret);
        } else {
            new_conn =
                (mbedtls_net_context *)malloc(sizeof(mbedtls_net_context));
            memcpy(new_conn, &conn, sizeof(mbedtls_net_context));

            if (fork() == 0) {
                handler(new_conn);
                exit(0);
            }
        }
    } while (1);
}

int main() {
    int ret = -1;

    if (server_init()) {
        return -1;
    }

    server_listen();

    ret = 0;
out:
    return ret;
}
