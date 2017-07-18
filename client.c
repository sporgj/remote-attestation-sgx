#include <stdio.h>
#include <string.h>

#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_urts.h>
#include <sgx_utils.h>

#include <mbedtls/rsa.h>

#include "att.h"
#include "enclave_u.h"
#include "log.h"

#define ENCLAVE_PATH "./enclave/enclave.signed.so"
static sgx_enclave_id_t g_eid = 0;

int main() {
    int ret = -1, tlen;
    att_msg1_t *message1;

    log_debug("Initializing enclave...");
    if (init_enclave(&g_eid, true)) {
        return -1;
    }

    /* connect to the server */
    if (client_init()) {
        goto out;
    }

    log_debug("Generating enclave quote");
    if (generate_msg1(g_eid, &message1, &tlen)) {
        goto out;
    }

    log_debug("Sending msg1 to server...");
    if (client_send_receive(tlen, ATT_MSG1, 0, message1)) {
        goto out;
    }

    log_info("Received MSG2, processing...");

    ret = 0;
out:
    // TODO destroy the enclave
    if (ret && g_eid) {
    }

    return ret;
}
