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

void hexdump(uint8_t *data, uint32_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

int init_enclave(sgx_enclave_id_t *p_eid, bool is_client) {
    int launch_token_update = 0, ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    sgx_launch_token_t launch_token = {0};
    secret_t secret;

    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, &launch_token,
                             &launch_token_update, p_eid, NULL);
    if (SGX_SUCCESS != ret) {
        log_error("Error, call sgx_create_enclave fail.");
        return -1;
    }

    /* if it's not the client, skip initialization */
    if (!is_client) {
        return 0;
    }

    ecall_init_enclave(*p_eid, &ret, &secret);
    if (ret) {
        log_error("ecall_init_enclave() FAILED");
        // TODO destroy enclave here
    }

    log_info("enclave_secret (size = %zu bytes):", sizeof(secret_t));
    hexdump((uint8_t *)&secret, sizeof(secret_t));

    return 0;
}

uint8_t pubkey[256];
int pubkey_len = sizeof(pubkey);

int generate_msg1(sgx_enclave_id_t eid, att_msg1_t **pp_msg1, int *tlen) {
    int ret = -1, len;
    uint32_t quote_size;
    uint8_t * pubkey_buf;
    att_msg1_t msg1, *message1;
    sgx_target_info_t qe_info = {0};
    sgx_epid_group_id_t p_gid = {0};
    sgx_report_t report;
    sgx_spid_t spid = {0};
    sgx_status_t status;
    sgx_quote_t *quote;

    /* generate the report of the quoting enclave */
    if ((ret = sgx_init_quote(&qe_info, &p_gid))) {
        log_info("sgx_init_quote() ret=%#x", ret);
        goto out;
    }

    /* use that to create the report */
    ecall_create_report(eid, &ret, &qe_info, &report, &msg1, pubkey,
                        &pubkey_len);
    if (ret) {
        log_error("ecall_create_report() FAILED. ret=%#x", ret);
        goto out;
    }

    sgx_get_quote_size(NULL, &quote_size);

    /* now create the quote and send it over */
    len = sizeof(att_msg1_t) + pubkey_len + quote_size;
    message1 = (att_msg1_t *)calloc(1, len);

    pubkey_buf = (uint8_t *)(((uint8_t *)message1) + sizeof(att_msg1_t));
    quote = (sgx_quote_t *)(pubkey_buf + pubkey_len);

    status = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, NULL, NULL,
                           0, NULL, quote, quote_size);
    if (status != SGX_SUCCESS) {
        log_error("sgx_get_quote() ret = %#x", status);
        goto out;
    }

    /* copy the public key */
    memcpy(pubkey_buf, pubkey, pubkey_len);

    log_info("MSG1: payload(%d bytes) + pubkey(%d bytes) + quote(%d bytes)",
             (int)sizeof(att_msg1_t), pubkey_len, (int)quote_size);

    *pp_msg1 = message1;
    *tlen = len;

    ret = 0;
out:
    return ret;
}

/*** SERVER STUFF *****/
int process_msg1(uint8_t *payload, att_hdr_t *send_hdr, uint8_t **send_ptr) {
    int ret = -1;

    send_hdr->tlen = 0;
    send_hdr->type = ATT_MSG2;
    *send_ptr = NULL;

    ret = 0;
    return ret;
}

int process_message(att_hdr_t *hdr, uint8_t *payload, att_hdr_t *send_hdr,
                    uint8_t **send_ptr) {
    int ret = -1;

    switch (hdr->type) {
        case ATT_MSG1:
            return process_msg1(payload, send_hdr, send_ptr);
    }

    ret = 0;
    return ret;
}
