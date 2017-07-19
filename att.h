#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <sgx_urts.h>

#define DEFAULT_BACKLOG 10
#define SERVER_PORT "42329"
#define SERVER_ADDR "0.0.0.0"

typedef struct _ekey_t { uint8_t bytes[16]; } ekey_t;

typedef struct _nonce_t { uint8_t bytes[16]; } nonce_t;

typedef struct _secret_t { uint8_t bytes[16]; } secret_t;

int client_init();
int client_stop();

typedef enum _att_type {
    ATT_MSG1 = 0x01,
    ATT_MSG2 = 0x02,
    ATT_ERR = 0x10
} att_type_t;

#define ATT_ACK_OK 0x2048

#define RSA_PUBKEY_BITS 2048
#define RSA_PUBKEY_BYTES (RSA_PUBKEY_BITS >> 3)

typedef int16_t att_ack_t;
typedef int32_t att_code_t;

typedef struct _att_hdr {
    uint16_t tlen;
    att_code_t status;
    att_type_t type;
} __attribute__((packed)) att_hdr_t;

typedef struct _att_msg1 {
    uint16_t pk_len;
    nonce_t nonce;
    secret_t wrapped_secret;
    uint8_t pubkey[0];
} __attribute__((packed)) att_msg1_t;

typedef struct _att_msg2 {
    uint8_t pl_ciphertext[RSA_PUBKEY_BYTES];
    uint8_t quote[0];
} __attribute__((packed)) att_msg2_t;

static const char * att_type_2_str(att_type_t tp)
{
    switch(tp) {
        case ATT_MSG1: return "ATT_MSG1";
        case ATT_MSG2: return "ATT_MSG2";
        case ATT_ERR: return "ATT_ERR";
    }

    return "ATT_UNK";
}

int init_enclave(sgx_enclave_id_t * eid, bool is_client);
int att_process_msg1(att_hdr_t * recv_hdr, uint8_t * recv_payload);
int generate_msg1(sgx_enclave_id_t eid, att_msg1_t ** pp_msg1, int * tlen);

int process_message(sgx_enclave_id_t eid, att_hdr_t *hdr, uint8_t *payload, att_hdr_t *send_hdr,
                    uint8_t **send_ptr);

int client_send_receive(int len, att_type_t tp, att_code_t status, void *ptr);
