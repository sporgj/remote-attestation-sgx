#include "sgx_report.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include <string.h>

#include <att.h>

static mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256R1;

/* the secret we will be sending over */
static secret_t g_secret;

/* our public key context */
static mbedtls_pk_context _pk, *g_pk = &_pk;

int sgx_rng(void *d, unsigned char *c, size_t l) {
    sgx_read_rand((uint8_t *)c, l);
    return l;
}

static int generate_public_private_keypair() {
    int ret = -1;

    mbedtls_pk_init(g_pk);
    mbedtls_pk_setup(g_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    /* generate the keypair */
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(_pk), sgx_rng, NULL, 2048, 65537);

    return ret;
}

static uint8_t buf[512];
int ecall_create_report(sgx_target_info_t *qe_info, sgx_report_t *report,
                        att_msg1_t *p_msg1, uint8_t *pubkey, int p_cap) {
    int ret = 0, nc_off = 0, len = 0, l, pk_len;
    sgx_target_info_t _qe = {0};
    sgx_report_t _report;
    sgx_report_data_t data = {0};
    ekey_t _e, *ekey = &_e;
    nonce_t _i, nonce, *iv = &_i;
    uint8_t *dest = (uint8_t *)&data;
    mbedtls_aes_context aes_ctx;
    att_msg1_t msg1 = {0};

    /* write the public key */
    pk_len = mbedtls_pk_write_pubkey_der(g_pk, buf, sizeof(buf));
    if (pk_len < 0) {
        return -2;
    }

    /* check if there's enough buffer to copy the public key */
    if (p_cap < pk_len) {
        return -4;
    }

    /* lets start setting user-defined data */
    msg1.pk_len = pk_len;

    /* generate random key and nonce */
    sgx_read_rand((uint8_t *)ekey, sizeof(ekey_t));
    sgx_read_rand((uint8_t *)iv, sizeof(nonce_t));

    memcpy(&nonce, iv, sizeof(nonce_t));

    /* h = enc[nonce](key, secret) | nonce | pubkey */
    l = sizeof(secret_t);
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, (uint8_t *)ekey, 128);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, l, (uint8_t *)iv,
                          (uint8_t *)&g_secret,
                          (uint8_t *)&msg1.wrapped_secret);
    mbedtls_aes_free(&aes_ctx);

    /* copy the remaining data */
    memcpy(&msg1.nonce, &nonce, sizeof(nonce_t));

    /* insert the msg1 into the report data */
    memcpy(dest, &msg1, sizeof(att_msg1_t));
    dest += sizeof(att_msg1_t);

    /* write the hash of the public key to the buffer */
    uint8_t *c = buf + sizeof(buf) - pk_len - 1;
    mbedtls_sha256(c, pk_len, dest, 0);

    /* copy in the quoting enclave target info and generate the report */
    memcpy(&_qe, qe_info, sizeof(sgx_target_info_t));
    ret = sgx_create_report(&_qe, &data, &_report);
    if (ret) {
        return -8;
    }

    /* copy the pubkey and set the length */
    memcpy(pubkey, c, l);

    /* copy out the report & msg1 */
    memcpy(report, &_report, sizeof(sgx_report_t));
    memcpy(p_msg1, &msg1, sizeof(att_msg1_t));
    return 0;
}

int ecall_generate_m2(uint8_t *pubkey, size_t pubkey_len, att_msg2_t *p_msg2) {
    int ret = -1;
    size_t olen;
    ekey_t ekey;
    att_msg2_t msg2 = {0};
    mbedtls_pk_context _k, *pk = &_k;
    mbedtls_pk_init(pk);

    /* parse the public key */
    ret = mbedtls_pk_parse_public_key(pk, pubkey, pubkey_len);
    if (ret) {
        return -1;
    }

    /* generate a random encryption key */
    sgx_read_rand((void *)&ekey, sizeof(ekey_t));

    /* encrypt into the buffer */
    ret = mbedtls_pk_encrypt(pk, (uint8_t *)&ekey, sizeof(ekey_t),
                             (uint8_t *)&msg2.pl_ciphertext, &olen,
                             sizeof(msg2.pl_ciphertext), NULL, NULL);
    if (ret) {
        return -2;
    }

    /* copy the buffer out */
    memcpy(p_msg2, &msg2, olen);

    ret = 0;
out:
    mbedtls_pk_free(pk);
    mbedtls_pk_free(pk);
    return ret;
}

int ecall_init_enclave(secret_t *ptr) {
    int ret = -1;

    sgx_read_rand((uint8_t *)&g_secret, sizeof(secret_t));
    memcpy(ptr, &g_secret, sizeof(secret_t));

    if (generate_public_private_keypair()) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}
