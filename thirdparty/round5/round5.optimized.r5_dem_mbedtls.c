/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the DEM functions used by the Round5 CCA KEM-based encrypt algorithm.
 */

#include "r5_dem.h"
#include "r5_parameter_sets.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/cipher.h>

#include "r5_hash.h"
#include "rng.h"
#include "misc.h"
#include "r5_memory.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int round5_dem(unsigned char *c2, unsigned long long *c2_len, const unsigned char *key, const unsigned char *m, const unsigned long long m_len) {

    int result = 1;
    size_t c2length;
    const mbedtls_cipher_info_t *ctx_info = NULL;
    unsigned char final_key_iv[32 + 12];
    unsigned char tag[16];
    const unsigned char * const iv = final_key_iv + PARAMS_KAPPA_BYTES;

    /* Hash key to obtain final key and IV */
    assert(PARAMS_KAPPA_BYTES == 32 || PARAMS_KAPPA_BYTES == 24 || PARAMS_KAPPA_BYTES == 16);
    HashR5DEM(final_key_iv, (size_t) (PARAMS_KAPPA_BYTES + 12), key, PARAMS_KAPPA_BYTES);

    /* Initialise AES GCM */
    switch (PARAMS_KAPPA_BYTES) {
        case 16:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            break;
        case 24:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM);
            break;
        case 32:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
            break;
    }

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    int res = mbedtls_cipher_setup(&ctx, ctx_info);
    if (res) {
        DEBUG_ERROR("Failed to initialise encryption engine\n");
        goto done_dem;
    }

    res = mbedtls_cipher_setkey(&ctx, final_key_iv, 8 * PARAMS_KAPPA_BYTES, MBEDTLS_ENCRYPT);
    if (res) {
        DEBUG_ERROR("Failed to initialise encryption engine\n");
        goto done_dem;
    }

    /* Encrypt message into c2 */
    res = mbedtls_cipher_auth_encrypt(&ctx, iv, 12, NULL, 0, m, (size_t)m_len, c2, &c2length, tag, 16);
    if (res) {
        DEBUG_ERROR("Failed to encrypt\n");
        goto done_dem;
    }

    /* Append tag and IV */
    memcpy(c2 + c2length, tag, 16);
    c2length += 16;

    /* Set total length */
    *c2_len = (unsigned long long) c2length;

    /* All OK */
    result = 0;

done_dem:
    mbedtls_cipher_free(&ctx);

    return result;
}

int round5_dem_inverse(unsigned char *m, unsigned long long *m_len, const unsigned char *key, const unsigned char *c2, const unsigned long long c2_len) {
    int result = 1;
    size_t m_len_tmp = 0;
    const mbedtls_cipher_info_t *ctx_info = NULL;
    unsigned char final_key_iv[32 + 12];
    unsigned char tag[16];
    const unsigned long long c2_len_no_tag = c2_len - 16U;
    const unsigned char * const iv = final_key_iv + PARAMS_KAPPA_BYTES;

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    /* Check length, must at least be as long as the tag (16 bytes).
     * Note that this is should already have been checked when calling this
     * function, so this is just an additional sanity check. */
    if (c2_len < 16) {
        DEBUG_ERROR("Invalid DEM message length: %llu < 16\n", c2_len);
        *m_len = 0;
        goto done_dem_inverse;
    }

    /* Hash key to obtain final key and IV */
    assert(PARAMS_KAPPA_BYTES == 32 || PARAMS_KAPPA_BYTES == 24 || PARAMS_KAPPA_BYTES == 16);
    HashR5DEM(final_key_iv, (size_t) (PARAMS_KAPPA_BYTES + 12), key, PARAMS_KAPPA_BYTES);

    /* Get tag */
    memcpy(tag, c2 + c2_len_no_tag, 16);

    /* Initialise AES GCM */
    switch (PARAMS_KAPPA_BYTES) {
        case 16:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            break;
        case 24:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM);
            break;
        case 32:
            ctx_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
            break;
    }

    int res = mbedtls_cipher_setup(&ctx, ctx_info);
    if (res) {
        DEBUG_ERROR("Failed to initialise encryption engine\n");
        goto done_dem_inverse;
    }

    res = mbedtls_cipher_setkey(&ctx, final_key_iv, 8 * PARAMS_KAPPA_BYTES, MBEDTLS_DECRYPT);
    if (res) {
        DEBUG_ERROR("Failed to initialise encryption engine\n");
        goto done_dem_inverse;
    }

    /* Decrypt */
    res = mbedtls_cipher_auth_decrypt(&ctx, iv, 12, NULL, 0, c2, (size_t)c2_len_no_tag, m, &m_len_tmp, tag, 16);
    if (res) {
        DEBUG_ERROR("Failed to decrypt\n");
        goto done_dem_inverse;
    }

    /* OK */
    result = 0;
    *m_len = (unsigned long long)m_len_tmp;

done_dem_inverse:
    mbedtls_cipher_free(&ctx);

    return result;
}
