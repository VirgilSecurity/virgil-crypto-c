/**
 * Copyright (C) 2015-2018 Virgil Security Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCP_PYTHIA
#if TEST_DEPENDENCIES_AVAILABLE

#include "pythia.h"
#include "vscp_pythia.h"

// clang-format off
static const uint8_t deblinded_bin[384] = {
    0x17, 0xD6, 0x40, 0x4D, 0xB8, 0x6F, 0xB1, 0x84, 0xB3, 0xD6, 0x53, 0xD6, 0xBF, 0xA1, 0xA7, 0xB2,
    0xFE, 0x7C, 0xDB, 0x49, 0x52, 0x34, 0x28, 0x46, 0x0B, 0x9C, 0x1B, 0xB0, 0x42, 0x8D, 0x3F, 0x21,
    0x61, 0xDB, 0xA0, 0xE0, 0xF0, 0x31, 0x4D, 0xCB, 0xFD, 0xC7, 0x6A, 0xAE, 0xD5, 0xAC, 0xC2, 0x5D,
    0x13, 0xC4, 0x34, 0xF9, 0xF3, 0x87, 0xF2, 0x49, 0x92, 0xCF, 0x0C, 0xF2, 0xB2, 0xFA, 0x3E, 0x0D,
    0x14, 0x47, 0xAA, 0xFC, 0xFA, 0x37, 0xC8, 0x8B, 0x3B, 0xAC, 0xD2, 0xA1, 0x5F, 0xAB, 0x24, 0x46,
    0x03, 0x22, 0xEE, 0xE1, 0x52, 0xF5, 0x62, 0x44, 0xEF, 0xA6, 0x29, 0xC5, 0xE7, 0xB3, 0x4C, 0x76,
    0x07, 0x52, 0xBD, 0x23, 0x81, 0x13, 0xAC, 0xF0, 0xDE, 0xE7, 0xE8, 0x99, 0xD3, 0xA8, 0xFF, 0x76,
    0x8C, 0x76, 0x00, 0xD4, 0x50, 0x62, 0x25, 0x68, 0x71, 0x47, 0x08, 0x27, 0x3C, 0xF1, 0x28, 0x63,
    0xB0, 0x7C, 0x53, 0x6F, 0x64, 0x6A, 0xF0, 0x82, 0x2A, 0x3A, 0x41, 0xCD, 0x37, 0x4A, 0xC6, 0x87,
    0x04, 0xF7, 0xDE, 0xDE, 0x5E, 0xF6, 0x44, 0x4F, 0xA8, 0x6B, 0xAE, 0xF0, 0x25, 0x38, 0xB9, 0xEA,
    0x20, 0xDC, 0x6E, 0xC8, 0x2C, 0x37, 0x3B, 0x27, 0x06, 0x99, 0x81, 0xA1, 0x4C, 0x59, 0xCC, 0xD2,
    0x6F, 0xE9, 0x65, 0xDD, 0x70, 0xF5, 0xC6, 0xFB, 0xA1, 0xFD, 0xE6, 0xC8, 0xD4, 0xF6, 0x30, 0x21,
    0x09, 0x08, 0x4F, 0x77, 0xFF, 0x90, 0xB5, 0xB1, 0xB2, 0x49, 0x09, 0x02, 0x21, 0x90, 0xDF, 0xDC,
    0xE2, 0x42, 0x08, 0xF4, 0x6F, 0xF1, 0x6A, 0xB0, 0xD7, 0x2F, 0xAF, 0x3B, 0x0C, 0xBE, 0xEC, 0xFB,
    0x36, 0xB3, 0x76, 0xAD, 0x0F, 0x91, 0x09, 0x64, 0x22, 0x5B, 0x2A, 0x17, 0xE2, 0x4D, 0x87, 0x17,
    0x03, 0x50, 0x7B, 0x39, 0xB6, 0x49, 0x39, 0x94, 0x52, 0xDD, 0xDC, 0xBC, 0x43, 0x77, 0x15, 0xEC,
    0x15, 0xC5, 0xED, 0x5F, 0x8D, 0xB0, 0x6B, 0x29, 0x77, 0x97, 0x9D, 0x53, 0x65, 0xE2, 0x54, 0x51,
    0x10, 0x16, 0xE8, 0x99, 0x29, 0xF8, 0x8E, 0x65, 0x91, 0xD9, 0xCC, 0x88, 0x74, 0x45, 0x7C, 0x60,
    0x15, 0x9F, 0x6E, 0x78, 0x14, 0xAD, 0x4D, 0x01, 0x84, 0xFA, 0x77, 0x33, 0x36, 0x36, 0x6D, 0x59,
    0x44, 0xE2, 0x9E, 0xDB, 0x8A, 0xC2, 0xF7, 0x3F, 0x26, 0x7B, 0x3F, 0xA2, 0xBE, 0xEA, 0x6F, 0xFB,
    0x9E, 0xA2, 0xF0, 0xB7, 0x67, 0x45, 0x2D, 0x65, 0xF4, 0xE6, 0x15, 0x42, 0x7D, 0xA2, 0x07, 0xB7,
    0x0B, 0x66, 0xAE, 0x90, 0x3E, 0xFD, 0x08, 0xA9, 0xDE, 0xD9, 0x5F, 0xBE, 0x41, 0x36, 0xB1, 0xDF,
    0x14, 0x1A, 0xD8, 0x4D, 0x23, 0x58, 0x62, 0x6C, 0xAF, 0xDA, 0x9F, 0xD8, 0x05, 0x1D, 0x70, 0xF0,
    0xDC, 0x70, 0x1B, 0x33, 0xF3, 0xF4, 0xD0, 0x83, 0xD0, 0x10, 0x88, 0xD4, 0x0C, 0xA6, 0xAE, 0x6F,
};
// clang-format on
static const uint8_t password[9] = "password";
static const uint8_t w[11] = "virgil.com";
static const uint8_t t[6] = "alice";
static const uint8_t msk[14] = "master secret";
static const uint8_t msk1[14] = "secret master";
static const uint8_t ssk[14] = "server secret";

void
blind_eval_deblind(pythia_buf_t *deblinded_password) {
    pythia_buf_t blinded_password, blinding_secret, transformed_password, transformation_private_key, transformed_tweak,
            transformation_key_id_buf, tweak_buf, pythia_secret_buf, pythia_scope_secret_buf, password_buf,
            transformation_public_key;

    blinded_password.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    blinded_password.allocated = PYTHIA_G1_BUF_SIZE;

    blinding_secret.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    blinding_secret.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    transformed_password.allocated = PYTHIA_GT_BUF_SIZE;

    transformation_private_key.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    transformation_private_key.allocated = PYTHIA_BN_BUF_SIZE;

    transformation_public_key.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    transformation_public_key.allocated = PYTHIA_G1_BUF_SIZE;

    transformed_tweak.p = (uint8_t *)malloc(PYTHIA_G2_BUF_SIZE);
    transformed_tweak.allocated = PYTHIA_G2_BUF_SIZE;

    transformation_key_id_buf.p = (uint8_t *)w;
    transformation_key_id_buf.len = 10;

    tweak_buf.p = (uint8_t *)t;
    tweak_buf.len = 5;

    pythia_secret_buf.p = (uint8_t *)msk;
    pythia_secret_buf.len = 13;

    pythia_scope_secret_buf.p = (uint8_t *)ssk;
    pythia_scope_secret_buf.len = 13;

    password_buf.p = (uint8_t *)password;
    password_buf.len = 8;

    if (pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    if (pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &pythia_secret_buf,
                &pythia_scope_secret_buf, &transformation_private_key, &transformation_public_key))
        TEST_FAIL();

    if (pythia_w_transform(
                &blinded_password, &tweak_buf, &transformation_private_key, &transformed_password, &transformed_tweak))
        TEST_FAIL();

    if (pythia_w_deblind(&transformed_password, &blinding_secret, deblinded_password))
        TEST_FAIL();

    free(blinded_password.p);
    free(blinding_secret.p);
    free(transformed_password.p);
    free(transformation_private_key.p);
    free(transformation_public_key.p);
    free(transformed_tweak.p);
}

void
test1_DeblindStability() {
    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    pythia_buf_t deblinded_password;

    const int iterations = 10;
    for (int i = 0; i < iterations; i++) {
        deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
        deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

        blind_eval_deblind(&deblinded_password);

        TEST_ASSERT_EQUAL_MEMORY(deblinded_bin, deblinded_password.p, 384);

        free(deblinded_password.p);
        deblinded_password.allocated = 0;
    }

    vscp_pythia_cleanup();
}

void
test2_BlindEvalProveVerify() {
    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    pythia_buf_t blinded_password, blinding_secret, transformed_password, transformation_private_key, transformed_tweak,
            transformation_public_key, proof_value_c, proof_value_u, transformation_key_id_buf, tweak_buf,
            pythia_secret_buf, pythia_scope_secret_buf, password_buf;

    blinded_password.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    blinded_password.allocated = PYTHIA_G1_BUF_SIZE;

    blinding_secret.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    blinding_secret.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    transformed_password.allocated = PYTHIA_GT_BUF_SIZE;

    transformation_private_key.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    transformation_private_key.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_tweak.p = (uint8_t *)malloc(PYTHIA_G2_BUF_SIZE);
    transformed_tweak.allocated = PYTHIA_G2_BUF_SIZE;

    transformation_public_key.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    transformation_public_key.allocated = PYTHIA_G1_BUF_SIZE;

    proof_value_c.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    proof_value_c.allocated = PYTHIA_BN_BUF_SIZE;

    proof_value_u.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    proof_value_u.allocated = PYTHIA_BN_BUF_SIZE;

    transformation_key_id_buf.p = (uint8_t *)w;
    transformation_key_id_buf.len = 10;

    tweak_buf.p = (uint8_t *)t;
    tweak_buf.len = 5;

    pythia_secret_buf.p = (uint8_t *)msk;
    pythia_secret_buf.len = 13;

    pythia_scope_secret_buf.p = (uint8_t *)ssk;
    pythia_scope_secret_buf.len = 13;

    password_buf.p = (uint8_t *)password;
    password_buf.len = 8;

    if (pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    if (pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &pythia_secret_buf,
                &pythia_scope_secret_buf, &transformation_private_key, &transformation_public_key))
        TEST_FAIL();

    if (pythia_w_transform(
                &blinded_password, &tweak_buf, &transformation_private_key, &transformed_password, &transformed_tweak))
        TEST_FAIL();

    if (pythia_w_prove(&transformed_password, &blinded_password, &transformed_tweak, &transformation_private_key,
                &transformation_public_key, &proof_value_c, &proof_value_u))
        TEST_FAIL();

    int verified = 0;
    if (pythia_w_verify(&transformed_password, &blinded_password, &tweak_buf, &transformation_public_key,
                &proof_value_c, &proof_value_u, &verified))
        TEST_FAIL();

    TEST_ASSERT_NOT_EQUAL(0, verified);

    free(blinded_password.p);
    free(blinding_secret.p);
    free(transformed_password.p);
    free(transformation_private_key.p);
    free(transformed_tweak.p);
    free(transformation_public_key.p);
    free(proof_value_c.p);
    free(proof_value_u.p);

    vscp_pythia_cleanup();
}

void
test3_UpdateDelta() {
    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    pythia_buf_t blinded_password, blinding_secret, transformed_password, transformation_private_key,
            new_transformation_private_key, transformed_tweak, password_update_token, updated_transformation_public_key,
            transformation_public_key, proof_value_c, proof_value_u, transformation_key_id_buf, tweak_buf,
            pythia_secret_buf, pythia_scope_secret_buf, password_buf, new_pythia_secret_buf, updated_deblinded_password,
            deblinded_password, new_deblinded_password;

    blinded_password.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    blinded_password.allocated = PYTHIA_G1_BUF_SIZE;

    blinding_secret.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    blinding_secret.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    transformed_password.allocated = PYTHIA_GT_BUF_SIZE;

    transformation_private_key.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    transformation_private_key.allocated = PYTHIA_BN_BUF_SIZE;

    new_transformation_private_key.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    new_transformation_private_key.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_tweak.p = (uint8_t *)malloc(PYTHIA_G2_BUF_SIZE);
    transformed_tweak.allocated = PYTHIA_G2_BUF_SIZE;

    transformation_public_key.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    transformation_public_key.allocated = PYTHIA_G1_BUF_SIZE;

    proof_value_c.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    proof_value_c.allocated = PYTHIA_BN_BUF_SIZE;

    proof_value_u.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    proof_value_u.allocated = PYTHIA_BN_BUF_SIZE;

    password_update_token.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    password_update_token.allocated = PYTHIA_BN_BUF_SIZE;

    updated_transformation_public_key.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    updated_transformation_public_key.allocated = PYTHIA_G1_BUF_SIZE;

    tweak_buf.p = (uint8_t *)t;
    tweak_buf.len = 5;

    transformation_key_id_buf.p = (uint8_t *)w;
    transformation_key_id_buf.len = 10;

    pythia_secret_buf.p = (uint8_t *)msk;
    pythia_secret_buf.len = 13;

    new_pythia_secret_buf.p = (uint8_t *)msk1;
    new_pythia_secret_buf.len = 13;

    pythia_scope_secret_buf.p = (uint8_t *)ssk;
    pythia_scope_secret_buf.len = 13;

    password_buf.p = (uint8_t *)password;
    password_buf.len = 8;

    deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

    new_deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    new_deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

    updated_deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    updated_deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

    if (pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    if (pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &pythia_secret_buf,
                &pythia_scope_secret_buf, &transformation_private_key, &transformation_public_key))
        TEST_FAIL();

    if (pythia_w_transform(
                &blinded_password, &tweak_buf, &transformation_private_key, &transformed_password, &transformed_tweak))
        TEST_FAIL();

    if (pythia_w_deblind(&transformed_password, &blinding_secret, &deblinded_password))
        TEST_FAIL();

    if (pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &new_pythia_secret_buf,
                &pythia_scope_secret_buf, &new_transformation_private_key, &transformation_public_key))
        TEST_FAIL();

    if (pythia_w_get_password_update_token(
                &transformation_private_key, &new_transformation_private_key, &password_update_token))
        TEST_FAIL();

    if (pythia_w_update_deblinded_with_token(&deblinded_password, &password_update_token, &updated_deblinded_password))
        TEST_FAIL();

    if (pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    if (pythia_w_transform(&blinded_password, &tweak_buf, &new_transformation_private_key, &transformed_password,
                &transformed_tweak))
        TEST_FAIL();

    if (pythia_w_deblind(&transformed_password, &blinding_secret, &new_deblinded_password))
        TEST_FAIL();

    TEST_ASSERT_EQUAL_INT(updated_deblinded_password.len, new_deblinded_password.len);
    TEST_ASSERT_EQUAL_MEMORY(updated_deblinded_password.p, new_deblinded_password.p, updated_deblinded_password.len);

    free(updated_deblinded_password.p);
    free(new_deblinded_password.p);
    free(deblinded_password.p);
    free(updated_transformation_public_key.p);
    free(password_update_token.p);
    free(proof_value_u.p);
    free(proof_value_c.p);
    free(transformation_public_key.p);
    free(transformed_tweak.p);
    free(transformation_private_key.p);
    free(new_transformation_private_key.p);
    free(transformed_password.p);
    free(blinding_secret.p);
    free(blinded_password.p);

    vscp_pythia_cleanup();
}

void
test4_BlindHugePassword() {
    const uint8_t password[137] =
            "passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpa"
            "sswordpasswordpasswordpassword";

    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    pythia_buf_t blinded_password, blinding_secret, password_buf;

    blinded_password.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    blinded_password.allocated = PYTHIA_G1_BUF_SIZE;

    blinding_secret.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    blinding_secret.allocated = PYTHIA_BN_BUF_SIZE;

    password_buf.p = (uint8_t *)password;
    password_buf.len = 136;

    if (!pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    free(blinded_password.p);
    free(blinding_secret.p);

    vscp_pythia_cleanup();
}

#endif

int
main() {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test1_DeblindStability);
    RUN_TEST(test2_BlindEvalProveVerify);
    RUN_TEST(test3_UpdateDelta);
    RUN_TEST(test4_BlindHugePassword);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
