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

#include "pythia_c.h"
#include "pythia_init.h"
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
static const uint8_t ssk[14] = "server secret";

void
blind_eval_deblind(gt_t deblinded) {
    g1_t blinded;
    g1_null(blinded);
    bn_t rInv;
    bn_null(rInv);
    gt_t y;
    gt_null(y);
    bn_t kw;
    bn_null(kw);
    g2_t tTilde;
    g2_null(tTilde);
    g1_t pi_p;
    g1_null(pi_p);

    g1_new(blinded);
    bn_new(rInv);

    pythia_blind(password, 8, blinded, rInv);

    gt_new(y);
    bn_new(kw);
    g2_new(tTilde);
    g1_new(pi_p);

    pythia_compute_kw(w, 10, msk, 13, ssk, 13, kw, pi_p);

    pythia_eval(blinded, t, 5, kw, y, tTilde);

    pythia_deblind(y, rInv, deblinded);

    g1_free(blinded);
    bn_free(rInv);
    gt_free(y);
    bn_free(kw);
    g2_free(tTilde);
    g1_free(pi_p);
}

void
test1_DeblindStability() {
    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    gt_t deblinded1;
    gt_null(deblinded1);
    gt_t deblinded2;
    gt_null(deblinded2);

    gt_new(deblinded1);

    gt_read_bin(deblinded1, deblinded_bin, 384);

    const int iterations = 10;

    for (int i = 0; i < iterations; i++) {
        gt_new(deblinded2);
        blind_eval_deblind(deblinded2);

        TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), RLC_EQ);
        gt_free(deblinded2);
    }

    gt_free(deblinded1);
    gt_free(deblinded2);

    vscp_pythia_cleanup();
}

void
test2_BlindEvalProveVerify() {
    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    g1_t blinded;
    g1_null(blinded);
    bn_t rInv;
    bn_null(rInv);
    gt_t y;
    gt_null(y);
    bn_t kw;
    bn_null(kw);
    g2_t tTilde;
    g2_null(tTilde);
    g1_t pi_p;
    g1_null(pi_p);
    bn_t c;
    bn_null(c);
    bn_t u;
    bn_null(u);

    g1_new(blinded);
    bn_new(rInv);

    pythia_blind(password, 8, blinded, rInv);

    gt_new(y);
    bn_new(kw);
    g2_new(tTilde);
    g1_new(pi_p);

    pythia_compute_kw(w, 10, msk, 13, ssk, 13, kw, pi_p);

    pythia_eval(blinded, t, 5, kw, y, tTilde);

    bn_new(c);
    bn_new(u);

    pythia_prove(y, blinded, tTilde, kw, pi_p, c, u);

    int verified = 0;
    pythia_verify(y, blinded, t, 5, pi_p, c, u, &verified);
    TEST_ASSERT_NOT_EQUAL(verified, 0);

    bn_free(u);
    bn_free(c);
    g1_free(pi_p);
    g2_free(tTilde);
    bn_free(kw);
    gt_free(y);
    bn_free(rInv);
    g1_free(blinded);

    vscp_pythia_cleanup();
}

void
test3_UpdateDelta() {
    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk0[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    TEST_ASSERT_EQUAL(vscp_status_SUCCESS, vscp_pythia_configure());

    g1_t blinded;
    g1_new(blinded);
    bn_t rInv;
    bn_new(rInv);
    pythia_blind(password, 8, blinded, rInv);

    gt_t y;
    gt_new(y);
    g1_t pi_p;
    g1_new(pi_p);

    bn_t kw;
    bn_new(kw);

    g2_t tTilde;
    g2_new(tTilde);

    pythia_compute_kw(w, 10, msk0, 13, ssk, 13, kw, pi_p);

    pythia_eval(blinded, t, 5, kw, y, tTilde);

    gt_t deblinded0;
    gt_new(deblinded0);

    pythia_deblind(y, rInv, deblinded0);

    bn_t kw1;
    bn_new(kw1);
    const uint8_t msk1[14] = "secret master";
    pythia_compute_kw(w, 10, msk1, 13, ssk, 13, kw1, pi_p);

    bn_t del;
    bn_new(del);

    get_delta(kw, kw1, del);

    gt_t deblinded1;
    gt_new(deblinded1);

    pythia_update_with_delta(deblinded0, del, deblinded1);

    g1_t blinded1;
    g1_new(blinded1);
    bn_t rInv1;
    bn_new(rInv1);

    pythia_blind(password, 8, blinded1, rInv1);

    gt_t y1;
    gt_new(y1);
    g2_t tTilde1;
    g2_new(tTilde1);

    pythia_eval(blinded1, t, 5, kw1, y1, tTilde1);

    gt_t deblinded2;
    gt_new(deblinded2);

    pythia_deblind(y1, rInv1, deblinded2);

    TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), RLC_EQ);

    gt_free(deblinded2);
    g2_free(tTilde1);
    bn_free(kw1);
    gt_free(y1);
    bn_free(rInv1);
    g1_free(blinded1);
    gt_free(deblinded1);
    bn_free(del);
    gt_free(deblinded0);
    g2_free(tTilde);
    bn_free(kw);
    g1_free(pi_p);
    gt_free(y);
    bn_free(rInv);
    g1_free(blinded);

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
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
