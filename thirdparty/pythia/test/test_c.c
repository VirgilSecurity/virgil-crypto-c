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

#include "pythia_c.h"
#include "pythia_init.h"
#include "pythia_init_c.h"

#include "unity.h"

static const char deblinded_hex[769] = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";
static const uint8_t password[9] = "password";
static const uint8_t w[11] = "virgil.com";
static const uint8_t t[6] = "alice";
static const uint8_t msk[14] = "master secret";
static const uint8_t ssk[14] = "server secret";

void blind_eval_deblind(gt_t deblinded) {
    g1_t blinded; g1_null(blinded);
    bn_t rInv; bn_null(rInv);
    gt_t y; gt_null(y);
    bn_t kw; bn_null(kw);
    g2_t tTilde; g2_null(tTilde);
    g1_t pi_p; g1_null(pi_p);

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

void test1_DeblindStability() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);

    gt_t deblinded1; gt_null(deblinded1);
    gt_t deblinded2; gt_null(deblinded2);

    gt_new(deblinded1);

    uint8_t deblinded_bin[384];
    const char *pos = deblinded_hex;
    for (size_t count = 0; count < 384; count++) {
        sscanf(pos, "%2hhx", &deblinded_bin[count]);
        pos += 2;
    }

    gt_read_bin(deblinded1, deblinded_bin, 384);

    const int iterations = 10;

    for (int i = 0; i < iterations; i++) {
        gt_new(deblinded2);
        blind_eval_deblind(deblinded2);

        TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), CMP_EQ);
        gt_free(deblinded2);
    }

    gt_free(deblinded1);
    gt_free(deblinded2);

    pythia_deinit();
}

void test2_BlindEvalProveVerify() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);

    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    g1_t blinded; g1_null(blinded);
    bn_t rInv; bn_null(rInv);
    gt_t y; gt_null(y);
    bn_t kw; bn_null(kw);
    g2_t tTilde; g2_null(tTilde);
    g1_t pi_p; g1_null(pi_p);
    bn_t c; bn_null(c);
    bn_t u; bn_null(u);

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

    pythia_deinit();
}

void test3_UpdateDelta() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);

    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk0[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    g1_t blinded; g1_new(blinded);
    bn_t rInv; bn_new(rInv);
    pythia_blind(password, 8, blinded, rInv);

    gt_t y; gt_new(y);
    g1_t pi_p; g1_new(pi_p);

    bn_t kw; bn_new(kw);

    g2_t tTilde; g2_new(tTilde);

    pythia_compute_kw(w, 10, msk0, 13, ssk, 13, kw, pi_p);

    pythia_eval(blinded, t, 5, kw, y, tTilde);

    gt_t deblinded0; gt_new(deblinded0);

    pythia_deblind(y, rInv, deblinded0);

    bn_t kw1; bn_new(kw1);
    const uint8_t msk1[14] = "secret master";
    pythia_compute_kw(w, 10, msk1, 13, ssk, 13, kw1, pi_p);

    bn_t del; bn_new(del);

    get_delta(kw, kw1, del);

    gt_t deblinded1; gt_new(deblinded1);

    pythia_update_with_delta(deblinded0, del, deblinded1);

    g1_t blinded1; g1_new(blinded1);
    bn_t rInv1; bn_new(rInv1);

    pythia_blind(password, 8, blinded1, rInv1);

    gt_t y1; gt_new(y1);
    g2_t tTilde1; g2_new(tTilde1);

    pythia_eval(blinded1, t, 5, kw1, y1, tTilde1);

    gt_t deblinded2; gt_new(deblinded2);

    pythia_deblind(y1, rInv1, deblinded2);

    TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), CMP_EQ);

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
    gt_free(y);
    bn_free(rInv);
    g1_free(blinded);

    pythia_deinit();
}

int main() {
    UNITY_BEGIN();

    conf_print();

    RUN_TEST(test1_DeblindStability);
    RUN_TEST(test2_BlindEvalProveVerify);
    RUN_TEST(test3_UpdateDelta);

    return UNITY_END();
}
