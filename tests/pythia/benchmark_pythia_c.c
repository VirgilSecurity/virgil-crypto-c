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
#include "pythia_c.h"
#include "pythia_init.h"
#include "pythia_init_c.h"
#include "vscp_pythia.h"

#include <relic/relic.h>

void
bench1_BlindEvalProveVerify() {
    vscp_pythia_init();

    const int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        const uint8_t password[9] = "password";
        const uint8_t w[11] = "virgil.com";
        const uint8_t t[6] = "alice";
        const uint8_t msk[14] = "master secret";
        const uint8_t ssk[14] = "server secret";

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

        TRY {
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
        }
        CATCH_ANY {
            TEST_FAIL();
        }
        FINALLY {
            bn_free(u);
            bn_free(c);
            g1_free(pi_p);
            g2_free(tTilde);
            bn_free(kw);
            gt_free(y);
            bn_free(rInv);
            g1_free(blinded);
        }
    }

    vscp_pythia_cleanup();
}

#endif

int
main() {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(bench1_BlindEvalProveVerify);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
