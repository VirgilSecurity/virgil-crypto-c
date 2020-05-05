//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_KEY_INFO
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_key_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_hybrid_key_alg_info.h"


void
test__ed25519_simple_alg_info__is_valid(void) {

    //
    //  Create key alg info.
    //
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_key_info_t *key_info = vscf_key_info_new_with_alg_info(alg_info);

    //
    //  Check.
    //
    TEST_ASSERT_FALSE(vscf_key_info_is_compound(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_signer(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_signer(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_info_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_cipher_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_signer_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_second_key_alg_id(key_info));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&alg_info);
    vscf_key_info_destroy(&key_info);
}

void
test__curve25519_ed25519_compound_key_alg_info__is_valid(void) {

    //
    //  Create key alg info.
    //
    vscf_impl_t *curve25519_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *ed25519_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &curve25519_info, &ed25519_info));

    vscf_key_info_t *key_info = vscf_key_info_new_with_alg_info(alg_info);

    //
    //  Check.
    //
    TEST_ASSERT_TRUE(vscf_key_info_is_compound(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_signer(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_signer(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_COMPOUND_KEY, vscf_key_info_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_info_compound_cipher_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_info_compound_signer_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_second_key_alg_id(key_info));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&alg_info);
    vscf_key_info_destroy(&key_info);
}

void
test__curve25519_ed25519_hybrid_key_alg_info__is_valid(void) {

    //
    //  Create key alg info.
    //
    vscf_impl_t *curve25519_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *ed25519_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_impl_t *alg_info = vscf_hybrid_key_alg_info_impl(
            vscf_hybrid_key_alg_info_new_with_infos_disown(vscf_alg_id_HYBRID_KEY, &curve25519_info, &ed25519_info));

    vscf_key_info_t *key_info = vscf_key_info_new_with_alg_info(alg_info);

    //
    //  Check.
    //
    TEST_ASSERT_FALSE(vscf_key_info_is_compound(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_compound_hybrid_signer(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_cipher(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid_post_quantum_signer(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_info_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_cipher_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_signer_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_info_hybrid_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_info_hybrid_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_cipher_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_compound_hybrid_signer_second_key_alg_id(key_info));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&alg_info);
    vscf_key_info_destroy(&key_info);
}

void
test__curve25519_round5_ed25519_falcon_compound_hybrid_key_alg_info__is_valid(void) {

    //
    //  Create key alg info.
    //
    vscf_impl_t *curve25519_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *ed25519_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_impl_t *round5_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_1CCA_5D));

    vscf_impl_t *falcon_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_FALCON));

    vscf_impl_t *cipher_alg_info = vscf_hybrid_key_alg_info_impl(
            vscf_hybrid_key_alg_info_new_with_infos_disown(vscf_alg_id_HYBRID_KEY, &curve25519_info, &round5_info));

    vscf_impl_t *signer_alg_info = vscf_hybrid_key_alg_info_impl(
            vscf_hybrid_key_alg_info_new_with_infos_disown(vscf_alg_id_HYBRID_KEY, &ed25519_info, &falcon_info));

    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));


    vscf_key_info_t *key_info = vscf_key_info_new_with_alg_info(alg_info);

    //
    //  Check.
    //
    TEST_ASSERT_TRUE(vscf_key_info_is_compound(key_info));
    TEST_ASSERT_FALSE(vscf_key_info_is_hybrid(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_compound_hybrid(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_compound_hybrid_cipher(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_compound_hybrid_signer(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_hybrid_post_quantum(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_hybrid_post_quantum_cipher(key_info));
    TEST_ASSERT_TRUE(vscf_key_info_is_hybrid_post_quantum_signer(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_COMPOUND_KEY, vscf_key_info_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_info_compound_cipher_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_info_compound_signer_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_NONE, vscf_key_info_hybrid_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_info_compound_hybrid_cipher_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_1CCA_5D, vscf_key_info_compound_hybrid_cipher_second_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_info_compound_hybrid_signer_first_key_alg_id(key_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_info_compound_hybrid_signer_second_key_alg_id(key_info));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&alg_info);
    vscf_key_info_destroy(&key_info);
}
#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__ed25519_simple_alg_info__is_valid);
    RUN_TEST(test__curve25519_ed25519_compound_key_alg_info__is_valid);
    RUN_TEST(test__curve25519_ed25519_hybrid_key_alg_info__is_valid);
    RUN_TEST(test__curve25519_round5_ed25519_falcon_compound_hybrid_key_alg_info__is_valid);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
