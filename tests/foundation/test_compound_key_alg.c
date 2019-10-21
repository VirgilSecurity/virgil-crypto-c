//  Copyright (C) 2015-2019 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_COMPOUND_KEY_ALG && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_compound_key_alg.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_fake_random.h"

#include "test_data_compound_key.h"

void
test__generate_key__curve25519_and_ed25519_with_fake_rng__success(void) {

    //
    //  Create dependencies first
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    vscf_compound_key_alg_take_random(key_alg, vscf_fake_random_impl(fake_random));

    vscf_impl_t *private_key =
            vscf_compound_key_alg_generate_key(key_alg, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *decryption_key = vscf_compound_private_key_get_decryption_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(decryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(decryption_key));

    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signing_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(signing_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *encryption_key = vscf_compound_public_key_get_encryption_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(encryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(encryption_key));

    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(verifying_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(verifying_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__generate_post_quantum_key__with_default_rng__success(void) {
#if VSCF_POST_QUANTUM
    //
    //  Create dependencies first
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_compound_key_alg_generate_post_quantum_key(key_alg, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *decryption_key = vscf_compound_private_key_get_decryption_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(decryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5, vscf_key_alg_id(decryption_key));

    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signing_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(signing_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *encryption_key = vscf_compound_public_key_get_encryption_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(encryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5, vscf_key_alg_id(encryption_key));

    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(verifying_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(verifying_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__curve25519_and_ed25519_with_fake_rng__success);
    RUN_TEST(test__generate_post_quantum_key__with_default_rng__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
