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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_SIGNER && VSCF_VERIFIER && VSCF_SHA384 && VSCF_KEY_PROVIDER)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_fake_random.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_sha384.h"
#include "vscf_signer.h"
#include "vscf_verifier.h"

#include "test_data_signer_verifier.h"
#include "test_data_compound_key.h"
#include "test_data_hybrid_key.h"

static void
inner_test__sign_verify__success(vsc_data_t public_key_data, vsc_data_t private_key_data) {
    //
    //  Configure algs.
    //
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0XAB);

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));
    vscf_signer_use_random(signer, vscf_fake_random_impl(fake_random));

    vscf_verifier_t *verifier = vscf_verifier_new();
    // vscf_verifier_use_random(verifier, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Import keys.
    //
    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Sign.
    //
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len(signer, private_key));

    vscf_signer_reset(signer);
    vscf_signer_append_data(signer, test_signer_DATA);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_signer_sign(signer, private_key, signature));

    //
    //  Verify.
    //
    status = vscf_verifier_reset(verifier, vsc_buffer_data(signature));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    vscf_verifier_append_data(verifier, test_signer_DATA);
    const bool is_valid = vscf_verifier_verify(verifier, public_key);

    //
    //  Check.
    //
    TEST_ASSERT_TRUE(is_valid);

    vsc_buffer_destroy(&signature);
    vscf_verifier_destroy(&verifier);
    vscf_signer_destroy(&signer);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_fake_random_destroy(&fake_random);
    vscf_key_provider_destroy(&key_provider);
}

void
test__sign_verify__with_ed25519__success(void) {
#if VSCF_ED25519
    inner_test__sign_verify__success(test_signer_ED25519_PUBLIC_KEY_PKCS8, test_signer_ED25519_PRIVATE_KEY_PKCS8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_ED25519 is disabled");
#endif
}

void
test__sign_verify__with_compound_curve25519_ed25519__success(void) {
#if !VSCF_COMPOUND_KEY_ALG
    TEST_IGNORE_MESSAGE("Feature VSCF_COMPOUND_KEY_ALG is disabled");
#elif !VSCF_ED25519
    TEST_IGNORE_MESSAGE("Feature VSCF_ED25519 is disabled");
#elif !VSCF_CURVE25519
    TEST_IGNORE_MESSAGE("Feature VSCF_CURVE25519 is disabled");
#else
    inner_test__sign_verify__success(test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY_PKCS8_DER,
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY_PKCS8_DER);
#endif
}

void
test__sign_verify__with_hybrid_ed25519_ed25519__success(void) {
#if !VSCF_HYBRID_KEY_ALG
    TEST_IGNORE_MESSAGE("Feature VSCF_HYBRID_KEY_ALG is disabled");
#elif !VSCF_ED25519
    TEST_IGNORE_MESSAGE("Feature VSCF_ED25519 is disabled");
#else
    inner_test__sign_verify__success(test_data_hybrid_key_ED25519_ED25519_PUBLIC_KEY_PKCS8_DER,
            test_data_hybrid_key_ED25519_ED25519_PRIVATE_KEY_PKCS8_DER);
#endif
}

void
test__sign_verify__with_hybrid_ed25519_falcon__success(void) {
#if !VSCF_HYBRID_KEY_ALG
    TEST_IGNORE_MESSAGE("Feature VSCF_HYBRID_KEY_ALG is disabled");
#elif !VSCF_ED25519
    TEST_IGNORE_MESSAGE("Feature VSCF_ED25519 is disabled");
#elif !VSCF_FALCON
    TEST_IGNORE_MESSAGE("Feature VSCF_FALCON is disabled");
#else
    inner_test__sign_verify__success(test_data_hybrid_key_ED25519_FALCON_512_PUBLIC_KEY_PKCS8_DER,
            test_data_hybrid_key_ED25519_FALCON_512_PRIVATE_KEY_PKCS8_DER);
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
    RUN_TEST(test__sign_verify__with_ed25519__success);
    RUN_TEST(test__sign_verify__with_compound_curve25519_ed25519__success);
    RUN_TEST(test__sign_verify__with_hybrid_ed25519_ed25519__success);
    RUN_TEST(test__sign_verify__with_hybrid_ed25519_falcon__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
