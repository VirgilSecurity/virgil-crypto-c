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


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_SIGNER && VSCF_SHA384 && VSCF_KEY_PROVIDER && VSCF_KEY && VSCF_PRIVATE_KEY && VSCF_FAKE_RANDOM &&            \
            VSCF_RSA_PRIVATE_KEY && VSCF_ED25519_PRIVATE_KEY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_fake_random.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_rsa_private_key.h"
#include "vscf_sha384.h"
#include "vscf_signer.h"

#include "test_data_signer_verifier.h"

void
test__sign__with_sha384_and_ed25519_private_key__returns_valid_signature(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_signer_ED25519_PRIVATE_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len(signer, private_key));

    vscf_signer_reset(signer);
    vscf_signer_update(signer, test_signer_DATA);
    vscf_signer_sign(signer, private_key, signature);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_signer_ED25519_SHA384_SIGNATURE_V2_COMPAT, signature);

    vsc_buffer_destroy(&signature);
    vscf_signer_destroy(&signer);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__sign__with_sha384_and_rsa2048_private_key__returns_valid_signature(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0XAB);

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_signer_RSA2048_PRIVATE_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(private_key);
    vscf_rsa_private_key_release_random((vscf_rsa_private_key_t *)private_key);
    vscf_rsa_private_key_take_random((vscf_rsa_private_key_t *)private_key, vscf_fake_random_impl(fake_random));

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len(signer, private_key));

    vscf_signer_reset(signer);
    vscf_signer_update(signer, test_signer_DATA);
    vscf_signer_sign(signer, private_key, signature);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_signer_RSA2048_SHA384_SIGNATURE_V2_COMPAT, signature);

    vsc_buffer_destroy(&signature);
    vscf_signer_destroy(&signer);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__sign__with_sha384_and_ed25519_private_key__returns_valid_signature);
    RUN_TEST(test__sign__with_sha384_and_rsa2048_private_key__returns_valid_signature);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
