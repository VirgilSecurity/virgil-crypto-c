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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_VERIFIER && VSCF_KEY_PROVIDER && VSCF_KEY && VSCF_PUBLIC_KEY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_verifier.h"

#include "test_data_signer_verifier.h"

void
test__reset__with_ed25519_sha384_signature__format_is_valid(void) {

    vscf_verifier_t *verifier = vscf_verifier_new();

    vscf_status_t status = vscf_verifier_reset(verifier, test_signer_ED25519_SHA384_SIGNATURE);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_verifier_destroy(&verifier);
}

void
test__verify__ed25519_sha384_signature_with_public_key__is_valid(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_signer_ED25519_PUBLIC_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_verifier_t *verifier = vscf_verifier_new();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_verifier_reset(verifier, test_signer_ED25519_SHA384_SIGNATURE));
    vscf_verifier_append_data(verifier, test_signer_DATA);
    bool is_valid = vscf_verifier_verify(verifier, public_key);

    TEST_ASSERT_TRUE(is_valid);

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__verify__ed25519_sha384_signature_v2_compat_with_public_key__is_valid(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_signer_ED25519_PUBLIC_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_verifier_t *verifier = vscf_verifier_new();

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_verifier_reset(verifier, test_signer_ED25519_SHA384_SIGNATURE_V2_COMPAT));
    vscf_verifier_append_data(verifier, test_signer_DATA);
    bool is_valid = vscf_verifier_verify(verifier, public_key);

    TEST_ASSERT_TRUE(is_valid);

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__reset__with_rsa2048_sha384_signature__format_is_valid(void) {

    vscf_verifier_t *verifier = vscf_verifier_new();

    vscf_status_t status = vscf_verifier_reset(verifier, test_signer_RSA2048_SHA384_SIGNATURE);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_verifier_destroy(&verifier);
}

void
test__verify__rsa2048_sha384_signature_with_public_key__is_valid(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_signer_RSA2048_PUBLIC_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_verifier_t *verifier = vscf_verifier_new();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_verifier_reset(verifier, test_signer_RSA2048_SHA384_SIGNATURE));
    vscf_verifier_append_data(verifier, test_signer_DATA);
    bool is_valid = vscf_verifier_verify(verifier, public_key);

    TEST_ASSERT_TRUE(is_valid);

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__verify__rsa2048_sha384_signature_v2_compat_with_public_key__is_valid(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_signer_RSA2048_PUBLIC_KEY_PKCS8, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_verifier_t *verifier = vscf_verifier_new();

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_verifier_reset(verifier, test_signer_RSA2048_SHA384_SIGNATURE_V2_COMPAT));
    vscf_verifier_append_data(verifier, test_signer_DATA);
    bool is_valid = vscf_verifier_verify(verifier, public_key);

    TEST_ASSERT_TRUE(is_valid);

    vscf_verifier_destroy(&verifier);
    vscf_impl_destroy(&public_key);
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
    RUN_TEST(test__reset__with_ed25519_sha384_signature__format_is_valid);
    RUN_TEST(test__verify__ed25519_sha384_signature_with_public_key__is_valid);
    RUN_TEST(test__verify__ed25519_sha384_signature_v2_compat_with_public_key__is_valid);
    RUN_TEST(test__reset__with_rsa2048_sha384_signature__format_is_valid);
    RUN_TEST(test__verify__rsa2048_sha384_signature_with_public_key__is_valid);
    RUN_TEST(test__verify__rsa2048_sha384_signature_v2_compat_with_public_key__is_valid);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
