//  Copyright (C) 2015-2021 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ECIES_ENVELOPE && VSCF_AES256_CBC && VSCF_HMAC && VSCF_KDF2 && VSCF_SHA384)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_aes256_cbc.h"
#include "vscf_ecies_envelope.h"
#include "vscf_hmac.h"
#include "vscf_kdf2.h"
#include "vscf_sha384.h"
#include "vscf_simple_alg_info.h"

#include "test_data_ecies_envelope.h"


void
test__pack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_valid_packed_data(void) {

    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    envelope.ephemeral_public_key =
            vscf_raw_public_key_new_with_data(test_data_ecies_envelope_ED25519_EPHEMERAL_PUBLIC_KEY, &alg_info);

    vscf_impl_t *hash = vscf_sha384_impl(vscf_sha384_new());

    vscf_kdf2_t *kdf2 = vscf_kdf2_new();
    vscf_kdf2_use_hash(kdf2, hash);
    envelope.kdf = vscf_kdf2_impl(kdf2);

    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, hash);
    envelope.mac = vscf_hmac_impl(hmac);

    vscf_aes256_cbc_t *aes256 = vscf_aes256_cbc_new();
    vscf_aes256_cbc_set_nonce(aes256, test_data_ecies_envelope_ED25519_AES256_CBC_IV);
    envelope.cipher = vscf_aes256_cbc_impl(aes256);

    envelope.mac_digest = vsc_buffer_new_with_data(test_data_ecies_envelope_ED25519_SHA384_MAC_DIGEST);
    envelope.encrypted_content = vsc_buffer_new_with_data(test_data_ecies_envelope_ED25519_ENCRYPTED_CONTENT);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_envelope_packed_len(&envelope));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ecies_envelope_pack(&envelope, out));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_envelope_ED25519_PACKED_V2_COMPAT, out);

    vsc_buffer_destroy(&out);
    vscf_ecies_envelope_cleanup_properties(&envelope);
}

void
test__unpack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__no_errors(void) {

    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};

    vscf_status_t status = vscf_ecies_envelope_unpack(&envelope, test_data_ecies_envelope_ED25519_PACKED);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_ecies_envelope_cleanup_properties(&envelope);
}

void
test__unpack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__when_packed_again_equal_to_initial(void) {

    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};

    vscf_status_t status = vscf_ecies_envelope_unpack(&envelope, test_data_ecies_envelope_ED25519_PACKED);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_envelope_packed_len(&envelope));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ecies_envelope_pack(&envelope, out));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_envelope_ED25519_PACKED_V2_COMPAT, out);

    vsc_buffer_destroy(&out);
    vscf_ecies_envelope_cleanup_properties(&envelope);
}

void
test__unpack__v2_compat_ed25519__when_packed_again_equal_to_initial(void) {

    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};

    vscf_status_t status = vscf_ecies_envelope_unpack(&envelope, test_data_ecies_envelope_ED25519_PACKED_V2_COMPAT);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_envelope_packed_len(&envelope));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ecies_envelope_pack(&envelope, out));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_envelope_ED25519_PACKED_V2_COMPAT, out);

    vsc_buffer_destroy(&out);
    vscf_ecies_envelope_cleanup_properties(&envelope);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__pack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_valid_packed_data);
    RUN_TEST(test__unpack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__no_errors);
    RUN_TEST(test__unpack__ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__when_packed_again_equal_to_initial);
    RUN_TEST(test__unpack__v2_compat_ed25519__when_packed_again_equal_to_initial);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
