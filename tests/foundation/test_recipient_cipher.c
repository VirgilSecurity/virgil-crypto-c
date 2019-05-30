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

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_ASN1_DESERIALIZER && VSCF_ED25519_PUBLIC_KEY &&             \
            VSCF_ED25519_PRIVATE_KEY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_key_asn1_deserializer.h"
#include "vscf_alg_factory.h"
#include "vscf_recipient_cipher.h"

#include "test_data_recipient_cipher.h"


void
test__encrypt_decrypt__with_ed25519_key_recipient__success(void) {

    //
    //  Prepare recipients.
    //
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_data_recipient_cipher_ED25519_PUBLIC_KEY, NULL);
    vscf_impl_t *public_key = vscf_alg_factory_create_public_key_from_raw_key(raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

    vscf_raw_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_data_recipient_cipher_ED25519_PRIVATE_KEY, NULL);
    vscf_impl_t *private_key = vscf_alg_factory_create_private_key_from_raw_key(raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    //
    //  Encrypt.
    //
    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(recipient_cipher));

    size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
    size_t enc_msg_len =
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, test_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(message_info_len + enc_msg_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_encryption(recipient_cipher, test_data_recipient_cipher_MESSAGE, enc_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

    //
    //  Clear and decrypt.
    //
    vscf_recipient_cipher_release_random(recipient_cipher);
    vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg)) +
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(
                    recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, dec_msg);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_raw_key_destroy(&raw_private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__decrypt__with_ed25519_private_key__success(void) {
    //
    //  Prepare decryption key.
    //
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_data_recipient_cipher_ED25519_PRIVATE_KEY, NULL);
    vscf_impl_t *private_key = vscf_alg_factory_create_private_key_from_raw_key(raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();


    //
    //  Decrypt.
    //
    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher,
                                                                 test_data_recipient_cipher_ENCRYPTED_MESSAGE.len) +
                                                         vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(
                    recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   test_data_recipient_cipher_ENCRYPTED_MESSAGE, dec_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE_2, dec_msg);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_raw_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__encrypt_decrypt_chunk__with_ed25519_key_recipient__success(void) {

    //
    //  Prepare decryption key.
    //
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_data_recipient_cipher_ED25519_PRIVATE_KEY, NULL);
    vscf_impl_t *private_key = vscf_alg_factory_create_private_key_from_raw_key(raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

    //
    //  Decrypt.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vsc_data_t enc_msg = test_data_recipient_cipher_ENCRYPTED_MESSAGE;

    vsc_buffer_t *dec_msg =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher, enc_msg.len) +
                                         vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(
                    recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    //   Total: 446
    size_t len = 0;

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_data_slice_beg(enc_msg, len, 356), dec_msg));
    len += 356;

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_data_slice_beg(enc_msg, len, 8), dec_msg));
    len += 8;

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_data_slice_beg(enc_msg, len, 8), dec_msg));
    len += 8;

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_data_slice_beg(enc_msg, len, 8), dec_msg));
    len += 8;


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   vsc_data_slice_beg(enc_msg, len, enc_msg.len - len - 2), dec_msg));
    len += enc_msg.len - len - 2;

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_data_slice_beg(enc_msg, len, 2), dec_msg));
    len += 2;

    TEST_ASSERT_EQUAL(enc_msg.len, len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE_2, dec_msg);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_raw_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt_decrypt__with_ed25519_key_recipient__success);
    RUN_TEST(test__decrypt__with_ed25519_private_key__success);
    RUN_TEST(test__encrypt_decrypt_chunk__with_ed25519_key_recipient__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
