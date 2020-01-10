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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_PROVIDER && VSCF_ED25519)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"
#include "vscf_fake_random.h"
#include "vscf_aes256_gcm.h"
#include "vscf_random_padding.h"

#include "test_data_recipient_cipher.h"

enum {
    k_data_range_MIN = 1,
    k_data_range_MAX = 4 * 1024,
};

// --------------------------------------------------------------------------
//  Encrypt / Decrypt / No Signature / No Padding
// --------------------------------------------------------------------------
void
inner_test__encrypt_decrypt__no_signature_no_padding__success(
        vsc_data_t public_key_data, vsc_data_t private_key_data, size_t data_range_from, size_t data_range_to) {
    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    for (size_t data_len = data_range_from; data_len <= data_range_to; ++data_len) {

        printf("\r-- Encrypt / Decrypt / No Signature / No Padding - data length: %zu -- ", data_len);
        fflush(stdout);

        vsc_buffer_t *ab_plaintext = vsc_buffer_new_with_capacity(data_len);
        memset(vsc_buffer_unused_bytes(ab_plaintext), 0xAB, vsc_buffer_unused_len(ab_plaintext));
        vsc_buffer_inc_used(ab_plaintext, data_len);

        vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

        vscf_recipient_cipher_add_key_recipient(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

        //
        //  Encrypt.
        //
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(recipient_cipher));

        size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
        size_t enc_msg_len =
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, vsc_buffer_data(ab_plaintext).len) +
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

        vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(message_info_len + enc_msg_len);

        vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_encryption(recipient_cipher, vsc_buffer_data(ab_plaintext), enc_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

        //
        //  Clear and decrypt.
        //
        vscf_recipient_cipher_release_random(recipient_cipher);
        vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

        vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg)) +
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

        TEST_ASSERT_EQUAL(
                vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(recipient_cipher,
                                             test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

        //
        //  Check.
        //
        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(ab_plaintext), dec_msg);

        //
        //  Cleanup.
        //
        vsc_buffer_destroy(&ab_plaintext);
        vsc_buffer_destroy(&dec_msg);
        vsc_buffer_destroy(&enc_msg);
        vscf_recipient_cipher_destroy(&recipient_cipher);
    }

    printf("\r-- ");

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__encrypt_decrypt__no_signature_no_padding_with_ed25519_key_recipient__success(void) {
#if ENABLE_HEAVY_TESTS
    inner_test__encrypt_decrypt__no_signature_no_padding__success(test_data_recipient_cipher_ED25519_PUBLIC_KEY,
            test_data_recipient_cipher_ED25519_PRIVATE_KEY, k_data_range_MIN, k_data_range_MAX);
#else
    TEST_IGNORE_MESSAGE("Heavy tests are disabled.");
#endif
}

// --------------------------------------------------------------------------
//  Encrypt / Decrypt / No Signature / Random Padding
// --------------------------------------------------------------------------
void
inner_test__encrypt_decrypt__no_signature_with_random_padding__success(
        vsc_data_t public_key_data, vsc_data_t private_key_data, size_t data_range_from, size_t data_range_to) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xFF);

    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_use_random(random_padding, vscf_fake_random_impl(fake_random));

    for (size_t data_len = data_range_from; data_len <= data_range_to; ++data_len) {

        printf("\r-- Encrypt / Decrypt / No Signature / Random Padding - data length: %zu -- ", data_len);
        fflush(stdout);

        vsc_buffer_t *ab_plaintext = vsc_buffer_new_with_capacity(data_len);
        memset(vsc_buffer_unused_bytes(ab_plaintext), 0xAB, vsc_buffer_unused_len(ab_plaintext));
        vsc_buffer_inc_used(ab_plaintext, data_len);

        vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
        vscf_recipient_cipher_use_encryption_padding(recipient_cipher, vscf_random_padding_impl(random_padding));
        vscf_recipient_cipher_release_padding_params(recipient_cipher);
        vscf_recipient_cipher_take_padding_params(recipient_cipher, vscf_padding_params_new_with_constraints(160, 160));

        vscf_recipient_cipher_add_key_recipient(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

        //
        //  Encrypt.
        //
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(recipient_cipher));

        size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
        size_t enc_msg_len =
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, vsc_buffer_data(ab_plaintext).len) +
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

        vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(message_info_len + enc_msg_len);

        vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_encryption(recipient_cipher, vsc_buffer_data(ab_plaintext), enc_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

        //
        //  Clear and decrypt.
        //
        vscf_recipient_cipher_release_random(recipient_cipher);
        vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

        vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg)) +
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

        TEST_ASSERT_EQUAL(
                vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(recipient_cipher,
                                             test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

        //
        //  Check.
        //
        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(ab_plaintext), dec_msg);

        //
        //  Cleanup.
        //
        vsc_buffer_destroy(&ab_plaintext);
        vsc_buffer_destroy(&dec_msg);
        vsc_buffer_destroy(&enc_msg);
        vscf_recipient_cipher_destroy(&recipient_cipher);
    }

    printf("\r-- ");

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&fake_random);
    vscf_random_padding_destroy(&random_padding);
}

void
test__encrypt_decrypt__no_signature_with_random_padding_and_ed25519_key_recipient__success(void) {
#if ENABLE_HEAVY_TESTS
    inner_test__encrypt_decrypt__no_signature_with_random_padding__success(
            test_data_recipient_cipher_ED25519_PUBLIC_KEY, test_data_recipient_cipher_ED25519_PRIVATE_KEY,
            k_data_range_MIN, k_data_range_MAX);
#else
    TEST_IGNORE_MESSAGE("Heavy tests are disabled.");
#endif
}


// --------------------------------------------------------------------------
//  Encrypt / Decrypt / Signature / Random Padding
// --------------------------------------------------------------------------
void
inner_test__encrypt_decrypt__with_signature_and_random_padding__success(
        vsc_data_t public_key_data, vsc_data_t private_key_data, size_t data_range_from, size_t data_range_to) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xFF);

    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_use_random(random_padding, vscf_fake_random_impl(fake_random));

    for (size_t data_len = data_range_from; data_len <= data_range_to; ++data_len) {

        printf("\r-- Encrypt / Decrypt / Signature / Random Padding - data length: %zu -- ", data_len);
        fflush(stdout);

        vsc_buffer_t *ab_plaintext = vsc_buffer_new_with_capacity(data_len);
        memset(vsc_buffer_unused_bytes(ab_plaintext), 0xAB, vsc_buffer_unused_len(ab_plaintext));
        vsc_buffer_inc_used(ab_plaintext, data_len);

        vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
        vscf_recipient_cipher_use_encryption_padding(recipient_cipher, vscf_random_padding_impl(random_padding));
        vscf_recipient_cipher_release_padding_params(recipient_cipher);
        vscf_recipient_cipher_take_padding_params(recipient_cipher, vscf_padding_params_new_with_constraints(160, 160));

        vscf_recipient_cipher_add_key_recipient(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_add_signer(recipient_cipher,
                                                       test_data_recipient_cipher_RECIPIENT_ID, private_key));

        //
        //  Sign then Encrypt.
        //
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_start_signed_encryption(recipient_cipher, vsc_buffer_data(ab_plaintext).len));

        size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
        size_t enc_msg_len =
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, vsc_buffer_data(ab_plaintext).len) +
                vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

        vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(message_info_len + enc_msg_len);

        vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_encryption(recipient_cipher, vsc_buffer_data(ab_plaintext), enc_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

        size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
        vsc_buffer_t *enc_msg_footer = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);

        TEST_ASSERT_EQUAL(
                vscf_status_SUCCESS, vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer));

        //
        //  Clear and decrypt.
        //
        vscf_recipient_cipher_release_random(recipient_cipher);
        vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

        vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg)) +
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg_footer)) +
                vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

        TEST_ASSERT_EQUAL(
                vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(recipient_cipher,
                                             test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg_footer), dec_msg));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

        //
        //  Verify.
        //
        TEST_ASSERT_TRUE(vscf_recipient_cipher_is_data_signed(recipient_cipher));
        const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(recipient_cipher);
        TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
        const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

        TEST_ASSERT_EQUAL_DATA(test_data_recipient_cipher_RECIPIENT_ID, vscf_signer_info_signer_id(signer_info));
        const bool verified = vscf_recipient_cipher_verify_signer_info(recipient_cipher, signer_info, public_key);
        TEST_ASSERT_TRUE(verified);

        //
        //  Check.
        //
        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(ab_plaintext), dec_msg);

        //
        //  Cleanup.
        //
        vsc_buffer_destroy(&ab_plaintext);
        vsc_buffer_destroy(&dec_msg);
        vsc_buffer_destroy(&enc_msg);
        vscf_recipient_cipher_destroy(&recipient_cipher);
    }

    printf("\r-- ");

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&fake_random);
    vscf_random_padding_destroy(&random_padding);
}

void
test__encrypt_decrypt__with_signature_and_random_padding_and_ed25519_key_recipient__success(void) {
#if ENABLE_HEAVY_TESTS
    inner_test__encrypt_decrypt__with_signature_and_random_padding__success(
            test_data_recipient_cipher_ED25519_PUBLIC_KEY, test_data_recipient_cipher_ED25519_PRIVATE_KEY,
            k_data_range_MIN, k_data_range_MAX);
#else
    TEST_IGNORE_MESSAGE("Heavy tests are disabled.");
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
    RUN_TEST(test__encrypt_decrypt__no_signature_no_padding_with_ed25519_key_recipient__success);
    RUN_TEST(test__encrypt_decrypt__no_signature_with_random_padding_and_ed25519_key_recipient__success);
    RUN_TEST(test__encrypt_decrypt__with_signature_and_random_padding_and_ed25519_key_recipient__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
