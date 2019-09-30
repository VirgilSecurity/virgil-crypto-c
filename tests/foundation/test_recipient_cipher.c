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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_PROVIDER && VSCF_ED25519)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_recipient_cipher.h"
#include "vscf_key_provider.h"
#include "vscf_fake_random.h"

#include "test_data_recipient_cipher.h"


void
test__encrypt_decrypt__with_ed25519_key_recipient__success(void) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    //
    //  Encrypt.
    //
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
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__decrypt__with_ed25519_private_key__success(void) {
    //
    //  Prepare decryption key.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Decrypt.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

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
    vscf_key_provider_destroy(&key_provider);
}

void
test__decrypt__chunks_with_ed25519_key_recipient__success(void) {

    //
    //  Prepare decryption key.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

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
    vscf_key_provider_destroy(&key_provider);
}

void
test__sign_then_encrypt__with_self_signed_ed25519_key_recipient__success(void) {
    //
    //  Prepare random.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    //
    //  Prepare recipients / signers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_add_signer(recipient_cipher,
                                                   test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key));

    //
    //  Encrypt.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_signed_encryption(recipient_cipher, test_data_recipient_cipher_MESSAGE.len));

    size_t message_info_len = vscf_recipient_cipher_message_info_len(recipient_cipher);
    size_t enc_msg_data_len =
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, test_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *enc_msg_header = vsc_buffer_new_with_capacity(message_info_len);
    vsc_buffer_t *enc_msg_data = vsc_buffer_new_with_capacity(enc_msg_data_len);

    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg_header);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_encryption(
                                                   recipient_cipher, test_data_recipient_cipher_MESSAGE, enc_msg_data));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg_data));

    size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
    vsc_buffer_t *enc_msg_footer = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);
    vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_HEADER, enc_msg_header);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_DATA, enc_msg_data);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_FOOTER, enc_msg_footer);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&enc_msg_footer);
    vsc_buffer_destroy(&enc_msg_data);
    vsc_buffer_destroy(&enc_msg_header);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);
}

void
test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success(void) {
    //
    //  Prepare random.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);

    //
    //  Prepare recipients / verifiers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    //
    //  Decrypt.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher,
                                                   test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key,
                                                   test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_HEADER,
                                                   test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_FOOTER));

    size_t out_len = vscf_recipient_cipher_decryption_out_len(
            recipient_cipher, test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_DATA.len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);


    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_DATA, out));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, out));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, out);

    //
    //  Verify.
    //
    TEST_ASSERT_TRUE(vscf_recipient_cipher_is_data_signed(recipient_cipher));
    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(recipient_cipher);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

    TEST_ASSERT_EQUAL_DATA(test_data_recipient_cipher_ED25519_RECIPIENT_ID, vscf_signer_info_signer_id(signer_info));
    const bool verified = vscf_recipient_cipher_verify_signer_info(recipient_cipher, signer_info, public_key);
    TEST_ASSERT_TRUE(verified);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&out);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);
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
    RUN_TEST(test__decrypt__chunks_with_ed25519_key_recipient__success);
    RUN_TEST(test__sign_then_encrypt__with_self_signed_ed25519_key_recipient__success);
    RUN_TEST(test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
