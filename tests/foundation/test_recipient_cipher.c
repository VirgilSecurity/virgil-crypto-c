//  Copyright (C) 2015-2026 Virgil Security, Inc.
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
#include "vscf_aes256_kw.h"
#include "vscf_aes128_kw.h"
#include "vscf_message_info.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_kek_recipient_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_memory.h"
#include "vscf_error.h"

#include "vscf_private_key.h"
#include "vscf_chunk_cipher.h"
#include "vscf_ctr_drbg.h"

#include "test_data_recipient_cipher.h"
#include "test_data_compound_key.h"


// --------------------------------------------------------------------------
//  Encrypt / Decrypt
// --------------------------------------------------------------------------
static void
inner_test__encrypt_decrypt__with_one_key_recipient__success(vsc_data_t public_key_data, vsc_data_t private_key_data) {
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


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    vscf_recipient_cipher_add_key_recipient(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

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

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(recipient_cipher,
                                         test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

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
test__encrypt_decrypt__with_ed25519_key_recipient__success(void) {
    inner_test__encrypt_decrypt__with_one_key_recipient__success(
            test_data_recipient_cipher_ED25519_PUBLIC_KEY, test_data_recipient_cipher_ED25519_PRIVATE_KEY);
}

void
test__encrypt_decrypt__with_compound_curve25519_ed25519_key_recipient__success(void) {
    inner_test__encrypt_decrypt__with_one_key_recipient__success(
            test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY_PKCS8_DER,
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY_PKCS8_DER);
}

void
test__encrypt_decrypt__with_pqc_curve25519_ml_kem_768_ed25519_falcon_key_recipient__success(void) {
#if VSCF_POST_QUANTUM && MLKEM_LIBRARY && VSCF_FALCON
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_generate_post_quantum_private_key(key_provider, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vsc_buffer_t *pub_der =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, pub_der));

    vsc_buffer_t *priv_der =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, priv_der));

    inner_test__encrypt_decrypt__with_one_key_recipient__success(vsc_buffer_data(pub_der), vsc_buffer_data(priv_der));

    vsc_buffer_destroy(&pub_der);
    vsc_buffer_destroy(&priv_der);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or MLKEM_LIBRARY and/or VSCF_FALCON are disabled");
#endif
}

// --------------------------------------------------------------------------
//  Standalone decryption.
// --------------------------------------------------------------------------
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

// --------------------------------------------------------------------------
//  Sign then encrypt followed by decrypt then verify.
// --------------------------------------------------------------------------
static void
inner_test__sign_then_encrypt_and_decrypt_then_verify__with_self_signed_key_recipient__success(
        vsc_data_t public_key_data, vsc_data_t private_key_data) {

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

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    vscf_recipient_cipher_add_key_recipient(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_add_signer(recipient_cipher, test_data_recipient_cipher_RECIPIENT_ID, private_key));

    //
    //  Signed encryption.
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

    vscf_status_t enc_status = vscf_recipient_cipher_process_encryption(
            recipient_cipher, test_data_recipient_cipher_MESSAGE, enc_msg_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    enc_status = vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    size_t enc_msg_info_footer_len = vscf_recipient_cipher_message_info_footer_len(recipient_cipher);
    vsc_buffer_t *enc_msg_footer = vsc_buffer_new_with_capacity(enc_msg_info_footer_len);

    enc_status = vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    //
    //  Decrypt.
    //
    vscf_status_t dec_status = vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher,
            test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_buffer_data(enc_msg_header),
            vsc_buffer_data(enc_msg_footer));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    size_t out_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_data(enc_msg_data).len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);


    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);
    dec_status = vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg_data), out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    dec_status = vscf_recipient_cipher_finish_decryption(recipient_cipher, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, out);

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
    //  Cleanup.
    //
    vsc_buffer_destroy(&out);
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
test__sign_then_encrypt_and_decrypt_then_verify__with_ed25519_key_recipient__success(void) {
    inner_test__sign_then_encrypt_and_decrypt_then_verify__with_self_signed_key_recipient__success(
            test_data_recipient_cipher_ED25519_PUBLIC_KEY, test_data_recipient_cipher_ED25519_PRIVATE_KEY);
}

void
test__sign_then_encrypt_and_decrypt_then_verify__with_compound_curve25519_ed25519_key_recipient__success(void) {
    inner_test__sign_then_encrypt_and_decrypt_then_verify__with_self_signed_key_recipient__success(
            test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY_PKCS8_DER,
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY_PKCS8_DER);
}

void
test__sign_then_encrypt_and_decrypt_then_verify__with_pqc_curve25519_ml_kem_768_ed25519_falcon_key_recipient__success(
        void) {
#if VSCF_POST_QUANTUM && MLKEM_LIBRARY && VSCF_FALCON
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_generate_post_quantum_private_key(key_provider, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vsc_buffer_t *pub_der =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, pub_der));

    vsc_buffer_t *priv_der =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, priv_der));

    inner_test__sign_then_encrypt_and_decrypt_then_verify__with_self_signed_key_recipient__success(
            vsc_buffer_data(pub_der), vsc_buffer_data(priv_der));

    vsc_buffer_destroy(&pub_der);
    vsc_buffer_destroy(&priv_der);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or MLKEM_LIBRARY and/or VSCF_FALCON are disabled");
#endif
}

// --------------------------------------------------------------------------
//  Standalone signed encryption / decryption
// --------------------------------------------------------------------------
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
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer));

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
test__sign_then_encrypt__with_self_signed_ed25519_key_recipient_and_padding_cipher__success(void) {
#if VSCF_RANDOM_PADDING
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

    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_use_random(random_padding, random);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);
    vscf_recipient_cipher_take_encryption_padding(recipient_cipher, vscf_random_padding_impl(random_padding));

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
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, enc_msg_footer));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_HEADER, enc_msg_header);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_DATA, enc_msg_data);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_FOOTER, enc_msg_footer);

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
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_RANDOM_PADDING is disabled");
#endif
}

static void
inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success(
        vsc_data_t header, vsc_data_t data, vsc_data_t footer) {
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
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher,
                                         test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, header, footer));

    size_t out_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, data.len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);


    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher, data, out));
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

void
test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success(void) {
    inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_HEADER,
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_DATA,
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_FOOTER);
}

void
test__decrypt_then_verify__with_ed25519_key_recipient_and_padding_cipher_and_detached_header_and_detached_footer__success(
        void) {
#if VSCF_RANDOM_PADDING
    inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_HEADER,
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_DATA,
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING_FOOTER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_RANDOM_PADDING is disabled");
#endif
}

static void
inner_test__decrypt_then_verify__ciphertext__success(vsc_data_t ciphertext, vsc_data_t plaintext,
        vsc_data_t recipient_id, vsc_data_t recipient_private_key, vsc_data_t signer_id,
        vsc_data_t signature_verify_key) {
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

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, signature_verify_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, recipient_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));


    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(recipient_cipher, random);

    //
    //  Decrypt.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(
                                                   recipient_cipher, recipient_id, private_key, vsc_data_empty()));

    size_t out_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, ciphertext.len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    vscf_status_t status = vscf_recipient_cipher_process_decryption(recipient_cipher, ciphertext, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    status = vscf_recipient_cipher_finish_decryption(recipient_cipher, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, out);

    //
    //  Verify.
    //
    TEST_ASSERT_TRUE(vscf_recipient_cipher_is_data_signed(recipient_cipher));
    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(recipient_cipher);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

    TEST_ASSERT_EQUAL_DATA(signer_id, vscf_signer_info_signer_id(signer_info));
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

void
test__decrypt_then_verify__with_ed25519_key_recipient__success(void) {
    inner_test__decrypt_then_verify__ciphertext__success(test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE,
            test_data_recipient_cipher_MESSAGE, test_data_recipient_cipher_ED25519_RECIPIENT_ID,
            test_data_recipient_cipher_ED25519_PRIVATE_KEY, test_data_recipient_cipher_ED25519_RECIPIENT_ID,
            test_data_recipient_cipher_ED25519_PUBLIC_KEY);
}

void
test__decrypt_then_verify__with_set2_ed25519_key_recipient__success(void) {
    inner_test__decrypt_then_verify__ciphertext__success(test_data_recipient_cipher_SET2_SIGNED_THEN_ENCRYPTED_MESSAGE,
            test_data_recipient_cipher_SET2_MESSAGE, test_data_recipient_cipher_SET2_ED25519_RECIPIENT_ID,
            test_data_recipient_cipher_SET2_ED25519_PRIVATE_KEY, test_data_recipient_cipher_SET2_ED25519_RECIPIENT_ID,
            test_data_recipient_cipher_SET2_ED25519_PUBLIC_KEY);
}

static void
inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_embedded_header_and_embedded_footer_by_chunks__success(
        vsc_data_t data) {
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
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(
                    recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    const size_t enc_data_len = data.len;

    size_t out_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, enc_data_len);
    out_len += vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);


    size_t processed_len = 0;
    while (processed_len < enc_data_len) {
        const size_t data_left = enc_data_len - processed_len;
        const size_t chunk_size = data_left < 16 ? data_left : 16;
        vsc_data_t chunk = vsc_data_slice_beg(data, processed_len, chunk_size);
        vscf_status_t status = vscf_recipient_cipher_process_decryption(recipient_cipher, chunk, out);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
        processed_len += chunk_size;
    }

    vscf_status_t status = vscf_recipient_cipher_finish_decryption(recipient_cipher, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
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

void
test__decrypt_then_verify__with_ed25519_key_recipient_and_embedded_header_and_embedded_footer_by_chunks__success(void) {
    inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_embedded_header_and_embedded_footer_by_chunks__success(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE);
}

void
test__decrypt_then_verify__with_ed25519_key_recipient_and_padding_cipher_and_embedded_header_and_embedded_footer_by_chunks__success(
        void) {
#if VSCF_RANDOM_PADDING
    inner_test__decrypt_then_verify__with_ed25519_key_recipient_and_embedded_header_and_embedded_footer_by_chunks__success(
            test_data_recipient_cipher_SIGNED_THEN_ENCRYPTED_MESSAGE_WITH_PADDING);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_RANDOM_PADDING is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Check if key recipient has been added.
// --------------------------------------------------------------------------
void
test__has_key_recipient__with_no_recipients__return_false(void) {
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    const bool was_added =
            vscf_recipient_cipher_has_key_recipient(recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID);
    TEST_ASSERT_FALSE(was_added);

    vscf_recipient_cipher_destroy(&recipient_cipher);
}

void
test__has_key_recipient__with_added_ed25519_recipient_and_correct_id__return_true(void) {

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

    //
    //  Configure cipher.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    //
    //  Check.
    //
    const bool was_added =
            vscf_recipient_cipher_has_key_recipient(recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID);
    TEST_ASSERT_TRUE(was_added);

    //
    //  Cleanup.
    //
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__has_key_recipient__with_added_ed25519_recipient_and_incorrect_id__return_false(void) {

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

    //
    //  Configure cipher.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    //
    //  Check.
    //
    const char invalid_recipient_id[] = "incorrect-recipient-id";
    const bool was_added = vscf_recipient_cipher_has_key_recipient(
            recipient_cipher, vsc_data_from_str(invalid_recipient_id, sizeof(invalid_recipient_id) - 1));
    TEST_ASSERT_FALSE(was_added);

    //
    //  Cleanup.
    //
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__has_key_recipient__with_added_ed25519_recipient_with_empty_and_empty_id__return_true(void) {

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

    //
    //  Configure cipher.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(recipient_cipher, vsc_data_empty(), public_key);

    //
    //  Check.
    //
    const bool was_added = vscf_recipient_cipher_has_key_recipient(recipient_cipher, vsc_data_empty());
    TEST_ASSERT_TRUE(was_added);

    //
    //  Cleanup.
    //
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__has_key_recipient__with_added_ed25519_recipient_with_empty_and_non_empty_id__return_false(void) {

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

    //
    //  Configure cipher.
    //
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(recipient_cipher, vsc_data_empty(), public_key);

    //
    //  Check.
    //
    const bool was_added =
            vscf_recipient_cipher_has_key_recipient(recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID);
    TEST_ASSERT_FALSE(was_added);

    //
    //  Cleanup.
    //
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
//  Check with padding cipher.
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__with_padding_and_ed25519_key_recipient__success(void) {
#if VSCF_RANDOM_PADDING
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

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_take_random(random_padding, vscf_fake_random_impl(fake_random));

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(
            recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, public_key);

    vscf_recipient_cipher_take_encryption_padding(recipient_cipher, vscf_random_padding_impl(random_padding));

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
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_RANDOM_PADDING is disabled");
#endif
}

void
test__decrypt__with_padding_and_ed25519_key_recipient__success(void) {
#if VSCF_RANDOM_PADDING
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

    vsc_buffer_t *dec_msg =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher,
                                                 test_data_recipient_cipher_ENCRYPTED_MESSAGE_WITH_PADDING.len) +
                                         vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(
                    recipient_cipher, test_data_recipient_cipher_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   test_data_recipient_cipher_ENCRYPTED_MESSAGE_WITH_PADDING, dec_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, dec_msg);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_RANDOM_PADDING is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Corner cases / Bug fixes
// --------------------------------------------------------------------------
void
test__decrypt__set2_with_ed25519_key_recipient__success(void) {

    //
    //  Prepare recipients.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, test_data_recipient_cipher_SET3_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    //
    //  Decrypt.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_key(recipient_cipher,
                    test_data_recipient_cipher_SET3_ED25519_RECIPIENT_ID, private_key, vsc_data_empty()));

    const size_t dec_part1_len = vscf_recipient_cipher_decryption_out_len(
            recipient_cipher, test_data_recipient_cipher_SET3_ENCRYPTED_MESSAGE_PART1.len);

    vsc_buffer_t *dec_msg1 = vsc_buffer_new_with_capacity(dec_part1_len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   test_data_recipient_cipher_SET3_ENCRYPTED_MESSAGE_PART1, dec_msg1));

    const size_t dec_part2_len = vscf_recipient_cipher_decryption_out_len(
            recipient_cipher, test_data_recipient_cipher_SET3_ENCRYPTED_MESSAGE_PART2.len);

    vsc_buffer_t *dec_msg2 = vsc_buffer_new_with_capacity(dec_part2_len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(recipient_cipher,
                                                   test_data_recipient_cipher_SET3_ENCRYPTED_MESSAGE_PART2, dec_msg2));

    const size_t dec_finish_len = vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0);

    vsc_buffer_t *dec_msg3 = vsc_buffer_new_with_capacity(dec_finish_len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg3));

    vsc_buffer_t *dec_msg = vsc_buffer_new();
    vsc_buffer_append_data(dec_msg, vsc_buffer_data(dec_msg1));
    vsc_buffer_append_data(dec_msg, vsc_buffer_data(dec_msg2));
    vsc_buffer_append_data(dec_msg, vsc_buffer_data(dec_msg3));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_SET3_MESSAGE, dec_msg);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&dec_msg);
    vsc_buffer_destroy(&dec_msg1);
    vsc_buffer_destroy(&dec_msg2);
    vsc_buffer_destroy(&dec_msg3);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
//  EFAIL / staging-buffer mitigation tests
// --------------------------------------------------------------------------
void
test__decrypt__tampered_ciphertext__auth_fails_and_output_is_empty(void) {
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

    vscf_recipient_cipher_t *enc_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(enc_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(enc_cipher));

    const size_t msg_info_len = vscf_recipient_cipher_message_info_len(enc_cipher);
    const size_t enc_len =
            vscf_recipient_cipher_encryption_out_len(enc_cipher, test_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(enc_cipher, 0);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(msg_info_len + enc_len);
    vscf_recipient_cipher_pack_message_info(enc_cipher, enc_msg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_encryption(enc_cipher, test_data_recipient_cipher_MESSAGE, enc_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(enc_cipher, enc_msg));
    vscf_recipient_cipher_destroy(&enc_cipher);

    //
    //  Tamper: flip the last byte of the encrypted message (always within the GCM auth tag).
    //
    TEST_ASSERT(vsc_buffer_len(enc_msg) > 0);
    vsc_buffer_begin(enc_msg)[vsc_buffer_len(enc_msg) - 1] ^= 0xFF;

    //
    //  Attempt decryption — must fail with AUTH_FAILED; output must be empty.
    //
    vscf_recipient_cipher_t *dec_cipher = vscf_recipient_cipher_new();

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(dec_cipher,
                                         test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

    const size_t out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, vsc_buffer_len(enc_msg)) +
                           vscf_recipient_cipher_decryption_out_len(dec_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(dec_cipher, vsc_buffer_data(enc_msg), out));

    //
    //  process_decryption must write NOTHING to caller's buffer (staging holds it).
    //
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out));

    const vscf_status_t status = vscf_recipient_cipher_finish_decryption(dec_cipher, out);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_AUTH_FAILED, status);

    //
    //  After auth failure, caller's buffer must still be empty — no plaintext exposed.
    //
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out));

    vsc_buffer_destroy(&out);
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&dec_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__decrypt_chunks__tampered_ciphertext__auth_fails_and_all_chunk_buffers_are_empty(void) {
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

    vscf_recipient_cipher_t *enc_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(enc_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(enc_cipher));

    const size_t msg_info_len = vscf_recipient_cipher_message_info_len(enc_cipher);
    const size_t enc_len =
            vscf_recipient_cipher_encryption_out_len(enc_cipher, test_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(enc_cipher, 0);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(msg_info_len + enc_len);
    vscf_recipient_cipher_pack_message_info(enc_cipher, enc_msg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_encryption(enc_cipher, test_data_recipient_cipher_MESSAGE, enc_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(enc_cipher, enc_msg));
    vscf_recipient_cipher_destroy(&enc_cipher);

    //
    //  Tamper: flip the last byte of the encrypted message (always within the GCM auth tag).
    //
    TEST_ASSERT(vsc_buffer_len(enc_msg) > 0);
    vsc_buffer_begin(enc_msg)[vsc_buffer_len(enc_msg) - 1] ^= 0xFF;

    //
    //  Feed tampered ciphertext in two chunks; verify buffers are empty throughout.
    //
    vscf_recipient_cipher_t *dec_cipher = vscf_recipient_cipher_new();

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_start_decryption_with_key(dec_cipher,
                                         test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty()));

    const vsc_data_t full = vsc_buffer_data(enc_msg);
    const size_t half = full.len / 2;

    const size_t chunk1_out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, half);
    vsc_buffer_t *out1 = vsc_buffer_new_with_capacity(chunk1_out_len);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(dec_cipher, vsc_data_slice_beg(full, 0, half), out1));
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out1));

    const size_t chunk2_out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, full.len - half);
    vsc_buffer_t *out2 = vsc_buffer_new_with_capacity(chunk2_out_len);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(
                                                   dec_cipher, vsc_data_slice_beg(full, half, full.len - half), out2));
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out2));

    //
    //  finish_decryption must return AUTH_FAILED and write nothing to finish buffer.
    //
    const size_t finish_out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, 0);
    vsc_buffer_t *out3 = vsc_buffer_new_with_capacity(finish_out_len);
    const vscf_status_t status = vscf_recipient_cipher_finish_decryption(dec_cipher, out3);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_AUTH_FAILED, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out3));

    vsc_buffer_destroy(&out1);
    vsc_buffer_destroy(&out2);
    vsc_buffer_destroy(&out3);
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&dec_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  KEK (pre-shared symmetric key) encrypt / decrypt
// --------------------------------------------------------------------------
static void
test__encrypt_decrypt__with_aes256_kw_kek_recipient__success(void) {
    static const byte kek_id_bytes[] = {0x6b, 0x65, 0x6b, 0x2d, 0x69, 0x64};
    static const byte kek_bytes[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f};
    vsc_data_t kek_id = vsc_data(kek_id_bytes, sizeof(kek_id_bytes));
    vsc_data_t kek = vsc_data(kek_bytes, sizeof(kek_bytes));

    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vscf_impl_t *kw_impl = vscf_aes256_kw_impl(kw);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_kek_recipient(recipient_cipher, kek_id, kek, kw_impl);

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
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, kek_id, kek, kw_impl, vsc_data_empty()));

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
    vscf_impl_destroy(&kw_impl);
}

static void
test__encrypt_decrypt__with_aes256_kw_kek_recipient__wrong_kek_id__not_found(void) {
    static const byte kek_id_bytes[] = {0x6b, 0x65, 0x6b, 0x2d, 0x69, 0x64};
    static const byte wrong_kek_id_bytes[] = {0x77, 0x72, 0x6f, 0x6e, 0x67};
    static const byte kek_bytes[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f};
    vsc_data_t kek_id = vsc_data(kek_id_bytes, sizeof(kek_id_bytes));
    vsc_data_t wrong_kek_id = vsc_data(wrong_kek_id_bytes, sizeof(wrong_kek_id_bytes));
    vsc_data_t kek = vsc_data(kek_bytes, sizeof(kek_bytes));

    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vscf_impl_t *kw_impl = vscf_aes256_kw_impl(kw);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_kek_recipient(recipient_cipher, kek_id, kek, kw_impl);

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

    vscf_recipient_cipher_release_random(recipient_cipher);
    vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

    vsc_data_t enc_data = vsc_buffer_data(enc_msg);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND,
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, wrong_kek_id, kek, kw_impl, enc_data));

    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
}

static void
test__encrypt_decrypt__with_aes128_kw_kek_recipient__success(void) {
    static const byte kek_id_bytes[] = {0x6b, 0x65, 0x6b, 0x2d, 0x31, 0x32, 0x38};
    static const byte kek_bytes[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    vsc_data_t kek_id = vsc_data(kek_id_bytes, sizeof(kek_id_bytes));
    vsc_data_t kek = vsc_data(kek_bytes, sizeof(kek_bytes));

    vscf_aes128_kw_t *kw = vscf_aes128_kw_new();
    vscf_impl_t *kw_impl = vscf_aes128_kw_impl(kw);

    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_kek_recipient(recipient_cipher, kek_id, kek, kw_impl);

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

    vscf_recipient_cipher_release_random(recipient_cipher);
    vscf_recipient_cipher_release_encryption_cipher(recipient_cipher);

    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, vsc_buffer_len(enc_msg)) +
            vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, kek_id, kek, kw_impl, vsc_data_empty()));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_decryption(recipient_cipher, vsc_buffer_data(enc_msg), dec_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(recipient_cipher, dec_msg));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, dec_msg);

    vsc_buffer_destroy(&dec_msg);
    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
}

//  Build a real encrypted message with one aes256-kw KEK recipient; return the full ciphertext.
static vsc_buffer_t *
encrypt_with_aes256_kw_kek(vsc_data_t kek_id, vsc_data_t kek) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vscf_impl_t *kw_impl = vscf_aes256_kw_impl(kw);
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_kek_recipient(recipient_cipher, kek_id, kek, kw_impl);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(recipient_cipher));
    size_t enc_msg_len =
            vscf_recipient_cipher_message_info_len(recipient_cipher) +
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, test_data_recipient_cipher_MESSAGE.len) +
            vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0);
    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(enc_msg_len);
    vscf_recipient_cipher_pack_message_info(recipient_cipher, enc_msg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_process_encryption(recipient_cipher, test_data_recipient_cipher_MESSAGE, enc_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(recipient_cipher, enc_msg));

    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
    return enc_msg;
}

//  Correct kek_id but wrong KEK bytes: the wrapped key fails its integrity check.
static void
test__decrypt__with_aes256_kw_kek_recipient__wrong_kek__auth_fails(void) {
    static const byte kek_id_bytes[] = {0x6b, 0x65, 0x6b, 0x2d, 0x69, 0x64};
    static const byte kek_bytes[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f};
    static const byte wrong_kek_bytes[32] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
            0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2,
            0xe1, 0xe0};
    vsc_data_t kek_id = vsc_data(kek_id_bytes, sizeof(kek_id_bytes));

    vsc_buffer_t *enc_msg = encrypt_with_aes256_kw_kek(kek_id, vsc_data(kek_bytes, sizeof(kek_bytes)));

    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vscf_impl_t *kw_impl = vscf_aes256_kw_impl(kw);
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    TEST_ASSERT_EQUAL(vscf_status_ERROR_KEY_RECIPIENT_KEK_IS_WRONG,
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, kek_id,
                    vsc_data(wrong_kek_bytes, sizeof(wrong_kek_bytes)), kw_impl, vsc_buffer_data(enc_msg)));

    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
}

//  Message wrapped with aes256-kw, decryption attempted with an aes128-kw wrap object:
//  the algorithm mismatch must be rejected, not routed into the wrong primitive.
static void
test__decrypt__kek_algorithm_mismatch__fails(void) {
    static const byte kek_id_bytes[] = {0x6b, 0x65, 0x6b, 0x2d, 0x69, 0x64};
    static const byte kek256_bytes[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f};
    static const byte kek128_bytes[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    vsc_data_t kek_id = vsc_data(kek_id_bytes, sizeof(kek_id_bytes));

    vsc_buffer_t *enc_msg = encrypt_with_aes256_kw_kek(kek_id, vsc_data(kek256_bytes, sizeof(kek256_bytes)));

    vscf_aes128_kw_t *kw = vscf_aes128_kw_new();
    vscf_impl_t *kw_impl = vscf_aes128_kw_impl(kw);
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ENCRYPTED_DATA,
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, kek_id,
                    vsc_data(kek128_bytes, sizeof(kek128_bytes)), kw_impl, vsc_buffer_data(enc_msg)));

    vsc_buffer_destroy(&enc_msg);
    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
}

// --------------------------------------------------------------------------
//  Malformed-message-info regression tests (assert-on-untrusted-input fixes)
//
//  These exercise the trust boundary: an attacker-supplied CMS message info
//  with a malformed KEKRecipientInfo must produce a graceful error, never an
//  abort() from a programmatic assert in the deserializer or the AES Key Wrap
//  primitive.
// --------------------------------------------------------------------------

//  Decode a DER length field at `off`. Returns the length value and writes the
//  number of length octets to `*octets`.
static size_t
der_decode_len(vsc_data_t der, size_t off, size_t *octets) {
    const byte b = der.bytes[off];
    if (b < 0x80) {
        *octets = 1;
        return b;
    }
    const size_t n = (size_t)(b & 0x7f);
    size_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        value = (value << 8) | der.bytes[off + 1 + i];
    }
    *octets = 1 + n;
    return value;
}

//  Total size (tag + length + value) of the TLV starting at `off`.
static size_t
der_tlv_total(vsc_data_t der, size_t off) {
    size_t octets = 0;
    const size_t len = der_decode_len(der, off + 1, &octets);
    return 1 + octets + len;
}

//  Decrement a DER length field in place by `delta`, preserving its octet count.
static void
der_dec_len_field(byte *buf, size_t lenfield_off, size_t octets, size_t delta) {
    if (octets == 1) {
        buf[lenfield_off] = (byte)(buf[lenfield_off] - delta);
        return;
    }
    const size_t n = octets - 1;
    size_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        value = (value << 8) | buf[lenfield_off + 1 + i];
    }
    value -= delta;
    for (size_t i = 0; i < n; ++i) {
        buf[lenfield_off + 1 + (n - 1 - i)] = (byte)(value & 0xff);
        value >>= 8;
    }
}

//  Build a CMS message info with a single KEKRecipientInfo (AES-256-KW) and an
//  AES-256-GCM content encryption alg. `encrypted_key` and `kek_id` use caller
//  patterns so they can be located in the serialized bytes for patching.
static vsc_buffer_t *
build_kek_message_info(vsc_data_t kek_id, vsc_data_t encrypted_key, vsc_data_t nonce) {
    vscf_impl_t *kek_alg = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_AES256_KW));
    vscf_kek_recipient_info_t *kekri = vscf_kek_recipient_info_new_with_members(kek_id, &kek_alg, encrypted_key);
    vscf_impl_t *data_alg =
            vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(vscf_alg_id_AES256_GCM, nonce));

    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_message_info_add_kek_recipient(message_info, &kekri);
    vscf_message_info_set_data_encryption_alg_info(message_info, &data_alg);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(serializer, message_info));
    vscf_message_info_der_serializer_serialize(serializer, message_info, out);

    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_destroy(&message_info);
    return out;
}

//  Locate the encryptedKey OCTET STRING (a 1-octet-length string holding `pattern`)
//  in `der` and shrink its value to `new_len` bytes, fixing every enclosing TLV
//  length field. Returns the patched message info bytes.
static vsc_buffer_t *
shrink_encrypted_key(vsc_data_t der, vsc_data_t pattern, size_t new_len) {
    //  Find the value; the OCTET STRING tag/len sit two bytes before it (value <= 127).
    size_t val_off = SIZE_MAX;
    for (size_t i = 0; i + pattern.len <= der.len; ++i) {
        if (memcmp(der.bytes + i, pattern.bytes, pattern.len) == 0) {
            val_off = i;
            break;
        }
    }
    TEST_ASSERT_NOT_EQUAL(SIZE_MAX, val_off);
    const size_t tgt = val_off - 2; // OCTET STRING tag offset
    TEST_ASSERT_EQUAL_HEX8(0x04, der.bytes[tgt]);
    TEST_ASSERT_EQUAL(pattern.len, der.bytes[tgt + 1]);

    const size_t delta = pattern.len - new_len;

    byte *buf = (byte *)vscf_alloc(der.len);
    memcpy(buf, der.bytes, der.len);

    //  Walk root -> target, decrementing each enclosing container's length field.
    size_t pos = 0;
    while (pos != tgt) {
        size_t octets = 0;
        const size_t len = der_decode_len(der, pos + 1, &octets);
        const size_t content = pos + 1 + octets;
        const size_t content_end = content + len;
        TEST_ASSERT_TRUE(content <= tgt && tgt < content_end);
        der_dec_len_field(buf, pos + 1, octets, delta);

        size_t child = content;
        while (!(child <= tgt && tgt < child + der_tlv_total(der, child))) {
            child += der_tlv_total(der, child);
            TEST_ASSERT_TRUE(child < content_end);
        }
        pos = child;
    }
    //  Set the encryptedKey's own length (1 octet, new_len <= 127).
    buf[tgt + 1] = (byte)new_len;

    //  Emit bytes with the (delta) tail bytes of the value removed.
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(der.len - delta);
    vsc_buffer_write_data(out, vsc_data(buf, val_off + new_len));
    vsc_buffer_write_data(out, vsc_data(buf + val_off + pattern.len, der.len - (val_off + pattern.len)));
    vscf_dealloc(buf);
    return out;
}

//  Attempt KEK decryption of crafted message info; returns the status without aborting.
static vscf_status_t
try_decrypt_with_kek(vsc_data_t message_info, vsc_data_t kek_id, vsc_data_t kek) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vscf_impl_t *kw_impl = vscf_aes256_kw_impl(kw);
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();

    const vscf_status_t status =
            vscf_recipient_cipher_start_decryption_with_kek(recipient_cipher, kek_id, kek, kw_impl, message_info);

    vscf_recipient_cipher_destroy(&recipient_cipher);
    vscf_impl_destroy(&kw_impl);
    return status;
}

static const byte k_regr_kek_id[] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5};
static const byte k_regr_kek[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//  A valid wrapped-key length is >= 24 and a multiple of 8; 40 bytes is the real size for a 32-byte CEK.
static const byte k_regr_enc_key[40] = {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC,
        0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
static const byte k_regr_nonce[12] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB};

//  Sanity: the crafted (well-formed) message info round-trips through the deserializer.
static void
test__kek__crafted_message_info__deserializes(void) {
    vsc_data_t kek_id = vsc_data(k_regr_kek_id, sizeof(k_regr_kek_id));
    vsc_buffer_t *mi = build_kek_message_info(
            kek_id, vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), vsc_data(k_regr_nonce, sizeof(k_regr_nonce)));

    vscf_error_t error;
    vscf_error_reset(&error);
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);
    vscf_message_info_t *parsed = vscf_message_info_der_serializer_deserialize(serializer, vsc_buffer_data(mi), &error);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(parsed);
    const vscf_kek_recipient_info_list_t *list = vscf_message_info_kek_recipient_info_list(parsed);
    TEST_ASSERT_TRUE(vscf_kek_recipient_info_list_has_item(list));

    vscf_message_info_destroy(&parsed);
    vscf_message_info_der_serializer_destroy(&serializer);
    vsc_buffer_destroy(&mi);
}

//  A message info followed by trailing bytes (e.g. the ciphertext stream) must deserialize using
//  only the VirgilMessageInfo SEQUENCE; a trailing 0xA2 must NOT be misread as the optional
//  footerInfo [2] field. Regression for the intermittent BAD_MESSAGE_INFO when decrypting a
//  freshly encrypted KEK message whose ciphertext happened to start with 0xA0..0xA3.
static void
test__deserialize__message_info_with_trailing_bytes__ignores_trailing(void) {
    vsc_data_t kek_id = vsc_data(k_regr_kek_id, sizeof(k_regr_kek_id));
    vsc_buffer_t *mi = build_kek_message_info(
            kek_id, vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), vsc_data(k_regr_nonce, sizeof(k_regr_nonce)));

    //  Append trailing bytes starting with every optional context tag the parser checks for.
    const byte trailing[] = {0xA2, 0x10, 0x38, 0x1b, 0xA0, 0xA1, 0xA3, 0x00, 0xFF};
    vsc_buffer_t *with_tail = vsc_buffer_new_with_capacity(vsc_buffer_len(mi) + sizeof(trailing));
    vsc_buffer_write_data(with_tail, vsc_buffer_data(mi));
    vsc_buffer_write_data(with_tail, vsc_data(trailing, sizeof(trailing)));

    vscf_error_t error;
    vscf_error_reset(&error);
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);
    vscf_message_info_t *parsed =
            vscf_message_info_der_serializer_deserialize(serializer, vsc_buffer_data(with_tail), &error);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(parsed);
    const vscf_kek_recipient_info_list_t *list = vscf_message_info_kek_recipient_info_list(parsed);
    TEST_ASSERT_TRUE(vscf_kek_recipient_info_list_has_item(list));

    vscf_message_info_destroy(&parsed);
    vscf_message_info_der_serializer_destroy(&serializer);
    vsc_buffer_destroy(&with_tail);
    vsc_buffer_destroy(&mi);
}

//  Empty encryptedKey OCTET STRING must be rejected gracefully, not abort the deserializer.
static void
test__kek__empty_encrypted_key__fails_without_abort(void) {
    vsc_data_t kek_id = vsc_data(k_regr_kek_id, sizeof(k_regr_kek_id));
    vsc_buffer_t *mi = build_kek_message_info(
            kek_id, vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), vsc_data(k_regr_nonce, sizeof(k_regr_nonce)));
    vsc_buffer_t *bad = shrink_encrypted_key(vsc_buffer_data(mi), vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), 0);

    const vscf_status_t status =
            try_decrypt_with_kek(vsc_buffer_data(bad), kek_id, vsc_data(k_regr_kek, sizeof(k_regr_kek)));
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_destroy(&bad);
    vsc_buffer_destroy(&mi);
}

//  A short (< 24) wrapped key must be rejected before reaching the AES-KW length assert.
static void
test__kek__short_encrypted_key__fails_without_abort(void) {
    vsc_data_t kek_id = vsc_data(k_regr_kek_id, sizeof(k_regr_kek_id));
    vsc_buffer_t *mi = build_kek_message_info(
            kek_id, vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), vsc_data(k_regr_nonce, sizeof(k_regr_nonce)));
    vsc_buffer_t *bad = shrink_encrypted_key(vsc_buffer_data(mi), vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), 8);

    const vscf_status_t status =
            try_decrypt_with_kek(vsc_buffer_data(bad), kek_id, vsc_data(k_regr_kek, sizeof(k_regr_kek)));
    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ENCRYPTED_DATA, status);

    vsc_buffer_destroy(&bad);
    vsc_buffer_destroy(&mi);
}

//  A non-multiple-of-8 wrapped key (>= 24) must be rejected before the AES-KW block assert.
static void
test__kek__misaligned_encrypted_key__fails_without_abort(void) {
    vsc_data_t kek_id = vsc_data(k_regr_kek_id, sizeof(k_regr_kek_id));
    vsc_buffer_t *mi = build_kek_message_info(
            kek_id, vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), vsc_data(k_regr_nonce, sizeof(k_regr_nonce)));
    vsc_buffer_t *bad = shrink_encrypted_key(vsc_buffer_data(mi), vsc_data(k_regr_enc_key, sizeof(k_regr_enc_key)), 30);

    const vscf_status_t status =
            try_decrypt_with_kek(vsc_buffer_data(bad), kek_id, vsc_data(k_regr_kek, sizeof(k_regr_kek)));
    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ENCRYPTED_DATA, status);

    vsc_buffer_destroy(&bad);
    vsc_buffer_destroy(&mi);
}

// --------------------------------------------------------------------------
//  Chunk cipher envelope: authenticated metadata binding (R8).
//
//  The chunked data cipher binds its serialized CMS 'data encryption alg info'
//  (chunked OID + chunk_size + initial_nonce) into the data AEAD, so an OID
//  swap or a chunk_size/initial_nonce tamper fails closed on both the signed
//  and unsigned envelope paths.
// --------------------------------------------------------------------------

//  The chunked alg_info DER deserializer enforces chunk_size in [256, 64 MiB],
//  so use a valid chunk_size and a plaintext that spans several frames.
#define CHUNK_ENVELOPE_CHUNK_SIZE 256
#define CHUNK_ENVELOPE_PLAINTEXT_LEN 700

static byte chunk_envelope_plaintext_bytes[CHUNK_ENVELOPE_PLAINTEXT_LEN];

static vsc_data_t
chunk_envelope_plaintext(void) {
    for (size_t i = 0; i < CHUNK_ENVELOPE_PLAINTEXT_LEN; ++i) {
        chunk_envelope_plaintext_bytes[i] = (byte)(i * 31u + 7u);
    }
    return vsc_data(chunk_envelope_plaintext_bytes, CHUNK_ENVELOPE_PLAINTEXT_LEN);
}

//  Build a chunk_cipher configured as the encryption cipher (key + chunk_size;
//  the recipient cipher injects a random key and nonce, so no key set here).
static vscf_impl_t *
make_encryption_chunk_cipher(void) {
    vscf_chunk_cipher_t *chunk_cipher = vscf_chunk_cipher_new();

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));
    vscf_chunk_cipher_take_random(chunk_cipher, vscf_ctr_drbg_impl(rng));

    vscf_chunk_cipher_set_chunk_size(chunk_cipher, CHUNK_ENVELOPE_CHUNK_SIZE);

    return vscf_chunk_cipher_impl(chunk_cipher);
}

//  Encrypt MESSAGE into an unsigned envelope using an injected chunk_cipher.
//  Returns the full serialized envelope (message info || framed ciphertext).
static vsc_buffer_t *
chunk_envelope_encrypt_unsigned(vscf_impl_t *public_key) {
    const vsc_data_t plaintext = chunk_envelope_plaintext();

    vscf_recipient_cipher_t *enc_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(enc_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);
    vscf_recipient_cipher_take_encryption_cipher(enc_cipher, make_encryption_chunk_cipher());

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_encryption(enc_cipher));

    const size_t msg_info_len = vscf_recipient_cipher_message_info_len(enc_cipher);
    const size_t enc_len = vscf_recipient_cipher_encryption_out_len(enc_cipher, plaintext.len) +
                           vscf_recipient_cipher_encryption_out_len(enc_cipher, 0);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(msg_info_len + enc_len);
    vscf_recipient_cipher_pack_message_info(enc_cipher, enc_msg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_encryption(enc_cipher, plaintext, enc_msg));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(enc_cipher, enc_msg));

    vscf_recipient_cipher_destroy(&enc_cipher);
    return enc_msg;
}

//  Decrypt an unsigned chunked envelope through a fresh recipient cipher with
//  no chunk knowledge.  Returns the final finish_decryption status; on success
//  the plaintext is written to 'out'.
static vscf_status_t
chunk_envelope_decrypt_unsigned(vsc_data_t envelope, vscf_impl_t *private_key, vsc_buffer_t **out_ref) {
    vscf_recipient_cipher_t *dec_cipher = vscf_recipient_cipher_new();

    const vscf_status_t start_status = vscf_recipient_cipher_start_decryption_with_key(
            dec_cipher, test_data_recipient_cipher_RECIPIENT_ID, private_key, vsc_data_empty());
    if (start_status != vscf_status_SUCCESS) {
        vscf_recipient_cipher_destroy(&dec_cipher);
        return start_status;
    }

    const size_t out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, envelope.len) +
                           vscf_recipient_cipher_decryption_out_len(dec_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    const vscf_status_t proc_status = vscf_recipient_cipher_process_decryption(dec_cipher, envelope, out);
    if (proc_status != vscf_status_SUCCESS) {
        vscf_recipient_cipher_destroy(&dec_cipher);
        *out_ref = out;
        return proc_status;
    }

    const vscf_status_t status = vscf_recipient_cipher_finish_decryption(dec_cipher, out);

    vscf_recipient_cipher_destroy(&dec_cipher);
    *out_ref = out;
    return status;
}

//  Find the chunked OID (1.3.6.1.4.1.54811.1.4) inside the serialized envelope
//  and return the offset of its first byte, or SIZE_MAX if not present.
static size_t
find_chunked_oid_offset(vsc_data_t envelope) {
    static const byte chunked_oid[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x04};
    if (envelope.len < sizeof(chunked_oid)) {
        return SIZE_MAX;
    }
    for (size_t i = 0; i + sizeof(chunked_oid) <= envelope.len; ++i) {
        if (memcmp(envelope.bytes + i, chunked_oid, sizeof(chunked_oid)) == 0) {
            return i;
        }
    }
    return SIZE_MAX;
}

void
test__chunk_cipher_envelope__unsigned_round_trip__success(void) {
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

    vsc_buffer_t *envelope = chunk_envelope_encrypt_unsigned(public_key);

    //  Sanity: the envelope really uses the chunked identifier.
    TEST_ASSERT_NOT_EQUAL(SIZE_MAX, find_chunked_oid_offset(vsc_buffer_data(envelope)));

    vsc_buffer_t *out = NULL;
    const vscf_status_t status = chunk_envelope_decrypt_unsigned(vsc_buffer_data(envelope), private_key, &out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(chunk_envelope_plaintext(), out);

    vsc_buffer_destroy(&out);
    vsc_buffer_destroy(&envelope);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__chunk_cipher_envelope__signed_round_trip__success(void) {
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

    //
    //  Signed encryption with an injected chunk_cipher.
    //
    vscf_recipient_cipher_t *enc_cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_add_key_recipient(enc_cipher, test_data_recipient_cipher_RECIPIENT_ID, public_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_recipient_cipher_add_signer(enc_cipher, test_data_recipient_cipher_RECIPIENT_ID, private_key));
    vscf_recipient_cipher_take_encryption_cipher(enc_cipher, make_encryption_chunk_cipher());

    const vsc_data_t plaintext = chunk_envelope_plaintext();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_signed_encryption(enc_cipher, plaintext.len));

    const size_t msg_info_len = vscf_recipient_cipher_message_info_len(enc_cipher);
    const size_t enc_len = vscf_recipient_cipher_encryption_out_len(enc_cipher, plaintext.len) +
                           vscf_recipient_cipher_encryption_out_len(enc_cipher, 0);

    vsc_buffer_t *enc_header = vsc_buffer_new_with_capacity(msg_info_len);
    vsc_buffer_t *enc_data = vsc_buffer_new_with_capacity(enc_len);

    vscf_recipient_cipher_pack_message_info(enc_cipher, enc_header);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_process_encryption(enc_cipher, plaintext, enc_data));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_encryption(enc_cipher, enc_data));

    const size_t footer_len = vscf_recipient_cipher_message_info_footer_len(enc_cipher);
    vsc_buffer_t *enc_footer = vsc_buffer_new_with_capacity(footer_len);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_pack_message_info_footer(enc_cipher, enc_footer));

    //  Sanity: chunked identifier present in the header.
    TEST_ASSERT_NOT_EQUAL(SIZE_MAX, find_chunked_oid_offset(vsc_buffer_data(enc_header)));

    vscf_recipient_cipher_destroy(&enc_cipher);

    //
    //  Verified decryption through a fresh recipient cipher (no chunk knowledge).
    //
    vscf_recipient_cipher_t *dec_cipher = vscf_recipient_cipher_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_start_verified_decryption_with_key(dec_cipher,
                                                   test_data_recipient_cipher_RECIPIENT_ID, private_key,
                                                   vsc_buffer_data(enc_header), vsc_buffer_data(enc_footer)));

    const size_t out_len = vscf_recipient_cipher_decryption_out_len(dec_cipher, vsc_buffer_len(enc_data)) +
                           vscf_recipient_cipher_decryption_out_len(dec_cipher, 0);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_recipient_cipher_process_decryption(dec_cipher, vsc_buffer_data(enc_data), out));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_recipient_cipher_finish_decryption(dec_cipher, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(chunk_envelope_plaintext(), out);

    TEST_ASSERT_TRUE(vscf_recipient_cipher_is_data_signed(dec_cipher));
    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(dec_cipher);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);
    TEST_ASSERT_TRUE(vscf_recipient_cipher_verify_signer_info(dec_cipher, signer_info, public_key));

    vsc_buffer_destroy(&out);
    vsc_buffer_destroy(&enc_footer);
    vsc_buffer_destroy(&enc_data);
    vsc_buffer_destroy(&enc_header);
    vscf_recipient_cipher_destroy(&dec_cipher);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__chunk_cipher_envelope__oid_downgrade__fails_closed(void) {
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

    vsc_buffer_t *envelope = chunk_envelope_encrypt_unsigned(public_key);

    //
    //  Downgrade: flip the discriminating last byte of the chunked OID
    //  (1.3.6.1.4.1.54811.1.4 -> ...1.3), so the CMS no longer identifies the
    //  chunked algorithm.  Decryption must fail closed: either the cipher can
    //  no longer be reconstructed, or the bound auth-data mismatches.
    //
    const size_t oid_offset = find_chunked_oid_offset(vsc_buffer_data(envelope));
    TEST_ASSERT_NOT_EQUAL(SIZE_MAX, oid_offset);
    vsc_buffer_begin(envelope)[oid_offset + 9] = 0x03;

    vsc_buffer_t *out = NULL;
    const vscf_status_t status = chunk_envelope_decrypt_unsigned(vsc_buffer_data(envelope), private_key, &out);
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, status);
    if (out != NULL) {
        TEST_ASSERT_EQUAL(0, vsc_buffer_len(out));
        vsc_buffer_destroy(&out);
    }

    vsc_buffer_destroy(&envelope);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__chunk_cipher_envelope__param_tamper__auth_fails(void) {
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

    vsc_buffer_t *envelope = chunk_envelope_encrypt_unsigned(public_key);

    //
    //  Param tamper: the alg_info parameters (version INTEGER, chunkSize
    //  INTEGER, initialNonce OCTET STRING) follow the OID.  Flip a byte in the
    //  initial nonce region (well past the OID + short version/chunkSize
    //  encodings) so the OID stays valid and the cipher reconstructs, but the
    //  bound auth-data differs from what the encryptor bound.  The AEAD tag
    //  check must fail and no plaintext must be produced.
    //
    //  DER layout of the AlgorithmIdentifier parameters after the 10-byte OID
    //  content: params SEQUENCE (0x30 len) | version INTEGER (02 01 01) |
    //  chunkSize INTEGER (02 02 01 00 for 256) | initialNonce OCTET STRING
    //  (04 0C <12 bytes>).  So the nonce content begins at oid_offset + 21.
    //  Flip a byte inside the nonce so the OID and chunk_size stay valid (the
    //  cipher reconstructs) but the bound metadata differs -> AEAD auth failure.
    const size_t oid_offset = find_chunked_oid_offset(vsc_buffer_data(envelope));
    TEST_ASSERT_NOT_EQUAL(SIZE_MAX, oid_offset);
    const size_t nonce_content = oid_offset + 21;
    TEST_ASSERT(nonce_content + 12 <= vsc_buffer_len(envelope));
    vsc_buffer_begin(envelope)[nonce_content + 5] ^= 0xFF;

    vsc_buffer_t *out = NULL;
    const vscf_status_t status = chunk_envelope_decrypt_unsigned(vsc_buffer_data(envelope), private_key, &out);
    //  Must fail closed via the AEAD tag check (the bound nonce metadata changed).
    TEST_ASSERT_EQUAL(vscf_status_ERROR_AUTH_FAILED, status);
    if (out != NULL) {
        TEST_ASSERT_EQUAL(0, vsc_buffer_len(out));
        vsc_buffer_destroy(&out);
    }

    vsc_buffer_destroy(&envelope);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt_decrypt__with_ed25519_key_recipient__success);
    RUN_TEST(test__encrypt_decrypt__with_compound_curve25519_ed25519_key_recipient__success);
    RUN_TEST(test__encrypt_decrypt__with_pqc_curve25519_ml_kem_768_ed25519_falcon_key_recipient__success);
    RUN_TEST(test__decrypt__with_ed25519_private_key__success);
    RUN_TEST(test__decrypt__chunks_with_ed25519_key_recipient__success);

    RUN_TEST(test__sign_then_encrypt_and_decrypt_then_verify__with_ed25519_key_recipient__success);
    RUN_TEST(test__sign_then_encrypt_and_decrypt_then_verify__with_compound_curve25519_ed25519_key_recipient__success);
    RUN_TEST(
            test__sign_then_encrypt_and_decrypt_then_verify__with_pqc_curve25519_ml_kem_768_ed25519_falcon_key_recipient__success);

    RUN_TEST(test__sign_then_encrypt__with_self_signed_ed25519_key_recipient__success);
    RUN_TEST(test__sign_then_encrypt__with_self_signed_ed25519_key_recipient_and_padding_cipher__success);
    RUN_TEST(test__decrypt_then_verify__with_ed25519_key_recipient_and_detached_header_and_detached_footer__success);
    RUN_TEST(
            test__decrypt_then_verify__with_ed25519_key_recipient_and_padding_cipher_and_detached_header_and_detached_footer__success);
    RUN_TEST(test__decrypt_then_verify__with_ed25519_key_recipient__success);
    RUN_TEST(test__decrypt_then_verify__with_set2_ed25519_key_recipient__success);
    RUN_TEST(
            test__decrypt_then_verify__with_ed25519_key_recipient_and_embedded_header_and_embedded_footer_by_chunks__success);
    RUN_TEST(
            test__decrypt_then_verify__with_ed25519_key_recipient_and_padding_cipher_and_embedded_header_and_embedded_footer_by_chunks__success);

    RUN_TEST(test__encrypt_decrypt__with_padding_and_ed25519_key_recipient__success);
    RUN_TEST(test__decrypt__with_padding_and_ed25519_key_recipient__success);

    RUN_TEST(test__has_key_recipient__with_no_recipients__return_false);
    RUN_TEST(test__has_key_recipient__with_added_ed25519_recipient_and_correct_id__return_true);
    RUN_TEST(test__has_key_recipient__with_added_ed25519_recipient_and_incorrect_id__return_false);
    RUN_TEST(test__has_key_recipient__with_added_ed25519_recipient_with_empty_and_empty_id__return_true);
    RUN_TEST(test__has_key_recipient__with_added_ed25519_recipient_with_empty_and_non_empty_id__return_false);

    RUN_TEST(test__decrypt__set2_with_ed25519_key_recipient__success);

    RUN_TEST(test__decrypt__tampered_ciphertext__auth_fails_and_output_is_empty);
    RUN_TEST(test__decrypt_chunks__tampered_ciphertext__auth_fails_and_all_chunk_buffers_are_empty);

    RUN_TEST(test__chunk_cipher_envelope__unsigned_round_trip__success);
    RUN_TEST(test__chunk_cipher_envelope__signed_round_trip__success);
    RUN_TEST(test__chunk_cipher_envelope__oid_downgrade__fails_closed);
    RUN_TEST(test__chunk_cipher_envelope__param_tamper__auth_fails);

    RUN_TEST(test__encrypt_decrypt__with_aes256_kw_kek_recipient__success);
    RUN_TEST(test__encrypt_decrypt__with_aes256_kw_kek_recipient__wrong_kek_id__not_found);
    RUN_TEST(test__encrypt_decrypt__with_aes128_kw_kek_recipient__success);
    RUN_TEST(test__decrypt__with_aes256_kw_kek_recipient__wrong_kek__auth_fails);
    RUN_TEST(test__decrypt__kek_algorithm_mismatch__fails);

    RUN_TEST(test__kek__crafted_message_info__deserializes);
    RUN_TEST(test__deserialize__message_info_with_trailing_bytes__ignores_trailing);
    RUN_TEST(test__kek__empty_encrypted_key__fails_without_abort);
    RUN_TEST(test__kek__short_encrypted_key__fails_without_abort);
    RUN_TEST(test__kek__misaligned_encrypted_key__fails_without_abort);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
