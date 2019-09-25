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
    (VSCF_MESSAGE_INFO && VSCF_MESSAGE_INFO_FOOTER && VSCF_MESSAGE_INFO_DER_SERIALIZER && VSCF_ALG_INFO &&             \
            VSCF_SIMPLE_ALG_INFO && VSCF_CIPHER_ALG_INFO && VSCF_HASH_BASED_ALG_INFO && VSCF_SALTED_KDF_ALG_INFO &&    \
            VSCF_PBE_ALG_INFO)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_message_info.h"
#include "vscf_message_info_footer.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_pbe_alg_info.h"

#include "test_data_message_info_der.h"


// --------------------------------------------------------------------------
//  Header
// --------------------------------------------------------------------------
void
test__serialize__cms_with_one_rsa2048_key_recipient__returns_valid_cms(void) {

    vscf_impl_t *key_encryption_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));

    vscf_key_recipient_info_t *key_recipient =
            vscf_key_recipient_info_new_with_data(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.recipient_id,
                    key_encryption_alg_info, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.encrypted_key);

    vscf_impl_t *data_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce));


    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_message_info_add_key_recipient(message_info, &key_recipient);
    vscf_message_info_set_data_encryption_alg_info(message_info, &data_encryption_alg_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(serializer, message_info));
    vscf_message_info_der_serializer_serialize(serializer, message_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_cms_V2_COMPATIBLE_ONE_RSA2048_KEY_RECIPIENT.serialized, out);

    vscf_impl_destroy(&key_encryption_alg_info);
    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_destroy(&message_info);
}

void
test__serialize__cms_with_one_password_recipient__returns_valid_cms(void) {

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA384));

    vscf_impl_t *kdf_hash_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HMAC, &hash_alg_info));

    vscf_impl_t *kdf_alg_info = vscf_salted_kdf_alg_info_impl(vscf_salted_kdf_alg_info_new_with_members(
            vscf_alg_id_PKCS5_PBKDF2, &kdf_hash_alg_info, test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_salt,
            test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_iteration_count));

    vscf_impl_t *key_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_CBC, test_message_info_cms_ONE_PASSWORD_RECIPIENT.key_encryption_alg_nonce));

    vscf_impl_t *pbe_alg_info = vscf_pbe_alg_info_impl(
            vscf_pbe_alg_info_new_with_members(vscf_alg_id_PKCS5_PBES2, &kdf_alg_info, &key_encryption_alg_info));

    vscf_password_recipient_info_t *password_recipient = vscf_password_recipient_info_new_with_members(
            &pbe_alg_info, test_message_info_cms_ONE_PASSWORD_RECIPIENT.encrypted_key);

    vscf_impl_t *data_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, test_message_info_cms_ONE_PASSWORD_RECIPIENT.data_encryption_alg_nonce));

    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_message_info_add_password_recipient(message_info, &password_recipient);
    vscf_message_info_set_data_encryption_alg_info(message_info, &data_encryption_alg_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(serializer, message_info));
    vscf_message_info_der_serializer_serialize(serializer, message_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_cms_V2_COMPATIBLE_ONE_PASSWORD_RECIPIENT.serialized, out);

    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_destroy(&message_info);
}

void
test__serialize__cms_with_custom_params__returns_cms_with_no_recipients_and_3_params(void) {

    vscf_message_info_custom_params_t *custom_params = vscf_message_info_custom_params_new();
    vscf_message_info_custom_params_add_string(custom_params, test_message_info_cms_STRING_CUSTOM_PARAM_KEY,
            test_message_info_cms_STRING_CUSTOM_PARAM_VALUE);
    vscf_message_info_custom_params_add_data(
            custom_params, test_message_info_cms_DATA_CUSTOM_PARAM_KEY, test_message_info_cms_DATA_CUSTOM_PARAM_VALUE);
    vscf_message_info_custom_params_add_int(
            custom_params, test_message_info_cms_INT_CUSTOM_PARAM_KEY, test_message_info_cms_INT_CUSTOM_PARAM_VALUE);

    vscf_impl_t *data_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce));

    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_message_info_set_custom_params(message_info, custom_params);
    vscf_message_info_set_data_encryption_alg_info(message_info, &data_encryption_alg_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(serializer, message_info));
    vscf_message_info_der_serializer_serialize(serializer, message_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_cms_V2_COMPATIBLE_NO_RECIPIENTS_AND_3_CUSTOM_PARAMS, out);

    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_destroy(&message_info);
    vscf_message_info_custom_params_destroy(&custom_params);
}

void
test__serialize__cms_with_signed_data_info__returns_valid_cms(void) {

    vscf_footer_info_t *footer_info = vscf_footer_info_new();
    vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info_m(footer_info);

    vscf_footer_info_set_data_size(footer_info, 4096);

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA512));
    vscf_signed_data_info_set_hash_alg_info(signed_data_info, &hash_alg_info);

    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_impl_t *data_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce));
    vscf_message_info_set_data_encryption_alg_info(message_info, &data_encryption_alg_info);
    vscf_message_info_set_footer_info(message_info, footer_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(serializer, message_info));
    vscf_message_info_der_serializer_serialize(serializer, message_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_cms_NO_RECIPIENTS_AND_SIGNED_DATA_INFO, out);

    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_destroy(&message_info);
    vscf_footer_info_destroy(&footer_info);
}

void
test__deserialize__cms_with_one_rsa2048_key_recipient__returns_valid_key_recipient(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.serialized, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    const vscf_key_recipient_info_list_t *recipient_info_list = vscf_message_info_key_recipient_info_list(message_info);
    TEST_ASSERT_NOT_NULL(recipient_info_list);
    TEST_ASSERT_TRUE(vscf_key_recipient_info_list_has_item(recipient_info_list));

    //
    //  Check: ktri KeyTransRecipientInfo.
    //
    const vscf_key_recipient_info_t *key_recipient = vscf_key_recipient_info_list_item(recipient_info_list);

    vsc_data_t recipient_id = vscf_key_recipient_info_recipient_id(key_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.recipient_id, recipient_id);

    const vscf_impl_t *key_encryption_alg_info = vscf_key_recipient_info_key_encryption_algorithm(key_recipient);
    TEST_ASSERT_EQUAL(vscf_alg_id_RSA, vscf_alg_info_alg_id(key_encryption_alg_info));

    vsc_data_t encrypted_key = vscf_key_recipient_info_encrypted_key(key_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.encrypted_key, encrypted_key);

    //
    //  Check: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *data_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_alg_info_alg_id(data_encryption_alg_info));

    const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)data_encryption_alg_info;
    vsc_data_t alg_nonce = vscf_cipher_alg_info_nonce(cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce, alg_nonce);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_one_password_recipient__returns_valid_key_recipient(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_ONE_PASSWORD_RECIPIENT.serialized, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    const vscf_password_recipient_info_list_t *recipient_info_list =
            vscf_message_info_password_recipient_info_list(message_info);
    TEST_ASSERT_NOT_NULL(recipient_info_list);
    TEST_ASSERT_TRUE(vscf_password_recipient_info_list_has_item(recipient_info_list));

    //
    //  Check: pwri [3] PasswordRecipientInfo.
    //
    const vscf_password_recipient_info_t *password_recipient =
            vscf_password_recipient_info_list_item(recipient_info_list);

    //  Check: PBES2.
    const vscf_impl_t *key_encryption_alg_info =
            vscf_password_recipient_info_key_encryption_algorithm(password_recipient);
    TEST_ASSERT_EQUAL(vscf_alg_id_PKCS5_PBES2, vscf_alg_info_alg_id(key_encryption_alg_info));

    const vscf_pbe_alg_info_t *pbe_alg_info = (const vscf_pbe_alg_info_t *)key_encryption_alg_info;

    const vscf_impl_t *pbe_cipher_alg_info = vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_CBC, vscf_alg_info_alg_id(pbe_cipher_alg_info));
    const vscf_cipher_alg_info_t *pbe_underlying_cipher_alg_info = (const vscf_cipher_alg_info_t *)pbe_cipher_alg_info;

    vsc_data_t key_encryption_alg_nonce = vscf_cipher_alg_info_nonce(pbe_underlying_cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(
            test_message_info_cms_ONE_PASSWORD_RECIPIENT.key_encryption_alg_nonce, key_encryption_alg_nonce);


    //  Check: PBKDF2.
    const vscf_impl_t *kdf_alg_info = vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_PKCS5_PBKDF2, vscf_alg_info_alg_id(kdf_alg_info));

    const vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = (const vscf_salted_kdf_alg_info_t *)kdf_alg_info;
    vsc_data_t kdf_salt = vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_salt, kdf_salt);

    size_t kdf_iteration_count = vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL(test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_iteration_count, kdf_iteration_count);

    const vscf_impl_t *kdf_hash_alg_info = vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_HMAC, vscf_alg_info_alg_id(kdf_hash_alg_info));
    const vscf_hash_based_alg_info_t *kdf_hmac_alg_info = (const vscf_hash_based_alg_info_t *)kdf_hash_alg_info;
    const vscf_impl_t *hmac_hash_alg_info = vscf_hash_based_alg_info_hash_alg_info(kdf_hmac_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA384, vscf_alg_info_alg_id(hmac_hash_alg_info));

    //  Check: encryptedKey.
    vsc_data_t encrypted_key = vscf_password_recipient_info_encrypted_key(password_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.encrypted_key, encrypted_key);

    //
    //  Check: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *data_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_alg_info_alg_id(data_encryption_alg_info));

    const vscf_cipher_alg_info_t *data_encryption_cipher_alg_info =
            (const vscf_cipher_alg_info_t *)data_encryption_alg_info;
    vsc_data_t alg_nonce = vscf_cipher_alg_info_nonce(data_encryption_cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.data_encryption_alg_nonce, alg_nonce);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_v2_compatible_one_rsa2048_key_recipient__returns_valid_key_recipient(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_V2_COMPATIBLE_ONE_RSA2048_KEY_RECIPIENT.serialized, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    const vscf_key_recipient_info_list_t *recipient_info_list = vscf_message_info_key_recipient_info_list(message_info);
    TEST_ASSERT_NOT_NULL(recipient_info_list);
    TEST_ASSERT_TRUE(vscf_key_recipient_info_list_has_item(recipient_info_list));

    //
    //  Check: ktri KeyTransRecipientInfo.
    //
    const vscf_key_recipient_info_t *key_recipient = vscf_key_recipient_info_list_item(recipient_info_list);

    vsc_data_t recipient_id = vscf_key_recipient_info_recipient_id(key_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_V2_COMPATIBLE_ONE_RSA2048_KEY_RECIPIENT.recipient_id, recipient_id);

    const vscf_impl_t *key_encryption_alg_info = vscf_key_recipient_info_key_encryption_algorithm(key_recipient);
    TEST_ASSERT_EQUAL(vscf_alg_id_RSA, vscf_alg_info_alg_id(key_encryption_alg_info));

    vsc_data_t encrypted_key = vscf_key_recipient_info_encrypted_key(key_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_V2_COMPATIBLE_ONE_RSA2048_KEY_RECIPIENT.encrypted_key, encrypted_key);

    //
    //  Check: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *data_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_alg_info_alg_id(data_encryption_alg_info));

    const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)data_encryption_alg_info;
    vsc_data_t alg_nonce = vscf_cipher_alg_info_nonce(cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(
            test_message_info_cms_V2_COMPATIBLE_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce, alg_nonce);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_v2_compatible_one_password_recipient__returns_password_recipient(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_V2_COMPATIBLE_ONE_PASSWORD_RECIPIENT.serialized, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    const vscf_password_recipient_info_list_t *recipient_info_list =
            vscf_message_info_password_recipient_info_list(message_info);
    TEST_ASSERT_NOT_NULL(recipient_info_list);
    TEST_ASSERT_TRUE(vscf_password_recipient_info_list_has_item(recipient_info_list));

    //
    //  Check: pwri [3] PasswordRecipientInfo.
    //
    const vscf_password_recipient_info_t *password_recipient =
            vscf_password_recipient_info_list_item(recipient_info_list);

    //  Check: PBES2.
    const vscf_impl_t *key_encryption_alg_info =
            vscf_password_recipient_info_key_encryption_algorithm(password_recipient);
    TEST_ASSERT_EQUAL(vscf_alg_id_PKCS5_PBES2, vscf_alg_info_alg_id(key_encryption_alg_info));

    const vscf_pbe_alg_info_t *pbe_alg_info = (const vscf_pbe_alg_info_t *)key_encryption_alg_info;

    const vscf_impl_t *pbe_cipher_alg_info = vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_CBC, vscf_alg_info_alg_id(pbe_cipher_alg_info));
    const vscf_cipher_alg_info_t *pbe_underlying_cipher_alg_info = (const vscf_cipher_alg_info_t *)pbe_cipher_alg_info;

    vsc_data_t key_encryption_alg_nonce = vscf_cipher_alg_info_nonce(pbe_underlying_cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(
            test_message_info_cms_ONE_PASSWORD_RECIPIENT.key_encryption_alg_nonce, key_encryption_alg_nonce);


    //  Check: PBKDF2.
    const vscf_impl_t *kdf_alg_info = vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_PKCS5_PBKDF2, vscf_alg_info_alg_id(kdf_alg_info));

    const vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = (const vscf_salted_kdf_alg_info_t *)kdf_alg_info;
    vsc_data_t kdf_salt = vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_salt, kdf_salt);

    size_t kdf_iteration_count = vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL(test_message_info_cms_ONE_PASSWORD_RECIPIENT.kdf_iteration_count, kdf_iteration_count);

    const vscf_impl_t *kdf_hash_alg_info = vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_HMAC, vscf_alg_info_alg_id(kdf_hash_alg_info));
    const vscf_hash_based_alg_info_t *kdf_hmac_alg_info = (const vscf_hash_based_alg_info_t *)kdf_hash_alg_info;
    const vscf_impl_t *hmac_hash_alg_info = vscf_hash_based_alg_info_hash_alg_info(kdf_hmac_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA384, vscf_alg_info_alg_id(hmac_hash_alg_info));

    //  Check: encryptedKey.
    vsc_data_t encrypted_key = vscf_password_recipient_info_encrypted_key(password_recipient);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.encrypted_key, encrypted_key);

    //
    //  Check: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *data_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_alg_info_alg_id(data_encryption_alg_info));

    const vscf_cipher_alg_info_t *data_encryption_cipher_alg_info =
            (const vscf_cipher_alg_info_t *)data_encryption_alg_info;
    vsc_data_t alg_nonce = vscf_cipher_alg_info_nonce(data_encryption_cipher_alg_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_ONE_PASSWORD_RECIPIENT.data_encryption_alg_nonce, alg_nonce);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_no_recipients_and_3_params__read_int_param_is_valid(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_NO_RECIPIENTS_AND_3_CUSTOM_PARAMS, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    vscf_message_info_custom_params_t *custom_params = vscf_message_info_custom_params(message_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    int value =
            vscf_message_info_custom_params_find_int(custom_params, test_message_info_cms_INT_CUSTOM_PARAM_KEY, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_EQUAL(test_message_info_cms_INT_CUSTOM_PARAM_VALUE, value);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_no_recipients_and_3_params__read_string_param_is_valid(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_NO_RECIPIENTS_AND_3_CUSTOM_PARAMS, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    vscf_message_info_custom_params_t *custom_params = vscf_message_info_custom_params(message_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_data_t value = vscf_message_info_custom_params_find_string(
            custom_params, test_message_info_cms_STRING_CUSTOM_PARAM_KEY, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_STRING_CUSTOM_PARAM_VALUE, value);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_no_recipients_and_3_params__read_data_param_is_valid(void) {

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_NO_RECIPIENTS_AND_3_CUSTOM_PARAMS, NULL);

    TEST_ASSERT_NOT_NULL(message_info);

    vscf_message_info_custom_params_t *custom_params = vscf_message_info_custom_params(message_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_data_t value = vscf_message_info_custom_params_find_data(
            custom_params, test_message_info_cms_DATA_CUSTOM_PARAM_KEY, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_EQUAL_DATA(test_message_info_cms_DATA_CUSTOM_PARAM_VALUE, value);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_footer_info__is_valid_data_size(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_NO_RECIPIENTS_AND_SIGNED_DATA_INFO, NULL);
    TEST_ASSERT_NOT_NULL(message_info);

    TEST_ASSERT_TRUE(vscf_message_info_has_footer_info(message_info));

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(message_info);
    const size_t data_size = vscf_footer_info_data_size(footer_info);
    TEST_ASSERT_EQUAL(4096, data_size);

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize__cms_with_signed_data_info__is_valid_hash_alg_info(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_t *message_info = vscf_message_info_der_serializer_deserialize(
            serializer, test_message_info_cms_NO_RECIPIENTS_AND_SIGNED_DATA_INFO, NULL);
    TEST_ASSERT_NOT_NULL(message_info);

    TEST_ASSERT_TRUE(vscf_message_info_has_footer_info(message_info));

    const vscf_footer_info_t *footer_info = vscf_message_info_footer_info(message_info);
    const vscf_signed_data_info_t *signed_data_info = vscf_footer_info_signed_data_info(footer_info);
    const vscf_impl_t *hash_alg_info = vscf_signed_data_info_hash_alg_info(signed_data_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA512, vscf_alg_info_alg_id(hash_alg_info));

    vscf_message_info_destroy(&message_info);
    vscf_message_info_der_serializer_destroy(&serializer);
}

// --------------------------------------------------------------------------
//  Footer
// --------------------------------------------------------------------------
void
test__serialize_footer__with_ed25519_signer__returns_valid_cms(void) {

    vsc_data_t ed25519_signer_id = test_message_info_SIGNER_INFO_ED25519_SIGNER_ID;
    vsc_buffer_t *ed25519_signature = vsc_buffer_new_with_data(test_message_info_SIGNER_INFO_ED25519_SIGNATURE);
    vscf_impl_t *ed25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_signer_info_t *signer_info =
            vscf_signer_info_new_with_members(ed25519_signer_id, &ed25519_alg_info, &ed25519_signature);

    vscf_message_info_footer_t *footer = vscf_message_info_footer_new();
    vscf_message_info_footer_add_signer_info(footer, &signer_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    size_t out_len = vscf_message_info_der_serializer_serialized_footer_len(serializer, footer);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);
    vscf_message_info_der_serializer_serialize_footer(serializer, footer, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_CMS_FOOTER_WITH_ED25519_SIGNER, out);

    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_footer_destroy(&footer);
}

void
test__serialize_footer__with_ed25519_and_rsa2048_signers__returns_valid_cms(void) {

    //
    //  Ed25519 signer
    //
    vsc_data_t ed25519_signer_id = test_message_info_SIGNER_INFO_ED25519_SIGNER_ID;
    vsc_buffer_t *ed25519_signature = vsc_buffer_new_with_data(test_message_info_SIGNER_INFO_ED25519_SIGNATURE);
    vscf_impl_t *ed25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_signer_info_t *ed25519_signer_info =
            vscf_signer_info_new_with_members(ed25519_signer_id, &ed25519_alg_info, &ed25519_signature);

    //
    //  RSA2048 signer
    //
    vsc_data_t rsa2048_signer_id = test_message_info_SIGNER_INFO_RSA2048_SIGNER_ID;
    vsc_buffer_t *rsa2048_signature = vsc_buffer_new_with_data(test_message_info_SIGNER_INFO_RSA2048_SIGNATURE);
    vscf_impl_t *rsa2048_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));

    vscf_signer_info_t *rsa2048_signer_info =
            vscf_signer_info_new_with_members(rsa2048_signer_id, &rsa2048_alg_info, &rsa2048_signature);

    //
    //  Configure footer
    //
    vscf_message_info_footer_t *footer = vscf_message_info_footer_new();
    vscf_message_info_footer_add_signer_info(footer, &ed25519_signer_info);
    vscf_message_info_footer_add_signer_info(footer, &rsa2048_signer_info);

    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    //
    //  Serialize footer
    //
    size_t out_len = vscf_message_info_der_serializer_serialized_footer_len(serializer, footer);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);
    vscf_message_info_der_serializer_serialize_footer(serializer, footer, out);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, out);

    //
    //  Cleanp
    //
    vsc_buffer_destroy(&out);
    vscf_message_info_der_serializer_destroy(&serializer);
    vscf_message_info_footer_destroy(&footer);
}

void
test__deserialize_footer__with_ed25519_signer__is_valid_signer_id(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_SIGNER, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    vsc_data_t ed25519_signer_id = vscf_signer_info_signer_id(ed25519_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_ED25519_SIGNER_ID, ed25519_signer_id);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_signer__is_valid_signer_alg_info(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_SIGNER, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    const vscf_impl_t *signer_alg_info = vscf_signer_info_signer_alg_info(ed25519_signer_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_info_alg_id(signer_alg_info));

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_signer__is_valid_signature(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_SIGNER, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    vsc_data_t ed25519_signature = vscf_signer_info_signature(ed25519_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_ED25519_SIGNATURE, ed25519_signature);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signer_id(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    vsc_data_t ed25519_signer_id = vscf_signer_info_signer_id(ed25519_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_ED25519_SIGNER_ID, ed25519_signer_id);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signer_alg_info(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    const vscf_impl_t *signer_alg_info = vscf_signer_info_signer_alg_info(ed25519_signer_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_info_alg_id(signer_alg_info));

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signature(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));

    const vscf_signer_info_t *ed25519_signer_info = vscf_signer_info_list_item(signer_infos);

    vsc_data_t ed25519_signature = vscf_signer_info_signature(ed25519_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_ED25519_SIGNATURE, ed25519_signature);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signer_id(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_next(signer_infos));

    const vscf_signer_info_t *rsa2048_signer_info =
            vscf_signer_info_list_item(vscf_signer_info_list_next(signer_infos));

    vsc_data_t rsa2048_signer_id = vscf_signer_info_signer_id(rsa2048_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_RSA2048_SIGNER_ID, rsa2048_signer_id);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signer_alg_info(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_next(signer_infos));

    const vscf_signer_info_t *rsa2048_signer_info =
            vscf_signer_info_list_item(vscf_signer_info_list_next(signer_infos));

    const vscf_impl_t *signer_alg_info = vscf_signer_info_signer_alg_info(rsa2048_signer_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_RSA, vscf_alg_info_alg_id(signer_alg_info));

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

void
test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signature(void) {
    vscf_message_info_der_serializer_t *serializer = vscf_message_info_der_serializer_new();
    vscf_message_info_der_serializer_setup_defaults(serializer);

    vscf_message_info_footer_t *footer = vscf_message_info_der_serializer_deserialize_footer(
            serializer, test_message_info_CMS_FOOTER_WITH_ED25519_AND_RSA2048_SIGNERS, NULL);
    TEST_ASSERT_NOT_NULL(footer);

    const vscf_signer_info_list_t *signer_infos = vscf_message_info_footer_signer_infos(footer);
    TEST_ASSERT_NOT_NULL(signer_infos);
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_item(signer_infos));
    TEST_ASSERT_TRUE(vscf_signer_info_list_has_next(signer_infos));

    const vscf_signer_info_t *rsa2048_signer_info =
            vscf_signer_info_list_item(vscf_signer_info_list_next(signer_infos));

    vsc_data_t rsa2048_signature = vscf_signer_info_signature(rsa2048_signer_info);
    TEST_ASSERT_EQUAL_DATA(test_message_info_SIGNER_INFO_RSA2048_SIGNATURE, rsa2048_signature);

    vscf_message_info_footer_destroy(&footer);
    vscf_message_info_der_serializer_destroy(&serializer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    //
    //  Header
    //
    RUN_TEST(test__serialize__cms_with_one_rsa2048_key_recipient__returns_valid_cms);
    RUN_TEST(test__serialize__cms_with_one_password_recipient__returns_valid_cms);
    RUN_TEST(test__serialize__cms_with_custom_params__returns_cms_with_no_recipients_and_3_params);
    RUN_TEST(test__serialize__cms_with_signed_data_info__returns_valid_cms);

    RUN_TEST(test__deserialize__cms_with_one_rsa2048_key_recipient__returns_valid_key_recipient);
    RUN_TEST(test__deserialize__cms_with_one_password_recipient__returns_valid_key_recipient);

    RUN_TEST(test__deserialize__cms_with_v2_compatible_one_rsa2048_key_recipient__returns_valid_key_recipient);
    RUN_TEST(test__deserialize__cms_with_v2_compatible_one_password_recipient__returns_password_recipient);

    RUN_TEST(test__deserialize__cms_with_no_recipients_and_3_params__read_int_param_is_valid);
    RUN_TEST(test__deserialize__cms_with_no_recipients_and_3_params__read_string_param_is_valid);
    RUN_TEST(test__deserialize__cms_with_no_recipients_and_3_params__read_data_param_is_valid);

    RUN_TEST(test__deserialize__cms_with_footer_info__is_valid_data_size);
    RUN_TEST(test__deserialize__cms_with_signed_data_info__is_valid_hash_alg_info);

    //
    //  Footer
    //
    RUN_TEST(test__serialize_footer__with_ed25519_signer__returns_valid_cms);
    RUN_TEST(test__serialize_footer__with_ed25519_and_rsa2048_signers__returns_valid_cms);

    RUN_TEST(test__deserialize_footer__with_ed25519_signer__is_valid_signer_id);
    RUN_TEST(test__deserialize_footer__with_ed25519_signer__is_valid_signer_alg_info);
    RUN_TEST(test__deserialize_footer__with_ed25519_signer__is_valid_signature);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signer_id);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signer_alg_info);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_ed25519_signature);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signer_id);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signer_alg_info);
    RUN_TEST(test__deserialize_footer__with_ed25519_and_rsa2048_signers__is_valid_rsa2048_signature);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
