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

#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSSQ_MESSENGER_FILE_CIPHER && VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_PROVIDER && VSCF_ED25519)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_key_provider.h"
#include "vscf_fake_random.h"
#include "vssq_messenger_cloud_fs_cipher.h"
#include "test_data_comm_kit.h"

// --------------------------------------------------------------------------
//  Encrypt / Decrypt
// --------------------------------------------------------------------------
static void
test__messenger_cloud_fs_cipher_encrypt__then_decrypt__text_match(void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare recipients.
    //
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *owner_public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_recipient_cipher_ED25519_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *owner_private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_recipient_cipher_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    // Encrypt and sign
    //
    vssq_messenger_cloud_fs_cipher_t *file_cipher = vssq_messenger_cloud_fs_cipher_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_setup_defaults(file_cipher));

    vsc_buffer_t *file_key =
            vsc_buffer_new_with_capacity(vssq_messenger_cloud_fs_cipher_init_encryption_out_key_len(file_cipher));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_init_encryption(file_cipher, owner_private_key,
                                         test_data_recipient_cipher_MESSAGE.len, file_key));

    vsc_buffer_t *header_buf =
            vsc_buffer_new_with_capacity(vssq_messenger_cloud_fs_cipher_start_encryption_out_len(file_cipher));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_start_encryption(file_cipher, header_buf));


    vsc_buffer_t *data_buf = vsc_buffer_new_with_capacity(vssq_messenger_cloud_fs_cipher_process_encryption_out_len(
            file_cipher, test_data_recipient_cipher_MESSAGE.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_process_encryption(
                                                   file_cipher, test_data_recipient_cipher_MESSAGE, data_buf));

    vsc_buffer_t *finish_buf =
            vsc_buffer_new_with_capacity(vssq_messenger_cloud_fs_cipher_finish_encryption_out_len(file_cipher));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_finish_encryption(file_cipher, finish_buf));

    vsc_buffer_t *footer_buf =
            vsc_buffer_new_with_capacity(vssq_messenger_cloud_fs_cipher_finish_encryption_footer_out_len(file_cipher));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vssq_messenger_cloud_fs_cipher_finish_encryption_footer(file_cipher, footer_buf));

    //
    // Decrypt
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_start_decryption(file_cipher, vsc_buffer_data(file_key)));

    vsc_buffer_t *buff_out = vsc_buffer_new_with_capacity(
            vssq_messenger_cloud_fs_cipher_process_decryption_out_len(file_cipher, vsc_buffer_data(header_buf).len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_process_decryption(file_cipher, vsc_buffer_data(header_buf), buff_out));

    vsc_buffer_reserve_unused(buff_out,
            vssq_messenger_cloud_fs_cipher_process_decryption_out_len(file_cipher, vsc_buffer_data(data_buf).len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_process_decryption(file_cipher, vsc_buffer_data(data_buf), buff_out));

    vsc_buffer_reserve_unused(buff_out,
            vssq_messenger_cloud_fs_cipher_process_decryption_out_len(file_cipher, vsc_buffer_data(finish_buf).len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_process_decryption(file_cipher, vsc_buffer_data(finish_buf), buff_out));

    vsc_buffer_reserve_unused(buff_out,
            vssq_messenger_cloud_fs_cipher_process_decryption_out_len(file_cipher, vsc_buffer_data(footer_buf).len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_process_decryption(file_cipher, vsc_buffer_data(footer_buf), buff_out));

    vsc_buffer_reserve_unused(buff_out, vssq_messenger_cloud_fs_cipher_finish_decryption_out_len(file_cipher));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vssq_messenger_cloud_fs_cipher_finish_decryption(file_cipher, owner_public_key, buff_out));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_recipient_cipher_MESSAGE, buff_out);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&file_key);
    vsc_buffer_destroy(&header_buf);
    vsc_buffer_destroy(&data_buf);
    vsc_buffer_destroy(&finish_buf);
    vsc_buffer_destroy(&footer_buf);
    vsc_buffer_destroy(&buff_out);

    vssq_messenger_cloud_fs_cipher_destroy(&file_cipher);
    vscf_impl_destroy(&owner_public_key);
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
    RUN_TEST(test__messenger_cloud_fs_cipher_encrypt__then_decrypt__text_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
