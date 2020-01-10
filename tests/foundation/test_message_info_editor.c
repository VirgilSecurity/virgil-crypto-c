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


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_RECIPIENT_CIPHER && VSCF_ALG_FACTORY && VSCF_KEY_PROVIDER && VSCF_ED25519 && VSCF_RSA)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_fake_random.h"
#include "vscf_key_provider.h"
#include "vscf_message_info_editor.h"

#include "test_data_message_info.h"
#include "test_data_recipient_cipher.h"

void
test__add_key_recipient__rsa2048_to_message_info_with_ed25519__correct(void) {
    //
    //  Prepare helpers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_message_info_editor_t *message_info_editor = vscf_message_info_editor_new();
    vscf_message_info_editor_use_random(message_info_editor, vscf_fake_random_impl(fake_random));

    //
    //  Prepare recipients.
    //
    vscf_impl_t *ed25519_private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_message_info_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *rsa2048_public_key =
            vscf_key_provider_import_public_key(key_provider, test_data_message_info_RSA2048_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Unpack
    //
    vscf_status_t status = vscf_message_info_editor_unpack(
            message_info_editor, test_data_message_info_MESSAGE_INFO_WITH_ONE_ED25519_RECIPIENT);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Unlock
    //
    status = vscf_message_info_editor_unlock(
            message_info_editor, test_data_message_info_ED25519_RECIPIENT_ID, ed25519_private_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Add new recipient
    //
    status = vscf_message_info_editor_add_key_recipient(
            message_info_editor, test_data_message_info_RSA2048_RECIPIENT_ID, rsa2048_public_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Pack
    //
    vsc_buffer_t *new_packed_message_info =
            vsc_buffer_new_with_capacity(vscf_message_info_editor_packed_len(message_info_editor));
    vscf_message_info_editor_pack(message_info_editor, new_packed_message_info);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_message_info_MESSAGE_INFO_WITH_ONE_ED25519_RECIPIENT_AND_ONE_RSA2048_RECIPIENT,
            new_packed_message_info);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&new_packed_message_info);
    vscf_impl_destroy(&rsa2048_public_key);
    vscf_impl_destroy(&ed25519_private_key);
    vscf_message_info_editor_destroy(&message_info_editor);
    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&fake_random);
}

void
test__remove_key_recipient__ed25519_from_message_info_with_ed25519_and_rsa2048__correct(void) {
    //
    //  Prepare helpers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_message_info_editor_t *message_info_editor = vscf_message_info_editor_new();
    vscf_message_info_editor_use_random(message_info_editor, vscf_fake_random_impl(fake_random));

    //
    //  Prepare recipients.
    //
    vscf_impl_t *rsa2048_private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_message_info_RSA2048_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Unpack
    //
    vscf_status_t status = vscf_message_info_editor_unpack(message_info_editor,
            test_data_message_info_MESSAGE_INFO_WITH_ONE_ED25519_RECIPIENT_AND_ONE_RSA2048_RECIPIENT);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Unlock
    //
    status = vscf_message_info_editor_unlock(
            message_info_editor, test_data_message_info_RSA2048_RECIPIENT_ID, rsa2048_private_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Remove recipient
    //
    bool was_removed = vscf_message_info_editor_remove_key_recipient(
            message_info_editor, test_data_message_info_ED25519_RECIPIENT_ID);
    TEST_ASSERT_TRUE(was_removed);

    //
    //  Pack
    //
    vsc_buffer_t *new_packed_message_info =
            vsc_buffer_new_with_capacity(vscf_message_info_editor_packed_len(message_info_editor));
    vscf_message_info_editor_pack(message_info_editor, new_packed_message_info);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_message_info_MESSAGE_INFO_WITH_ONE_RSA2048_RECIPIENT, new_packed_message_info);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&new_packed_message_info);
    vscf_impl_destroy(&rsa2048_private_key);
    vscf_message_info_editor_destroy(&message_info_editor);
    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&fake_random);
}

void
test__remove_key_recipient__rsa2048_from_message_info_with_ed25519_and_rsa2048__correct(void) {
    //
    //  Prepare helpers.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_message_info_editor_t *message_info_editor = vscf_message_info_editor_new();
    vscf_message_info_editor_use_random(message_info_editor, vscf_fake_random_impl(fake_random));

    //
    //  Prepare recipients.
    //
    vscf_impl_t *ed25519_private_key =
            vscf_key_provider_import_private_key(key_provider, test_data_message_info_ED25519_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Unpack
    //
    vscf_status_t status = vscf_message_info_editor_unpack(message_info_editor,
            test_data_message_info_MESSAGE_INFO_WITH_ONE_ED25519_RECIPIENT_AND_ONE_RSA2048_RECIPIENT);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Unlock
    //
    status = vscf_message_info_editor_unlock(
            message_info_editor, test_data_message_info_ED25519_RECIPIENT_ID, ed25519_private_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Remove recipient
    //
    bool was_removed = vscf_message_info_editor_remove_key_recipient(
            message_info_editor, test_data_message_info_RSA2048_RECIPIENT_ID);
    TEST_ASSERT_TRUE(was_removed);

    //
    //  Pack
    //
    vsc_buffer_t *new_packed_message_info =
            vsc_buffer_new_with_capacity(vscf_message_info_editor_packed_len(message_info_editor));
    vscf_message_info_editor_pack(message_info_editor, new_packed_message_info);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            test_data_message_info_MESSAGE_INFO_WITH_ONE_ED25519_RECIPIENT, new_packed_message_info);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&new_packed_message_info);
    vscf_impl_destroy(&ed25519_private_key);
    vscf_message_info_editor_destroy(&message_info_editor);
    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&fake_random);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__add_key_recipient__rsa2048_to_message_info_with_ed25519__correct);
    RUN_TEST(test__remove_key_recipient__ed25519_from_message_info_with_ed25519_and_rsa2048__correct);
    RUN_TEST(test__remove_key_recipient__rsa2048_from_message_info_with_ed25519_and_rsa2048__correct);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
