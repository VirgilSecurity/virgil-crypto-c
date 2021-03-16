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


#define TEST_DEPENDENCIES_AVAILABLE (VSSQ_MESSENGER)
#if TEST_DEPENDENCIES_AVAILABLE


#include "test_comm_kit_utils.h"

#include "vssq_messenger.h"
#include "vssq_contact_utils.h"
#include "vssq_error_message.h"

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_binary.h>


void
test__messenger_register__random_user__success(void) {
    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *messenger = create_messenger_and_register_user();

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger);
}

void
test__messenger_register_then_authenticate__random_user__success(void) {
    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *messenger_for_registration = create_messenger_and_register_user();
    vssq_messenger_t *messenger_for_authentication = create_messenger();

    //
    //  Authenticate.
    //
    const vssq_messenger_creds_t *creds = vssq_messenger_creds(messenger_for_registration);
    const vssq_status_t authenticate_status = vssq_messenger_authenticate(messenger_for_authentication, creds);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, authenticate_status, vssq_error_message_from_status(authenticate_status).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger_for_registration);
    vssq_messenger_destroy(&messenger_for_authentication);
}

void
test__messenger_creds_backup_then_restore_then_remove__random_user__success(void) {
    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *messenger_for_backup = create_messenger_and_register_user();
    vssq_messenger_t *messenger_for_restore = create_messenger();

    vsc_str_t pwd = vsc_str_from_str("password");

    //
    //  Backup.
    //
    const vssq_status_t backup_status = vssq_messenger_backup_creds(messenger_for_backup, pwd);
    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, backup_status, vssq_error_message_from_status(backup_status).chars);

    //
    //  Restore.
    //
    vsc_str_t username = vssq_messenger_username(messenger_for_backup);
    const vssq_status_t restore_status =
            vssq_messenger_authenticate_with_backup_creds(messenger_for_restore, username, pwd);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, restore_status, vssq_error_message_from_status(restore_status).chars);

    //
    //  Remove.
    //
    const vssq_status_t remove_status = vssq_messenger_remove_creds_backup(messenger_for_restore);
    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, remove_status, vssq_error_message_from_status(remove_status).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger_for_backup);
    vssq_messenger_destroy(&messenger_for_restore);
}

void
test__messenger_find_user_with_username__random_user__success(void) {
    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *bob_messenger = create_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_messenger_and_register_user();

    //
    //  Alice try to find Bob.
    //
    vssq_messenger_user_t *user_bob =
            vssq_messenger_find_user_with_username(alice_messenger, vssq_messenger_username(bob_messenger), &error);

    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, error.status, vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(user_bob);

    //
    //  Bob try to find Alice.
    //
    vssq_messenger_user_t *user_alice =
            vssq_messenger_find_user_with_username(bob_messenger, vssq_messenger_username(alice_messenger), &error);

    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, error.status, vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(user_alice);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&bob_messenger);
    vssq_messenger_destroy(&alice_messenger);
    vssq_messenger_user_destroy(&user_bob);
    vssq_messenger_user_destroy(&user_alice);
}


void
test__messenger_create_group__then_encrypt_decrypt_message_then_delete_group__success() {
    vssq_messenger_t *owner_messenger = create_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_messenger_and_register_user();

    vssq_messenger_user_list_t *other_participants = vssq_messenger_user_list_new();
    vssq_messenger_user_list_add(other_participants, vssq_messenger_user_modifiable(alice_messenger));

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Create group.
    //
    vsc_str_t group_id = vsc_str_from_str("GROUP-AT-LEAST-10-SYMBOLS");
    vssq_messenger_group_t *owner_group =
            vssq_messenger_create_group(owner_messenger, group_id, other_participants, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    const vssq_messenger_user_t *owner = vssq_messenger_group_owner(owner_group);

    //
    //  Encrypt message.
    //
    vsc_str_t message = vsc_str_from_str("Greetings!");

    const size_t encrypted_message_len = vssq_messenger_group_encrypted_message_len(owner_group, message.len);
    vsc_buffer_t *encrypted_message = vsc_buffer_new_with_capacity(encrypted_message_len);

    error.status = vssq_messenger_group_encrypt_message(owner_group, message, encrypted_message);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Load group.
    //
    vssq_messenger_group_t *alice_group = vssq_messenger_load_group(alice_messenger, group_id, owner, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    //
    //  Decrypt message.
    //
    const size_t decrypted_message_len =
            vssq_messenger_group_decrypted_message_len(alice_group, vsc_buffer_len(encrypted_message));

    vsc_str_buffer_t *decrypted_message = vsc_str_buffer_new_with_capacity(decrypted_message_len);

    error.status = vssq_messenger_group_decrypt_message(
            alice_group, vsc_buffer_data(encrypted_message), owner, decrypted_message);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_STR(message, vsc_str_buffer_str(decrypted_message));

    //
    //  Delete group.
    //
    error.status = vssq_messenger_group_remove(owner_group);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&owner_messenger);
    vssq_messenger_destroy(&alice_messenger);
    vssq_messenger_user_list_destroy(&other_participants);
    vssq_messenger_group_destroy(&owner_group);
    vsc_buffer_destroy(&encrypted_message);
    vssq_messenger_group_destroy(&alice_group);
    vsc_str_buffer_destroy(&decrypted_message);
}

void
test__messenger_create_group__then_export_it__expect_equal_exported_groups() {
    vssq_messenger_t *owner_messenger = create_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_messenger_and_register_user();

    vssq_messenger_user_list_t *other_participants = vssq_messenger_user_list_new();
    vssq_messenger_user_list_add(other_participants, vssq_messenger_user_modifiable(alice_messenger));

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Create group.
    //
    vsc_str_t group_id = vsc_str_from_str("GROUP-AT-LEAST-10-SYMBOLS");
    vssq_messenger_group_t *owner_group =
            vssq_messenger_create_group(owner_messenger, group_id, other_participants, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    const vssq_messenger_user_t *owner = vssq_messenger_group_owner(owner_group);

    //
    //  Load group.
    //
    vssq_messenger_group_t *alice_group = vssq_messenger_load_group(alice_messenger, group_id, owner, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    //
    //  Export groups.
    //
    vssc_json_object_t *owner_group_json = vssq_messenger_group_to_json(owner_group);
    TEST_ASSERT_NOT_NULL(owner_group_json);

    vsc_str_t owner_group_json_str = vssc_json_object_as_str(owner_group_json);
    TEST_ASSERT_GREATER_THAN(0, owner_group_json_str.len);

    vssc_json_object_t *alice_group_json = vssq_messenger_group_to_json(alice_group);
    TEST_ASSERT_NOT_NULL(alice_group_json);

    vsc_str_t alice_group_json_str = vssc_json_object_as_str(alice_group_json);
    TEST_ASSERT_GREATER_THAN(0, owner_group_json_str.len);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_STR(owner_group_json_str, alice_group_json_str);
    print_str(owner_group_json_str);

    //
    //  Delete group.
    //
    error.status = vssq_messenger_group_remove(owner_group);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&owner_messenger);
    vssq_messenger_destroy(&alice_messenger);
    vssq_messenger_user_list_destroy(&other_participants);
    vssq_messenger_group_destroy(&owner_group);
    vssq_messenger_group_destroy(&alice_group);
    vssc_json_object_destroy(&owner_group_json);
    vssc_json_object_destroy(&alice_group_json);
}

void
test__messenger_import_group__then_encrypt_decrypt__success() {
    vssq_messenger_t *owner_messenger = create_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_messenger_and_register_user();

    vssq_messenger_user_list_t *other_participants = vssq_messenger_user_list_new();
    vssq_messenger_user_list_add(other_participants, vssq_messenger_user_modifiable(alice_messenger));

    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Create group.
    //
    vsc_str_t group_id = vsc_str_from_str("GROUP-AT-LEAST-10-SYMBOLS");
    vssq_messenger_group_t *owner_group =
            vssq_messenger_create_group(owner_messenger, group_id, other_participants, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    const vssq_messenger_user_t *owner = vssq_messenger_group_owner(owner_group);

    //
    //  Export group.
    //
    vssc_json_object_t *owner_group_json = vssq_messenger_group_to_json(owner_group);
    TEST_ASSERT_NOT_NULL(owner_group_json);

    vsc_str_t owner_group_json_str = vssc_json_object_as_str(owner_group_json);
    TEST_ASSERT_GREATER_THAN(0, owner_group_json_str.len);

    //
    //  Encrypt message.
    //
    vsc_str_t message = vsc_str_from_str("Greetings!");

    const size_t encrypted_message_len = vssq_messenger_group_encrypted_message_len(owner_group, message.len);
    vsc_buffer_t *encrypted_message = vsc_buffer_new_with_capacity(encrypted_message_len);

    error.status = vssq_messenger_group_encrypt_message(owner_group, message, encrypted_message);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Import group.
    //
    vssq_messenger_group_t *alice_group =
            vssq_messenger_load_group_from_json_str(alice_messenger, owner_group_json_str, &error);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(owner_group);

    //
    //  Decrypt message.
    //
    const size_t decrypted_message_len =
            vssq_messenger_group_decrypted_message_len(alice_group, vsc_buffer_len(encrypted_message));

    vsc_str_buffer_t *decrypted_message = vsc_str_buffer_new_with_capacity(decrypted_message_len);

    error.status = vssq_messenger_group_decrypt_message(
            alice_group, vsc_buffer_data(encrypted_message), owner, decrypted_message);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Check
    //
    TEST_ASSERT_EQUAL_STR(message, vsc_str_buffer_str(decrypted_message));

    //
    //  Delete group.
    //
    error.status = vssq_messenger_group_remove(owner_group);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, vssq_error_status(&error), vssq_error_message_from_error(&error).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&owner_messenger);
    vssq_messenger_destroy(&alice_messenger);
    vssq_messenger_user_list_destroy(&other_participants);
    vssq_messenger_group_destroy(&owner_group);
    vssc_json_object_destroy(&owner_group_json);
    vsc_buffer_destroy(&encrypted_message);
    vssq_messenger_group_destroy(&alice_group);
    vsc_str_buffer_destroy(&decrypted_message);
}
#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__messenger_register__random_user__success);
    RUN_TEST(test__messenger_register_then_authenticate__random_user__success);
    RUN_TEST(test__messenger_creds_backup_then_restore_then_remove__random_user__success);
    RUN_TEST(test__messenger_find_user_with_username__random_user__success);
    RUN_TEST(test__messenger_create_group__then_encrypt_decrypt_message_then_delete_group__success);
    RUN_TEST(test__messenger_create_group__then_export_it__expect_equal_exported_groups);
    RUN_TEST(test__messenger_import_group__then_encrypt_decrypt__success);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
