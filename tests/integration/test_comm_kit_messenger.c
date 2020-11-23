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


#include "vssq_messenger.h"
#include "vssq_contact_utils.h"
#include "vssq_error_message.h"

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_binary.h>


static vsc_str_buffer_t *
generate_random_username(void) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();

    if (vscf_ctr_drbg_setup_defaults(ctr_drbg) != vscf_status_SUCCESS) {
        TEST_FAIL_MESSAGE("Can not initialize RNG.");
    }

    const vsc_str_t username_prefix = vsc_str_from_str("test_");

    const size_t random_bytes_len = (vssq_contact_utils_USERNAME_LEN_MAX - username_prefix.len) >> 1;
    vsc_buffer_t *random_bytes = vsc_buffer_new_with_capacity(random_bytes_len);

    if (vscf_ctr_drbg_random(ctr_drbg, random_bytes_len, random_bytes) != vscf_status_SUCCESS) {
        TEST_FAIL_MESSAGE("Random failed.");
    }

    vsc_str_buffer_t *username = vsc_str_buffer_new_with_capacity(vssq_contact_utils_USERNAME_LEN_MAX);
    vsc_str_buffer_write_str(username, username_prefix);

    vscf_binary_to_hex(vsc_buffer_data(random_bytes), username);

    vsc_buffer_destroy(&random_bytes);
    vscf_ctr_drbg_destroy(&ctr_drbg);

    return username;
}


static vssq_messenger_t *
create_messenger(void) {
    //
    //  Configure.
    //
    vsc_str_t base_url = vsc_str_from_str("https://messenger-dev.virgilsecurity.com");
    vsc_str_t ejabberd_url = vsc_str_from_str("xmpp-dev.virgilsecurity.com");

    vssq_messenger_config_t *config = vssq_messenger_config_new_with(base_url, ejabberd_url);

    vssq_messenger_t *messenger = vssq_messenger_new_with_config(config);
    const vssq_status_t status = vssq_messenger_setup_defaults(messenger);
    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, status, vssq_error_message_from_status(status).chars);

    vssq_messenger_config_destroy(&config);

    return messenger;
}

static vssq_messenger_t *
create_messenger_and_register_user(void) {

    vssq_messenger_t *messenger = create_messenger();
    vsc_str_buffer_t *username = generate_random_username();

    const vssq_status_t status = vssq_messenger_register(messenger, vsc_str_buffer_str(username));
    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, status, vssq_error_message_from_status(status).chars);

    vsc_str_buffer_destroy(&username);

    return messenger;
}

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
test__messenger_create_group__then_encrypt_decrypt_message_then_delete_group__success() {
    vssq_messenger_t *owner_messenger = create_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_messenger_and_register_user();

    vssq_messenger_user_list_t *other_participants = vssq_messenger_user_list_new();
    vssq_messenger_user_list_add(other_participants, vssq_messenger_user(alice_messenger));

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
    RUN_TEST(test__messenger_create_group__then_encrypt_decrypt_message_then_delete_group__success);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
