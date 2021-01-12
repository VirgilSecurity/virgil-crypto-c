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


#define TEST_DEPENDENCIES_AVAILABLE (VSSQ_MESSENGER && VSSQ_MESSENGER_CLOUD_FS)
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_comm_kit_utils.h"

#include "vssq_messenger.h"
#include "vssq_error_message.h"

#include <virgil/sdk/core/vssc_unix_time.h>

void
test__messenger_cloud_fs_create_file__then_delete_it__got_upload_link(void) {
    //
    //  Create messenger with random user.
    //
    vssq_messenger_t *messenger = create_messenger_and_register_user();

    //
    //  Create file.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    const vssq_messenger_cloud_fs_t *cloud_fs = vssq_messenger_cloud_fs(messenger);

    vsc_str_t file_name = vsc_str_from_str("hello.txt");
    vsc_str_t file_type = vsc_str_from_str("text/plain");
    size_t file_size = 1024;
    vsc_str_t root_folder_id = vsc_str_empty();
    vsc_data_t fake_encrypted_key = vsc_str_as_data(vsc_str_from_str("fake-file-encrypted-private-key"));
    size_t now = vssc_unix_time_now();

    vssq_messenger_cloud_fs_created_file_t *created_file = vssq_messenger_cloud_fs_create_file(
            cloud_fs, file_name, file_type, file_size, root_folder_id, fake_encrypted_key, &error);

    //
    //  Check.
    //
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(created_file);

    vsc_str_t created_file_upload_link = vssq_messenger_cloud_fs_created_file_upload_link(created_file);
    TEST_ASSERT_GREATER_THAN(0, created_file_upload_link.len);

    const vssq_messenger_cloud_fs_file_info_t *file_info = vssq_messenger_cloud_fs_created_file_info(created_file);
    TEST_ASSERT_NOT_NULL(file_info);

    vsc_str_t created_file_id = vssq_messenger_cloud_fs_file_info_id(file_info);
    TEST_ASSERT_EQUAL(32, vsc_str_len(created_file_id));

    vsc_str_t created_file_name = vssq_messenger_cloud_fs_file_info_name(file_info);
    TEST_ASSERT_EQUAL_STR(file_name, created_file_name);

    vsc_str_t created_file_type = vssq_messenger_cloud_fs_file_info_type(file_info);
    TEST_ASSERT_EQUAL_STR(file_type, created_file_type);

    size_t created_file_size = vssq_messenger_cloud_fs_file_info_size(file_info);
    TEST_ASSERT_EQUAL(file_size, created_file_size);

    size_t created_file_created_at = vssq_messenger_cloud_fs_file_info_created_at(file_info);
    TEST_ASSERT_GREATER_THAN(now, created_file_created_at);

    size_t created_file_updated_at = vssq_messenger_cloud_fs_file_info_updated_at(file_info);
    TEST_ASSERT_GREATER_THAN(now, created_file_updated_at);

    //
    //  Delete file.
    //
    error.status = vssq_messenger_cloud_fs_delete_file(cloud_fs, created_file_id);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger);
    vssq_messenger_cloud_fs_created_file_destroy(&created_file);
}

void
test__messenger_cloud_fs_create_folder__in_the_root_folder_then_delete_it__got_upload_link(void) {
    //
    //  Create messenger with random user.
    //
    vssq_messenger_t *messenger = create_messenger_and_register_user();

    //
    //  Create folder.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    const vssq_messenger_cloud_fs_t *cloud_fs = vssq_messenger_cloud_fs(messenger);

    vsc_str_t folder_name = vsc_str_from_str("temp");
    vsc_str_t root_folder_id = vsc_str_empty();
    vsc_data_t fake_encrypted_key = vsc_str_as_data(vsc_str_from_str("fake-folder-encrypted-private-key"));
    vsc_data_t fake_public_key = vsc_str_as_data(vsc_str_from_str("fake-folder-public-key"));
    size_t now = vssc_unix_time_now();

    vssq_messenger_cloud_fs_folder_info_t *folder_info = vssq_messenger_cloud_fs_create_folder(
            cloud_fs, folder_name, fake_encrypted_key, fake_public_key, root_folder_id, &error);

    //
    //  Check.
    //
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(folder_info);

    vsc_str_t created_folder_id = vssq_messenger_cloud_fs_folder_info_id(folder_info);
    TEST_ASSERT_EQUAL(32, vsc_str_len(created_folder_id));

    vsc_str_t created_folder_name = vssq_messenger_cloud_fs_folder_info_name(folder_info);
    TEST_ASSERT_EQUAL_STR(folder_name, created_folder_name);

    size_t created_folder_created_at = vssq_messenger_cloud_fs_folder_info_created_at(folder_info);
    TEST_ASSERT_GREATER_THAN(now, created_folder_created_at);

    size_t created_folder_updated_at = vssq_messenger_cloud_fs_folder_info_updated_at(folder_info);
    TEST_ASSERT_GREATER_THAN(now, created_folder_updated_at);

    //
    //  Delete folder.
    //
    error.status = vssq_messenger_cloud_fs_delete_folder(cloud_fs, created_folder_id);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger);
    vssq_messenger_cloud_fs_folder_info_destroy(&folder_info);
}
#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__messenger_cloud_fs_create_file__then_delete_it__got_upload_link);
    RUN_TEST(test__messenger_cloud_fs_create_folder__in_the_root_folder_then_delete_it__got_upload_link);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
