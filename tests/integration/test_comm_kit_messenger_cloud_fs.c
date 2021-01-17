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
compare_file_infos(
        const vssq_messenger_cloud_fs_file_info_t *expected, const vssq_messenger_cloud_fs_file_info_t *actual) {

    vsc_str_t expected_file_name = vssq_messenger_cloud_fs_file_info_name(expected);
    vsc_str_t expected_file_type = vssq_messenger_cloud_fs_file_info_type(expected);
    size_t expected_file_size = vssq_messenger_cloud_fs_file_info_size(expected);
    size_t expected_file_created_at = vssq_messenger_cloud_fs_file_info_created_at(expected);
    size_t expected_file_updated_at = vssq_messenger_cloud_fs_file_info_updated_at(expected);
    vsc_str_t expected_file_updated_by = vssq_messenger_cloud_fs_file_info_updated_by(expected);

    vsc_str_t actual_file_name = vssq_messenger_cloud_fs_file_info_name(actual);
    vsc_str_t actual_file_type = vssq_messenger_cloud_fs_file_info_type(actual);
    size_t actual_file_size = vssq_messenger_cloud_fs_file_info_size(actual);
    size_t actual_file_created_at = vssq_messenger_cloud_fs_file_info_created_at(actual);
    size_t actual_file_updated_at = vssq_messenger_cloud_fs_file_info_updated_at(actual);
    vsc_str_t actual_file_updated_by = vssq_messenger_cloud_fs_file_info_updated_by(actual);

    TEST_ASSERT_EQUAL_STR(expected_file_name, actual_file_name);
    TEST_ASSERT_EQUAL_STR(expected_file_type, actual_file_type);
    TEST_ASSERT_EQUAL(expected_file_size, actual_file_size);
    TEST_ASSERT_GREATER_OR_EQUAL(expected_file_created_at, actual_file_created_at);
    TEST_ASSERT_GREATER_OR_EQUAL(expected_file_updated_at, actual_file_updated_at);
    TEST_ASSERT_EQUAL_STR(expected_file_updated_by, actual_file_updated_by);
}


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
    TEST_ASSERT_GREATER_OR_EQUAL(now, created_file_created_at);

    size_t created_file_updated_at = vssq_messenger_cloud_fs_file_info_updated_at(file_info);
    TEST_ASSERT_GREATER_OR_EQUAL(now, created_file_updated_at);


    vsc_str_t my_identity = vssq_messenger_user_identity(vssq_messenger_user(messenger));
    vsc_str_t created_file_updated_by = vssq_messenger_cloud_fs_file_info_updated_by(file_info);
    TEST_ASSERT_EQUAL_STR(my_identity, created_file_updated_by);

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
test__messenger_cloud_fs_get_download_link__of_created_file__success(void) {
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

    vssq_messenger_cloud_fs_created_file_t *created_file = vssq_messenger_cloud_fs_create_file(
            cloud_fs, file_name, file_type, file_size, root_folder_id, fake_encrypted_key, &error);

    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(created_file);

    const vssq_messenger_cloud_fs_file_info_t *file_info = vssq_messenger_cloud_fs_created_file_info(created_file);
    TEST_ASSERT_NOT_NULL(file_info);

    vsc_str_t created_file_id = vssq_messenger_cloud_fs_file_info_id(file_info);

    //
    //  Get download link.
    //
    vssq_messenger_cloud_fs_file_download_info_t *download_info =
            vssq_messenger_cloud_fs_get_download_link(cloud_fs, created_file_id, &error);

    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(download_info);

    //
    //  Check.
    //

    vsc_str_t download_link = vssq_messenger_cloud_fs_file_download_info_link(download_info);
    TEST_ASSERT_GREATER_THAN(0, download_link.len);

    vsc_data_t file_encrypted_key = vssq_messenger_cloud_fs_file_download_info_file_encrypted_key(download_info);
    TEST_ASSERT_EQUAL_DATA(file_encrypted_key, fake_encrypted_key);

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
    vssq_messenger_cloud_fs_file_download_info_destroy(&download_info);
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
    TEST_ASSERT_GREATER_OR_EQUAL(now, created_folder_created_at);

    size_t created_folder_updated_at = vssq_messenger_cloud_fs_folder_info_updated_at(folder_info);
    TEST_ASSERT_GREATER_OR_EQUAL(now, created_folder_updated_at);

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

void
test__messenger_cloud_fs_list_folder__before_create_2_files_within_root__2_files_listed(void) {
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

    vsc_str_t file_name1 = vsc_str_from_str("hello1.txt");
    vsc_str_t file_name2 = vsc_str_from_str("hello2.txt");
    vsc_str_t file_type = vsc_str_from_str("text/plain");
    size_t file_size = 1024;
    vsc_str_t root_folder_id = vsc_str_empty();
    vsc_data_t fake_encrypted_key = vsc_str_as_data(vsc_str_from_str("fake-file-encrypted-private-key"));

    //
    //  Create first file.
    //
    vssq_messenger_cloud_fs_created_file_t *created_file1 = vssq_messenger_cloud_fs_create_file(
            cloud_fs, file_name1, file_type, file_size, root_folder_id, fake_encrypted_key, &error);

    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(created_file1);

    const vssq_messenger_cloud_fs_file_info_t *file1_info = vssq_messenger_cloud_fs_created_file_info(created_file1);
    vsc_str_t created_file1_id = vssq_messenger_cloud_fs_file_info_id(file1_info);

    //
    //  Create second file.
    //
    vssq_messenger_cloud_fs_created_file_t *created_file2 = vssq_messenger_cloud_fs_create_file(
            cloud_fs, file_name2, file_type, file_size, root_folder_id, fake_encrypted_key, &error);

    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(created_file2);

    const vssq_messenger_cloud_fs_file_info_t *file2_info = vssq_messenger_cloud_fs_created_file_info(created_file2);
    vsc_str_t created_file2_id = vssq_messenger_cloud_fs_file_info_id(file2_info);


    //
    //  List files from the root folder.
    //
    vssq_messenger_cloud_fs_folder_t *root_folder =
            vssq_messenger_cloud_fs_list_folder(cloud_fs, root_folder_id, &error);

    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));
    TEST_ASSERT_NOT_NULL(root_folder);

    //
    //  Check.
    //
    size_t total_entry_count = vssq_messenger_cloud_fs_folder_total_entry_count(root_folder);
    TEST_ASSERT_EQUAL(2, total_entry_count);

    size_t total_folder_count = vssq_messenger_cloud_fs_folder_total_folder_count(root_folder);
    TEST_ASSERT_EQUAL(0, total_folder_count);

    size_t total_file_count = vssq_messenger_cloud_fs_folder_total_file_count(root_folder);
    TEST_ASSERT_EQUAL(2, total_file_count);

    const vssq_messenger_cloud_fs_folder_info_list_t *folders = vssq_messenger_cloud_fs_folder_folders(root_folder);
    TEST_ASSERT_NOT_NULL(folders);

    const vssq_messenger_cloud_fs_file_info_list_t *files = vssq_messenger_cloud_fs_folder_files(root_folder);
    TEST_ASSERT_NOT_NULL(files);

    const vssq_messenger_cloud_fs_folder_info_t *info = vssq_messenger_cloud_fs_folder_info(root_folder);
    TEST_ASSERT_NOT_NULL(info);

    TEST_ASSERT_TRUE(vssq_messenger_cloud_fs_folder_is_root(root_folder));

    vsc_data_t folder_encrypted_key = vssq_messenger_cloud_fs_folder_folder_encrypted_key(root_folder);
    TEST_ASSERT_EQUAL(0, folder_encrypted_key.len);

    vsc_data_t folder_public_key = vssq_messenger_cloud_fs_folder_folder_public_key(root_folder);
    TEST_ASSERT_EQUAL(0, folder_public_key.len);

    //
    //  Compare file infos.
    //
    size_t checked_files = 2;
    for (const vssq_messenger_cloud_fs_file_info_list_t *file_it = files;
            (file_it != NULL) && vssq_messenger_cloud_fs_file_info_list_has_item(file_it);
            file_it = vssq_messenger_cloud_fs_file_info_list_next(file_it)) {

        const vssq_messenger_cloud_fs_file_info_t *file_info = vssq_messenger_cloud_fs_file_info_list_item(file_it);
        vsc_str_t file_id = vssq_messenger_cloud_fs_file_info_id(file_info);

        if (vsc_str_equal(created_file1_id, file_id)) {
            compare_file_infos(file1_info, file_info);

        } else if (vsc_str_equal(created_file2_id, file_id)) {
            compare_file_infos(file2_info, file_info);

        } else {
            TEST_FAIL_MESSAGE("Got unexpected file.");
        }

        if (0 == checked_files) {
            TEST_FAIL_MESSAGE("Got more files as expected.");
        }

        --checked_files;
    }

    TEST_ASSERT_EQUAL_MESSAGE(0, checked_files, "Got more files as expected.");

    //
    //  Delete files.
    //
    error.status = vssq_messenger_cloud_fs_delete_file(cloud_fs, created_file1_id);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));

    error.status = vssq_messenger_cloud_fs_delete_file(cloud_fs, created_file2_id);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(vssq_error_status(&error));

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger);
    vssq_messenger_cloud_fs_created_file_destroy(&created_file1);
    vssq_messenger_cloud_fs_created_file_destroy(&created_file2);
    vssq_messenger_cloud_fs_folder_destroy(&root_folder);
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
    RUN_TEST(test__messenger_cloud_fs_get_download_link__of_created_file__success);
    RUN_TEST(test__messenger_cloud_fs_create_folder__in_the_root_folder_then_delete_it__got_upload_link);
    RUN_TEST(test__messenger_cloud_fs_list_folder__before_create_2_files_within_root__2_files_listed);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}