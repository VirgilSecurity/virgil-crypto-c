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


#define TEST_DEPENDENCIES_AVAILABLE (VSSC_VIRGIL_HTTP_CLIENT && VSSK_KEYKNOX_CLIENT)
#if TEST_DEPENDENCIES_AVAILABLE


#include "test_env.h"
#include "test_sdk_utils.h"

#include <virgil/crypto/common/vsc_str_buffer.h>
#include <virgil/crypto/foundation/vscf_binary.h>

#include <virgil/sdk/core/vssc_unix_time.h>
#include <virgil/sdk/core/vssc_virgil_http_client.h>

#include <virgil/sdk/keyknox/vssk_keyknox_client.h>


#define MAKE_STR_CONSTANT(name, value)                                                                                 \
    static const char name##_CHARS[] = value;                                                                          \
    static const vsc_str_t name = {name##_CHARS, sizeof(name##_CHARS) - 1};

#define MAKE_DATA_CONSTANT_FROM_STR(name, value)                                                                       \
    static const byte name##_BYTES[] = value;                                                                          \
    static const vsc_data_t name = {name##_BYTES, sizeof(name##_BYTES) - 1};


MAKE_STR_CONSTANT(test_data_ROOT, "root")
MAKE_STR_CONSTANT(test_data_PATH1, "path1")
MAKE_STR_CONSTANT(test_data_PATH2, "path2")
MAKE_STR_CONSTANT(test_data_PATH3, "path3")
MAKE_STR_CONSTANT(test_data_PATH4, "path4")
MAKE_STR_CONSTANT(test_data_PATH5, "path5")

MAKE_DATA_CONSTANT_FROM_STR(test_data_META, "d5b1f64f-75b2-45ef-adc7-1b095b0677d5")
MAKE_DATA_CONSTANT_FROM_STR(test_data_VALUE, "4bc0ff31-cb8e-42da-a19a-8b8decdf63ed")

MAKE_DATA_CONSTANT_FROM_STR(test_data_META_2, "ab8e7331-55c5-4eb9-a160-7f6b79a40df7")
MAKE_DATA_CONSTANT_FROM_STR(test_data_VALUE_2, "19bd499c-27ca-4cbb-be81-f4666cda804f")

static vsc_str_buffer_t *
create_random_key(const test_env_t *env) {

    const size_t random_bytes_len = 8;
    vsc_buffer_t *random_bytes = vsc_buffer_new_with_capacity(random_bytes_len);

    const vscf_status_t rng_status = vscf_random(env->random, random_bytes_len, random_bytes);
    if (rng_status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&random_bytes);
        TEST_FAIL_MESSAGE("Random function failed");
        return NULL;
    }

    vsc_str_t key_prefix = vsc_str_from_str("key-");

    vsc_str_buffer_t *key_str = vsc_str_buffer_new_with_capacity(key_prefix.len + 2 * random_bytes_len);
    vsc_str_buffer_write_str(key_str, key_prefix);

    vscf_binary_to_hex(vsc_buffer_data(random_bytes), key_str);

    vsc_buffer_destroy(&random_bytes);

    return key_str;
}

void
test_assert_equal_keyknox_entry(
        vsc_str_t expected_owner, const vssk_keyknox_entry_t *expected_entry, const vssk_keyknox_entry_t *given_entry) {
    if (vsc_str_is_empty(vssk_keyknox_entry_owner(expected_entry))) {
        TEST_ASSERT_EQUAL_STR(expected_owner, vssk_keyknox_entry_owner(given_entry));
    } else {
        TEST_ASSERT_EQUAL_STR(vssk_keyknox_entry_owner(expected_entry), vssk_keyknox_entry_owner(given_entry));
    }
    TEST_ASSERT_EQUAL_STR(vssk_keyknox_entry_root(expected_entry), vssk_keyknox_entry_root(given_entry));
    TEST_ASSERT_EQUAL_STR(vssk_keyknox_entry_path(expected_entry), vssk_keyknox_entry_path(given_entry));
    TEST_ASSERT_EQUAL_STR(vssk_keyknox_entry_key(expected_entry), vssk_keyknox_entry_key(given_entry));
    TEST_ASSERT_EQUAL_DATA(vssk_keyknox_entry_meta(expected_entry), vssk_keyknox_entry_meta(given_entry));
    TEST_ASSERT_EQUAL_DATA(vssk_keyknox_entry_value(expected_entry), vssk_keyknox_entry_value(given_entry));

    const vssc_string_list_t *expected_identites = vssk_keyknox_entry_identities(expected_entry);
    const vssc_string_list_t *given_identities = vssk_keyknox_entry_identities(given_entry);
    for (const vssc_string_list_t *expected_identity_it = expected_identites;
            (expected_identity_it != NULL) && vssc_string_list_has_item(expected_identity_it);
            expected_identity_it = vssc_string_list_next(expected_identity_it)) {

        TEST_ASSERT_TRUE(vssc_string_list_contains(given_identities, vssc_string_list_item(expected_identity_it)));
    }
}

//
//  Return pushed keyknox entry.
//  If 'key' is empty then it will be generated.
//  If 'identity' is empty then it will be taken from JWT.
//
static vssk_keyknox_entry_t *
push_new_keyknox_entry_ext(
        const test_env_t *env, const vssc_jwt_t *jwt, const vssk_keyknox_entry_t *new_keyknox_entry) {
    //
    //  Init.
    //
    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vssc_http_request_t *push_keyknox_entry_request =
            vssk_keyknox_client_make_request_push(keyknox_client, new_keyknox_entry);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, core_sdk_error.status);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            push_keyknox_entry_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(jwt));

    vssc_http_response_t *push_keyknox_entry_response =
            vssc_virgil_http_client_send(push_keyknox_entry_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(push_keyknox_entry_response);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            vssk_keyknox_client_process_response_push(push_keyknox_entry_response, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(pushed_keyknox_entry);

    //
    //  Check fields.
    //
    test_assert_equal_keyknox_entry(vssc_jwt_identity(jwt), new_keyknox_entry, pushed_keyknox_entry);
    TEST_ASSERT_TRUE(vsc_data_is_valid_and_non_empty(vssk_keyknox_entry_hash(pushed_keyknox_entry)));

    //
    //  Cleanup.
    //
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&push_keyknox_entry_request);
    vssc_http_response_destroy(&push_keyknox_entry_response);

    return pushed_keyknox_entry;
}

static vssk_keyknox_entry_t *
push_new_keyknox_entry(const test_env_t *env, vsc_str_t root, vsc_str_t path, vsc_str_t key, vsc_str_t identity) {
    //
    //  Take identity from JWT if not given.
    //
    if (vsc_str_is_empty(identity)) {
        identity = vssc_jwt_identity(env->jwt);
    }

    //
    // Make a random key if not given.
    //
    vsc_str_buffer_t *key_buf = NULL;
    if (vsc_str_is_empty(key)) {
        key_buf = create_random_key(env);
        key = vsc_str_buffer_str(key_buf);
    }

    //
    //  Make Keyknox entry.
    //
    vssc_string_list_t *identities = vssc_string_list_new();
    vssc_string_list_add(identities, identity);

    vssk_keyknox_entry_t *new_keyknox_entry =
            vssk_keyknox_entry_new_with(root, path, key, identities, test_data_META, test_data_VALUE, vsc_data_empty());

    vssk_keyknox_entry_t *pushed_keyknox_entry = push_new_keyknox_entry_ext(env, env->jwt, new_keyknox_entry);

    //
    //  Cleanup and return.
    //
    vssk_keyknox_entry_destroy(&new_keyknox_entry);
    vsc_str_buffer_destroy(&key_buf);

    return pushed_keyknox_entry;
}

void
test__push__with_random_key_id__returns_expected_keyknox_entry(void) {
    const test_env_t *env = test_env_get();

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH1, vsc_str_empty(), vsc_str_empty());

    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
}

void
test__pull__pushed_entry__returns_expected_keyknox_entry(void) {
    const test_env_t *env = test_env_get();

    //
    //  Init.
    //
    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_buffer_t *key_buf = create_random_key(env);
    vsc_str_t key = vsc_str_buffer_str(key_buf);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH2, key, identity);


    //
    //  Pull Keyknox entry.
    //
    vssc_http_request_t *pull_keyknox_entry_request =
            vssk_keyknox_client_make_request_pull(keyknox_client, test_data_ROOT, test_data_PATH2, key, identity);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            pull_keyknox_entry_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *pull_keyknox_entry_response =
            vssc_virgil_http_client_send(pull_keyknox_entry_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(pull_keyknox_entry_response);

    vssk_keyknox_entry_t *pulled_keyknox_entry =
            vssk_keyknox_client_process_response_pull(pull_keyknox_entry_response, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(pulled_keyknox_entry);

    //
    //  Check fields.
    //
    TEST_ASSERT_EQUAL_STR(identity, vssk_keyknox_entry_owner(pulled_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(test_data_ROOT, vssk_keyknox_entry_root(pulled_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(test_data_PATH2, vssk_keyknox_entry_path(pulled_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(key, vssk_keyknox_entry_key(pulled_keyknox_entry));
    TEST_ASSERT_EQUAL_DATA(test_data_META, vssk_keyknox_entry_meta(pulled_keyknox_entry));
    TEST_ASSERT_EQUAL_DATA(test_data_VALUE, vssk_keyknox_entry_value(pulled_keyknox_entry));

    const vssc_string_list_t *pulled_identities = vssk_keyknox_entry_identities(pulled_keyknox_entry);
    TEST_ASSERT_TRUE(vssc_string_list_has_item(pulled_identities));
    TEST_ASSERT_EQUAL_STR(identity, vssc_string_list_item(pulled_identities));

    //
    //  Cleanup.
    //
    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
    vssk_keyknox_entry_destroy(&pulled_keyknox_entry);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&pull_keyknox_entry_request);
    vssc_http_response_destroy(&pull_keyknox_entry_response);
    vsc_str_buffer_destroy(&key_buf);
}

void
test__reset__pushed_entry_with_defined_root_and_path__returns_expected_keyknox_entry(void) {
    const test_env_t *env = test_env_get();

    //
    //  Init.
    //
    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_buffer_t *key_buf = create_random_key(env);
    vsc_str_t key = vsc_str_buffer_str(key_buf);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH3, key, identity);

    //
    //  Reset Keyknox entry.
    //
    vsc_str_t empty_key = vsc_str_empty();
    vsc_str_t empty_identity = vsc_str_empty();
    vssc_http_request_t *reset_keyknox_entry_request = vssk_keyknox_client_make_request_reset(
            keyknox_client, test_data_ROOT, test_data_PATH3, empty_key, empty_identity);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            reset_keyknox_entry_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *reset_keyknox_entry_response =
            vssc_virgil_http_client_send(reset_keyknox_entry_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(reset_keyknox_entry_response);

    vssk_keyknox_entry_t *reset_keyknox_entry =
            vssk_keyknox_client_process_response_reset(reset_keyknox_entry_response, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(reset_keyknox_entry);

    //
    //  Check fields.
    //
    TEST_ASSERT_EQUAL_STR(identity, vssk_keyknox_entry_owner(reset_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(test_data_ROOT, vssk_keyknox_entry_root(reset_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(test_data_PATH3, vssk_keyknox_entry_path(reset_keyknox_entry));
    TEST_ASSERT_EQUAL_STR(empty_key, vssk_keyknox_entry_key(reset_keyknox_entry));

    const vssc_string_list_t *reset_identities = vssk_keyknox_entry_identities(reset_keyknox_entry);
    TEST_ASSERT_FALSE(vssc_string_list_has_item(reset_identities));

    //
    //  Cleanup.
    //
    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
    vssk_keyknox_entry_destroy(&reset_keyknox_entry);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&reset_keyknox_entry_request);
    vssc_http_response_destroy(&reset_keyknox_entry_response);
    vsc_str_buffer_destroy(&key_buf);
}

void
test__get_keys__pushed_1_entry__returns_list_with_1_key(void) {
    const test_env_t *env = test_env_get();

    //
    //  Init.
    //
    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_buffer_t *key_buf = create_random_key(env);
    vsc_str_t key = vsc_str_buffer_str(key_buf);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH4, key, identity);

    //
    //  Get Keyknox keys.
    //
    vsc_str_t empty_identity = vsc_str_empty();
    vssc_http_request_t *get_keys_request =
            vssk_keyknox_client_make_request_get_keys(keyknox_client, test_data_ROOT, test_data_PATH4, empty_identity);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            get_keys_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *get_keys_response = vssc_virgil_http_client_send(get_keys_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(get_keys_response);

    vssc_string_list_t *keys = vssk_keyknox_client_process_response_get_keys(get_keys_response, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(keys);
    TEST_ASSERT_TRUE(vssc_string_list_has_item(keys));
    TEST_ASSERT_TRUE(vssc_string_list_contains(keys, key));

    //
    //  Cleanup.
    //
    vssc_string_list_destroy(&keys);
    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&get_keys_request);
    vssc_http_response_destroy(&get_keys_response);
    vsc_str_buffer_destroy(&key_buf);
}

void
test__reset__all_entries__success(void) {
    //
    //  Init.
    //
    const test_env_t *env = test_env_get();

    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Reset all Keyknox entries.
    //
    vsc_str_t empty_root = vsc_str_empty();
    vsc_str_t empty_path = vsc_str_empty();
    vsc_str_t empty_key = vsc_str_empty();
    vsc_str_t empty_identity = vsc_str_empty();
    vssc_http_request_t *reset_request =
            vssk_keyknox_client_make_request_reset(keyknox_client, empty_root, empty_path, empty_key, empty_identity);

    //
    //  Reset for user1.
    //
    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            reset_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *reset_response_1 = vssc_virgil_http_client_send(reset_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    vssk_keyknox_entry_t *reset_keyknox_entry_1 =
            vssk_keyknox_client_process_response_reset(reset_response_1, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(reset_keyknox_entry_1);

    //
    //  Reset for user2.
    //
    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            reset_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt2));

    vssc_http_response_t *reset_response_2 = vssc_virgil_http_client_send(reset_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    vssk_keyknox_entry_t *reset_keyknox_entry_2 =
            vssk_keyknox_client_process_response_reset(reset_response_2, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(reset_keyknox_entry_2);

    //
    //  Cleanup.
    //
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&reset_request);
    vssc_http_response_destroy(&reset_response_1);
    vssc_http_response_destroy(&reset_response_2);
    vssk_keyknox_entry_destroy(&reset_keyknox_entry_1);
    vssk_keyknox_entry_destroy(&reset_keyknox_entry_2);
}

void
test__set_admins__for_1_admin__can_modify_record_as_admin(void) {
    //
    //  Init.
    //
    const test_env_t *env = test_env_get();

    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_t identity2 = vssc_jwt_identity(env->jwt2);
    vsc_str_buffer_t *key_buf = create_random_key(env);
    vsc_str_t key = vsc_str_buffer_str(key_buf);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH5, key, identity);

    //
    //  Share Keyknox entry.
    //
    vssc_string_list_t *admins = vssc_string_list_new();
    vssc_string_list_add(admins, identity2);


    vssc_http_request_t *set_keyknox_admins_request = vssk_keyknox_client_make_request_set_admins(
            keyknox_client, test_data_ROOT, test_data_PATH5, admins, vsc_str_empty());
    TEST_ASSERT_NOT_NULL(set_keyknox_admins_request);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            set_keyknox_admins_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *set_keyknox_admins_response =
            vssc_virgil_http_client_send(set_keyknox_admins_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(set_keyknox_admins_response);

    //
    //  Push a new Keyknox entry as admin.
    //
    vsc_data_t original_entry_hash = vssk_keyknox_entry_hash(pushed_keyknox_entry);

    vssc_string_list_t *new_identities = vssc_string_list_new();
    vssc_string_list_add(new_identities, identity);
    vssc_string_list_add(new_identities, identity2);

    vssk_keyknox_entry_t *new_keyknox_entry = vssk_keyknox_entry_new_with_owner(identity, test_data_ROOT,
            test_data_PATH5, key, new_identities, test_data_META_2, test_data_VALUE_2, original_entry_hash);

    vssk_keyknox_entry_t *modified_keyknox_entry = push_new_keyknox_entry_ext(env, env->jwt2, new_keyknox_entry);

    //
    //  Pull the modified Keyknox entry from the original identity.
    //
    vssc_http_request_t *pull_keyknox_entry_request =
            vssk_keyknox_client_make_request_pull(keyknox_client, test_data_ROOT, test_data_PATH5, key, identity);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            pull_keyknox_entry_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *pull_keyknox_entry_response =
            vssc_virgil_http_client_send(pull_keyknox_entry_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(pull_keyknox_entry_response);

    vssk_keyknox_entry_t *pulled_keyknox_entry =
            vssk_keyknox_client_process_response_pull(pull_keyknox_entry_response, &keyknox_error);
    TEST_ASSERT_EQUAL(vssk_status_SUCCESS, keyknox_error.status);
    TEST_ASSERT_NOT_NULL(pulled_keyknox_entry);

    //
    //  Check fields.
    //
    test_assert_equal_keyknox_entry(identity, new_keyknox_entry, pulled_keyknox_entry);
    TEST_ASSERT_TRUE(vsc_data_is_valid_and_non_empty(vssk_keyknox_entry_hash(pulled_keyknox_entry)));

    //
    //  Cleanup.
    //
    vssc_string_list_destroy(&admins);
    vssc_string_list_destroy(&new_identities);
    vssk_keyknox_entry_destroy(&new_keyknox_entry);
    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
    vssk_keyknox_entry_destroy(&pulled_keyknox_entry);
    vssk_keyknox_entry_destroy(&modified_keyknox_entry);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&set_keyknox_admins_request);
    vssc_http_response_destroy(&set_keyknox_admins_response);
    vssc_http_request_destroy(&pull_keyknox_entry_request);
    vssc_http_response_destroy(&pull_keyknox_entry_response);
    vsc_str_buffer_destroy(&key_buf);
}

void
test__get_admins__with_1_admin__previously_added_admin_is_listed(void) {
    //
    //  Init.
    //
    const test_env_t *env = test_env_get();

    vssk_error_t keyknox_error;
    vssk_error_reset(&keyknox_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_keyknox_client_t *keyknox_client = vssk_keyknox_client_new_with_base_url(env->url);

    //
    //  Push Keyknox entry.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_t identity2 = vssc_jwt_identity(env->jwt2);
    vsc_str_buffer_t *key_buf = create_random_key(env);
    vsc_str_t key = vsc_str_buffer_str(key_buf);

    vssk_keyknox_entry_t *pushed_keyknox_entry =
            push_new_keyknox_entry(env, test_data_ROOT, test_data_PATH5, key, identity);

    //
    //  Share Keyknox entry.
    //
    vssc_string_list_t *admins = vssc_string_list_new();
    vssc_string_list_add(admins, identity2);


    vssc_http_request_t *set_keyknox_admins_request = vssk_keyknox_client_make_request_set_admins(
            keyknox_client, test_data_ROOT, test_data_PATH5, admins, vsc_str_empty());
    TEST_ASSERT_NOT_NULL(set_keyknox_admins_request);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            set_keyknox_admins_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *set_keyknox_admins_response =
            vssc_virgil_http_client_send(set_keyknox_admins_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(set_keyknox_admins_response);

    //
    //  List admins.
    //
    vssc_http_request_t *get_keyknox_admins_request =
            vssk_keyknox_client_make_request_get_admins(keyknox_client, test_data_ROOT, test_data_PATH5, identity);
    TEST_ASSERT_NOT_NULL(get_keyknox_admins_request);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            get_keyknox_admins_request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *get_keyknox_admins_response =
            vssc_virgil_http_client_send(get_keyknox_admins_request, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(get_keyknox_admins_response);

    //
    //  Check fields.
    //

    //
    //  Cleanup.
    //
    vssc_string_list_destroy(&admins);
    vssk_keyknox_entry_destroy(&pushed_keyknox_entry);
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&set_keyknox_admins_request);
    vssc_http_response_destroy(&set_keyknox_admins_response);
    vssc_http_request_destroy(&get_keyknox_admins_request);
    vssc_http_response_destroy(&get_keyknox_admins_response);
    vsc_str_buffer_destroy(&key_buf);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    const int env_load_status = test_env_load();
    if (env_load_status != 0) {
        return -1;
    }

    RUN_TEST(test__push__with_random_key_id__returns_expected_keyknox_entry);
    RUN_TEST(test__pull__pushed_entry__returns_expected_keyknox_entry);
    RUN_TEST(test__reset__pushed_entry_with_defined_root_and_path__returns_expected_keyknox_entry);
    RUN_TEST(test__get_keys__pushed_1_entry__returns_list_with_1_key);
    RUN_TEST(test__set_admins__for_1_admin__can_modify_record_as_admin);
    RUN_TEST(test__get_admins__with_1_admin__previously_added_admin_is_listed);
    RUN_TEST(test__reset__all_entries__success);

    test_env_release();
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
