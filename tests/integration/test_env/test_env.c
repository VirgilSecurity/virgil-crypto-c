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


#include "test_env.h"

#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/common/vsc_memory.h>

#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/private/vscf_atomic.h>

#include <virgil/sdk/core/vssc_json_object.h>
#include <virgil/sdk/core/vssc_jwt_generator.h>

#include <stdio.h>
#include <stdarg.h>

//
//  Inner context type.
//
typedef struct {
    vsc_str_mutable_t url;
    vsc_str_mutable_t app_id;
    vsc_str_mutable_t app_key_id;
    vsc_buffer_t *app_key_buf;
    vsc_buffer_t *app_public_key_buf;
    vsc_buffer_t *virgil_public_key_buf;
    vscf_impl_t *app_key;
    vscf_impl_t *app_public_key;
    vscf_impl_t *virgil_public_key;
    vssc_jwt_t *jwt;
    size_t refcnt;
} test_env_inner_t;

//
//  Global context.
//
static test_env_inner_t g_env_inner;
static test_env_t g_env;


//
//  Error messages.
//
const char k_error_msg_CRYPTO_INIT_FAILED[] = "Failed to initialize crypto engine.";
const char k_error_msg_IMPORT_APP_KEY_FAILED[] = "Failed to import app key.";
const char k_error_msg_IMPORT_APP_PUBLIC_KEY_FAILED[] = "Failed to import app public key.";
const char k_error_msg_IMPORT_VIRGIL_PUBLIC_KEY_FAILED[] = "Failed to import Virgil public key.";
const char k_error_msg_FAILED_TO_PARSE_ENV_FILE[] = "Env file is not a valid JSON.";
const char k_error_msg_FAILED_TO_GENERATE_JWT[] = "Failed to generate JWT.";
const char k_error_msg_format_FAILED_TO_OPEN_FILE[] = "File '%s' can not be opened.";
const char k_error_msg_format_FAILED_TO_READ_FILE[] = "File '%s' can not be read.";
const char k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING[] = "Env key '%s' is absent or not a string.";
const char k_error_msg_format_MISSING_ENV_KEY_OR_NOT_OBJECT[] = "Env key '%s' is absent or not an object.";

//
//  Json keys.
//
const char k_json_key_URL_CHARS[] = "url";
const vsc_str_t k_json_key_URL = {k_json_key_URL_CHARS, sizeof(k_json_key_URL_CHARS) - 1};

const char k_json_key_APP_ID_CHARS[] = "app_id";
const vsc_str_t k_json_key_APP_ID = {k_json_key_APP_ID_CHARS, sizeof(k_json_key_APP_ID_CHARS) - 1};

const char k_json_key_APP_KEY_ID_CHARS[] = "app_key_id";
const vsc_str_t k_json_key_APP_KEY_ID = {k_json_key_APP_KEY_ID_CHARS, sizeof(k_json_key_APP_KEY_ID_CHARS) - 1};

const char k_json_key_APP_KEY_CHARS[] = "app_key";
const vsc_str_t k_json_key_APP_KEY = {k_json_key_APP_KEY_CHARS, sizeof(k_json_key_APP_KEY_CHARS) - 1};

const char k_json_key_APP_PUBLIC_KEY_CHARS[] = "app_public_key";
const vsc_str_t k_json_key_APP_PUBLIC_KEY = {
        k_json_key_APP_PUBLIC_KEY_CHARS, sizeof(k_json_key_APP_PUBLIC_KEY_CHARS) - 1};

const char k_json_key_VIRGIL_PUBLIC_KEY_CHARS[] = "virgil_public_key";
const vsc_str_t k_json_key_VIRGIL_PUBLIC_KEY = {
        k_json_key_VIRGIL_PUBLIC_KEY_CHARS, sizeof(k_json_key_VIRGIL_PUBLIC_KEY_CHARS) - 1};

const vsc_str_t k_json_key_ENV = {VIRGIL_INTEGRATION_ENV, strlen(VIRGIL_INTEGRATION_ENV)};

const char k_jwt_IDENTITY_CHARS[] = "test_user";
const vsc_str_t k_jwt_IDENTITY = {k_jwt_IDENTITY_CHARS, sizeof(k_jwt_IDENTITY_CHARS) - 1};

//
//  Print error message.
//
void
print_error(const char *msg) {
    fprintf(stderr, "<ERROR>: %s\n", msg);
}

//
//  Print formatted error message.
//
void
print_formatted_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "<ERROR>: ");
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

//
//  Load test environment.
//
int
test_env_load(void) {
    //
    //  Read env.json.
    //
    const char *env_file_path = VIRGIL_INTEGRATION_ENV_FILE;

    FILE *env_file = fopen(env_file_path, "r");
    if (NULL == env_file) {
        print_formatted_error(k_error_msg_format_FAILED_TO_OPEN_FILE, env_file_path);
        return -1;
    }

    fseek(env_file, 0, SEEK_END);
    const size_t env_file_size = ftell(env_file);
    rewind(env_file);

    char *buffer = (char *)calloc(1, env_file_size);

    const size_t read_size = fread(buffer, 1, env_file_size, env_file);
    fclose(env_file);
    env_file = NULL;

    if (read_size != env_file_size) {
        print_formatted_error(k_error_msg_format_FAILED_TO_READ_FILE, env_file_path);
        free(buffer);
        return -1;
    }

    //
    //  Prepare var before goto.
    //
    vssc_json_object_t *root_json = NULL;
    vssc_json_object_t *env_json = NULL;

    vsc_buffer_t *app_key_buf = NULL;
    vsc_buffer_t *app_public_key_buf = NULL;
    vsc_buffer_t *virgil_public_key_buf = NULL;

    vscf_impl_t *app_key = NULL;
    vscf_impl_t *app_public_key = NULL;
    vscf_impl_t *virgil_public_key = NULL;

    vssc_jwt_generator_t *jwt_generator = NULL;
    vssc_jwt_t *jwt = NULL;

    //
    //  Init crypto engine.
    //
    vssc_error_t error;
    vssc_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    const vscf_status_t init_status = vscf_key_provider_setup_defaults(key_provider);

    if (init_status != vscf_status_SUCCESS) {
        print_error(k_error_msg_CRYPTO_INIT_FAILED);
        goto fail;
    }

    //
    //  Parse env.json.
    //
    root_json = vssc_json_object_parse(vsc_str(buffer, read_size), &error);
    if (NULL == root_json) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_OBJECT, k_json_key_ENV.chars);
        goto fail;
    }

    //
    //  Get fields from the env.json.
    //
    env_json = vssc_json_object_get_object_value(root_json, k_json_key_ENV, &error);
    if (NULL == env_json) {
        print_error(k_error_msg_FAILED_TO_PARSE_ENV_FILE);
        goto fail;
    }

    vsc_str_t url = vssc_json_object_get_string_value(env_json, k_json_key_URL, &error);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_URL_CHARS);
        goto fail;
    }

    vsc_str_t app_id = vssc_json_object_get_string_value(env_json, k_json_key_APP_ID, &error);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_ID_CHARS);
        goto fail;
    }

    vsc_str_t app_key_id = vssc_json_object_get_string_value(env_json, k_json_key_APP_KEY_ID, &error);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_KEY_ID_CHARS);
        goto fail;
    }

    const size_t app_key_buf_len = vssc_json_object_get_binary_value_len(env_json, k_json_key_APP_KEY);
    if (app_key_buf_len == 0) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_KEY_CHARS);
        goto fail;
    }

    app_key_buf = vsc_buffer_new_with_capacity(app_key_buf_len);
    error.status = vssc_json_object_get_binary_value(env_json, k_json_key_APP_KEY, app_key_buf);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_KEY_CHARS);
        goto fail;
    }

    const size_t app_public_key_buf_len = vssc_json_object_get_binary_value_len(env_json, k_json_key_APP_PUBLIC_KEY);
    if (app_public_key_buf_len == 0) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_PUBLIC_KEY_CHARS);
        goto fail;
    }

    app_public_key_buf = vsc_buffer_new_with_capacity(app_public_key_buf_len);
    error.status = vssc_json_object_get_binary_value(env_json, k_json_key_APP_PUBLIC_KEY, app_public_key_buf);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_APP_PUBLIC_KEY_CHARS);
        goto fail;
    }

    const size_t virgil_public_key_buf_len =
            vssc_json_object_get_binary_value_len(env_json, k_json_key_VIRGIL_PUBLIC_KEY);
    if (virgil_public_key_buf_len == 0) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_VIRGIL_PUBLIC_KEY_CHARS);
        goto fail;
    }

    virgil_public_key_buf = vsc_buffer_new_with_capacity(virgil_public_key_buf_len);
    error.status = vssc_json_object_get_binary_value(env_json, k_json_key_VIRGIL_PUBLIC_KEY, virgil_public_key_buf);
    if (vssc_error_has_error(&error)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, k_json_key_VIRGIL_PUBLIC_KEY_CHARS);
        goto fail;
    }


    //
    //  Import keys.
    //
    app_key = vscf_key_provider_import_private_key(key_provider, vsc_buffer_data(app_key_buf), NULL);
    if (NULL == app_key) {
        print_error(k_error_msg_IMPORT_APP_KEY_FAILED);
        goto fail;
    }

    app_public_key = vscf_key_provider_import_public_key(key_provider, vsc_buffer_data(app_public_key_buf), NULL);
    if (NULL == app_public_key) {
        print_error(k_error_msg_IMPORT_APP_PUBLIC_KEY_FAILED);
        goto fail;
    }

    virgil_public_key = vscf_key_provider_import_public_key(key_provider, vsc_buffer_data(virgil_public_key_buf), NULL);
    if (NULL == virgil_public_key) {
        print_error(k_error_msg_IMPORT_VIRGIL_PUBLIC_KEY_FAILED);
        goto fail;
    }


    //
    //  Generate jwt.
    //
    jwt_generator = vssc_jwt_generator_new_with_credentials(app_id, app_key_id, app_key);

    jwt = vssc_jwt_generator_generate_token(jwt_generator, k_jwt_IDENTITY, &error);
    if (vssc_error_has_error(&error)) {
        print_error(k_error_msg_FAILED_TO_GENERATE_JWT);
        goto fail;
    }


    //
    //  Pass to the env object.
    //
    g_env_inner.url = vsc_str_mutable_from_str(url);
    g_env_inner.app_id = vsc_str_mutable_from_str(app_id);
    g_env_inner.app_key_id = vsc_str_mutable_from_str(app_key_id);
    g_env_inner.app_key_buf = app_key_buf;
    g_env_inner.app_public_key_buf = app_public_key_buf;
    g_env_inner.virgil_public_key_buf = virgil_public_key_buf;
    g_env_inner.app_key = app_key;
    g_env_inner.app_public_key = app_public_key;
    g_env_inner.virgil_public_key = virgil_public_key;
    g_env_inner.jwt = jwt;

    g_env.url = vsc_str_mutable_as_str(g_env_inner.url);
    g_env.app_id = vsc_str_mutable_as_str(g_env_inner.app_id);
    g_env.app_key_id = vsc_str_mutable_as_str(g_env_inner.app_key_id);
    g_env.app_key_data = vsc_buffer_data(g_env_inner.app_key_buf);
    g_env.app_public_key_data = vsc_buffer_data(g_env_inner.app_public_key_buf);
    g_env.virgil_public_key_data = vsc_buffer_data(g_env_inner.virgil_public_key_buf);
    g_env.app_key = g_env_inner.app_key;
    g_env.app_public_key = g_env_inner.app_public_key;
    g_env.virgil_public_key = g_env_inner.virgil_public_key;
    g_env.jwt = g_env_inner.jwt;
    g_env.inner = &g_env_inner;

    vssc_json_object_destroy(&root_json);
    vssc_json_object_destroy(&env_json);

    vssc_jwt_generator_destroy(&jwt_generator);

    return 0;

fail:
    vssc_json_object_destroy(&root_json);
    vssc_json_object_destroy(&env_json);

    vssc_jwt_generator_destroy(&jwt_generator);
    vssc_jwt_destroy(&jwt);

    vsc_buffer_destroy(&app_key_buf);
    vsc_buffer_destroy(&app_public_key_buf);
    vsc_buffer_destroy(&virgil_public_key_buf);

    vscf_impl_destroy(&app_key);
    vscf_impl_destroy(&app_public_key);
    vscf_impl_destroy(&virgil_public_key);

    return -1;
}

//
//  Release test environment.
//
void
test_env_release(void) {
    vsc_str_mutable_release(&g_env_inner.url);
    vsc_str_mutable_release(&g_env_inner.app_id);
    vsc_str_mutable_release(&g_env_inner.app_key_id);
    vsc_buffer_destroy(&g_env_inner.app_key_buf);
    vsc_buffer_destroy(&g_env_inner.app_public_key_buf);
    vsc_buffer_destroy(&g_env_inner.virgil_public_key_buf);
    vscf_impl_destroy(&g_env_inner.app_key);
    vscf_impl_destroy(&g_env_inner.app_public_key);
    vscf_impl_destroy(&g_env_inner.virgil_public_key);
    vssc_jwt_destroy(&g_env_inner.jwt);

    vsc_zeroize(&g_env_inner, sizeof(test_env_inner_t));
    vsc_zeroize(&g_env, sizeof(test_env_t));
}

//
//  Return loaded test environment.
//
const test_env_t *
test_env_get(void) {
    return &g_env;
}
