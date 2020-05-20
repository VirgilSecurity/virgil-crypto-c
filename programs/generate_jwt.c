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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <virgil/crypto/foundation/vscf_base64.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/sdk/core/vssc_jwt_generator.h>
#include <virgil/sdk/core/vssc_base64_url.h>
#include <virgil/sdk/core/private/vssc_jwt_private.h>
#include <json-c/json.h>


const char k_error_msg_FAILED_TO_GENERATE_JWT[] = "Failed to generate JWT.";
const char k_error_msg_CRYPTO_INIT_FAILED[] = "Failed to initialize crypto engine.";
const char k_error_msg_IMPORT_APP_KEY_FAILED[] = "Failed import app key.";
const char k_error_msg_FAILED_TO_PARSE_ENV_FILE[] = "Env file is not a valid JSON.";
const char k_error_msg_format_FAILED_TO_OPEN_FILE[] = "File '%s' can not be opened.";
const char k_error_msg_format_FAILED_TO_READ_FILE[] = "File '%s' can not be read.";
const char k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING[] = "Env key '%s' is absent or not a string.";
const char k_error_msg_format_MISSING_ENV_KEY_OR_NOT_INT[] = "Env key '%s' is absent or not an integer.";


void print_help(const char* prog_name) {
    printf("USAGE:\n");
    printf("    %s <env_json> <identity>\n", prog_name);
    printf("OPTIONS:\n");
    printf("    <env_json> - path to env.json file with credentials\n"
           "    <identity> - to whom token will be issued\n"
           );
}

void print_error(const char* msg) {
    fprintf(stderr, "<ERROR>: %s\n", msg);
}

void print_formatted_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "<ERROR>: ");
    vfprintf(stderr, format, args );
    va_end(args);
    fprintf(stderr, "\n");
}

void
print_str(vsc_str_t str) {
    for (size_t i = 0; i < str.len; ++i) {
        fprintf(stdout, "%c", str.chars[i]);
    }
    fprintf(stdout, "\r\n");
}

void
print_data_as_str(vsc_data_t data) {
    print_str(vsc_str((const char *)data.bytes, data.len));
}


int main(int argc, const char *const *const argv) {

    const char* prog_name = argv[0] ? argv[0] : "generate_jwt";

    //
    //  Get args.
    //
    if (argc < 3) {
        print_help(prog_name);
        return -1;
    }

    const char *env_file_path = argv[1];
    const char *identity = argv[2];

    //
    //  Read env.json.
    //
    FILE* env_file = fopen(env_file_path, "r");
    if (NULL == env_file) {
        print_formatted_error(k_error_msg_format_FAILED_TO_OPEN_FILE, env_file_path);
        return -1;
    }

    fseek (env_file , 0 , SEEK_END);
    const size_t env_file_size = ftell(env_file);
    rewind(env_file);

    char *buffer = (char*)calloc(1, env_file_size);

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
    json_tokener *tokener = NULL;
    json_object *json_obj = NULL;

    vscf_impl_t *app_key = NULL;
    vssc_jwt_generator_t *jwt_generator = NULL;
    vssc_jwt_t *jwt = NULL;
    vsc_buffer_t *app_key_buf = NULL;
    vsc_buffer_t *tmp_buf = NULL;

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
    tokener = json_tokener_new();
    json_obj = json_tokener_parse_ex(tokener, buffer, read_size);

    if (NULL == json_obj) {
        print_error(k_error_msg_FAILED_TO_PARSE_ENV_FILE);
        goto fail;
    }

    //
    //  Get fields from the env.json.
    //
    json_object *app_id_obj = NULL;
    const bool is_app_id_exists = json_object_object_get_ex(json_obj, "app_id", &app_id_obj);
    if (!is_app_id_exists || !json_object_is_type(app_id_obj, json_type_string)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, "app_id");
        goto fail;
    }

    json_object *app_key_id_obj = NULL;
    const bool is_app_key_id_exists = json_object_object_get_ex(json_obj, "app_key_id", &app_key_id_obj);
    if (!is_app_key_id_exists || !json_object_is_type(app_key_id_obj, json_type_string)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, "app_key_id");
        goto fail;
    }

    json_object *app_key_obj = NULL;
    const bool is_app_key_exists = json_object_object_get_ex(json_obj, "app_key", &app_key_obj);
    if (!is_app_key_exists || !json_object_is_type(app_key_obj, json_type_string)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, "app_key");
        goto fail;
    }

    json_object *app_public_key_obj = NULL;
    const bool is_app_public_key_exists = json_object_object_get_ex(json_obj, "app_public_key", &app_public_key_obj);
    if (!is_app_public_key_exists || !json_object_is_type(app_public_key_obj, json_type_string)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_STRING, "app_public_key");
        goto fail;
    }

    json_object *ttl_obj = NULL;
    const bool is_ttl_exists = json_object_object_get_ex(json_obj, "ttl", &ttl_obj);
    if (is_ttl_exists && !json_object_is_type(ttl_obj, json_type_int)) {
        print_formatted_error(k_error_msg_format_MISSING_ENV_KEY_OR_NOT_INT, "ttl");
        goto fail;
    }

    //
    //  Import app key.
    //
    vsc_str_t app_id = vsc_str(json_object_get_string(app_id_obj), json_object_get_string_len(app_id_obj));
    vsc_str_t app_key_id = vsc_str(json_object_get_string(app_key_id_obj), json_object_get_string_len(app_key_id_obj));
    vsc_str_t app_key_b64 = vsc_str(json_object_get_string(app_key_obj), json_object_get_string_len(app_key_obj));
    vsc_str_t identity_str = vsc_str(identity, strlen(identity));

    const size_t app_key_buf_len = vscf_base64_decoded_len(app_key_b64.len);
    app_key_buf = vsc_buffer_new_with_capacity(app_key_buf_len);

    const vscf_status_t base64_status = vscf_base64_decode(vsc_str_as_data(app_key_b64), app_key_buf);
    if (base64_status != vscf_status_SUCCESS) {
        print_error(k_error_msg_IMPORT_APP_KEY_FAILED);
        goto fail;
    }

    app_key = vscf_key_provider_import_private_key(key_provider, vsc_buffer_data(app_key_buf), NULL);
    if (NULL == app_key) {
        print_error(k_error_msg_IMPORT_APP_KEY_FAILED);
        goto fail;
    }

    jwt_generator = vssc_jwt_generator_new_with_credentials(app_id, app_key_id, app_key);
    if (is_ttl_exists) {
        const size_t ttl = (size_t)json_object_get_int64(ttl_obj);
        vssc_jwt_generator_set_ttl(jwt_generator, ttl);
    }

    jwt = vssc_jwt_generator_generate_token(jwt_generator, identity_str, &error);
    if (vssc_error_has_error(&error)) {
        print_error(k_error_msg_FAILED_TO_GENERATE_JWT);
        goto fail;
    }

    print_str(vssc_jwt_as_string(jwt));


    tmp_buf = vsc_buffer_new_with_capacity(1024);

    if (vssc_base64_url_decode(vssc_jwt_get_header_string(jwt), tmp_buf) == vssc_status_SUCCESS) {
        fprintf(stdout, "\n----- HEADER -----\n");
        print_data_as_str(vsc_buffer_data(tmp_buf));
        vsc_buffer_reset(tmp_buf);
    }

    if (vssc_base64_url_decode(vssc_jwt_get_payload_string(jwt), tmp_buf) == vssc_status_SUCCESS) {
        fprintf(stdout, "\n----- PAYLOAD -----\n");
        print_data_as_str(vsc_buffer_data(tmp_buf));
        vsc_buffer_reset(tmp_buf);
    }

fail:
    vscf_key_provider_destroy(&key_provider);
    vssc_jwt_generator_destroy(&jwt_generator);
    vssc_jwt_destroy(&jwt);
    vscf_impl_destroy(&app_key);
    vsc_buffer_destroy(&app_key_buf);
    vsc_buffer_destroy(&tmp_buf);
    free(buffer);

    if (tokener) {
        json_tokener_free(tokener);
    }

    if (json_obj) {
        json_object_put(json_obj);
    }

    return 0;
}
