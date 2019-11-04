//
// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>
#include "vsce_assert.h"
#include "vsce_phe_php.h"
#include "vscf_foundation_php.h"
#include "vsce_phe_common.h"
#include "vsce_phe_server.h"
#include "vsce_phe_client.h"
#include "vsce_phe_cipher.h"

#define VSCE_HANDLE_STATUS(status) do { if(status != vsce_status_SUCCESS) { vsce_handle_throw_exception(status); } } while (false)

void
vsce_handle_throw_exception(vsce_status_t status) {
    switch(status) {

    case vsce_status_ERROR_INVALID_SUCCESS_PROOF:
        zend_throw_exception(NULL, "VSCE: Success proof check failed.", -1);
        break;
    case vsce_status_ERROR_INVALID_FAIL_PROOF:
        zend_throw_exception(NULL, "VSCE: Failure proof check failed.", -2);
        break;
    case vsce_status_ERROR_RNG_FAILED:
        zend_throw_exception(NULL, "VSCE: RNG returned error.", -3);
        break;
    case vsce_status_ERROR_PROTOBUF_DECODE_FAILED:
        zend_throw_exception(NULL, "VSCE: Protobuf decode failed.", -4);
        break;
    case vsce_status_ERROR_INVALID_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCE: Invalid public key.", -5);
        break;
    case vsce_status_ERROR_INVALID_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCE: Invalid private key.", -6);
        break;
    case vsce_status_ERROR_AES_FAILED:
        zend_throw_exception(NULL, "VSCE: AES error occurred.", -7);
        break;
    }
}

//
// Constants
//
const char VSCE_PHE_PHP_VERSION[] = "0.11.1";
const char VSCE_PHE_PHP_EXTNAME[] = "vsce_phe_php";
const char vsce_phe_server_t_php_res_name[] = "vsce_phe_server_t";
const char vsce_phe_client_t_php_res_name[] = "vsce_phe_client_t";
const char vsce_phe_cipher_t_php_res_name[] = "vsce_phe_cipher_t";

//
// Registered resources
//
int le_vsce_phe_server_t;
int le_vsce_phe_client_t;
int le_vsce_phe_cipher_t;

//
// Extension init functions declaration
//
PHP_MINIT_FUNCTION(vsce_phe_php);
PHP_MSHUTDOWN_FUNCTION(vsce_phe_php);

//
// Functions wrapping
//
//
// Wrap method: vsce_phe_server_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_server_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_new_php) {
    vsce_phe_server_t *phe_server = vsce_phe_server_new();
    zend_resource *phe_server_res = zend_register_resource(phe_server, le_vsce_phe_server_t);
    RETVAL_RES(phe_server_res);
}

//
// Wrap method: vsce_phe_server_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_server_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name,
    le_vsce_phe_server_t);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vsce_phe_server_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_server_setup_defaults(phe_server);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);
}

//
// Wrap method: vsce_phe_server_generate_server_key_pair
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_generate_server_key_pair_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_generate_server_key_pair_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);

    //
    // Allocate output buffer for output 'server_private_key'
    //
    zend_string *out_server_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *server_private_key = vsc_buffer_new();
    vsc_buffer_use(server_private_key, (byte *)ZSTR_VAL(out_server_private_key), ZSTR_LEN(out_server_private_key));

    //
    // Allocate output buffer for output 'server_public_key'
    //
    zend_string *out_server_public_key = zend_string_alloc(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH, 0);
    vsc_buffer_t *server_public_key = vsc_buffer_new();
    vsc_buffer_use(server_public_key, (byte *)ZSTR_VAL(out_server_public_key), ZSTR_LEN(out_server_public_key));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_server_generate_server_key_pair(phe_server, server_private_key, server_public_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_server_private_key) = vsc_buffer_len(server_private_key);
    ZSTR_LEN(out_server_public_key) = vsc_buffer_len(server_public_key);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_server_private_key);
        add_next_index_str(return_value, out_server_public_key);
        vsc_buffer_destroy(&server_private_key);
        vsc_buffer_destroy(&server_public_key);
    }
    else {
        zend_string_free(out_server_private_key);
        zend_string_free(out_server_public_key);
    }
}

//
// Wrap method: vsce_phe_server_enrollment_response_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_enrollment_response_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_enrollment_response_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);

    //
    // Call main function
    //
    size_t res =vsce_phe_server_enrollment_response_len(phe_server);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_server_get_enrollment
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_get_enrollment_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_public_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_get_enrollment_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_server_private_key = NULL;
    size_t in_server_private_key_len = 0;
    char *in_server_public_key = NULL;
    size_t in_server_public_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_server_private_key, in_server_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_server_public_key, in_server_public_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);
    vsc_data_t server_private_key = vsc_data((const byte*)in_server_private_key, in_server_private_key_len);
    vsc_data_t server_public_key = vsc_data((const byte*)in_server_public_key, in_server_public_key_len);

    //
    // Allocate output buffer for output 'enrollment_response'
    //
    zend_string *out_enrollment_response = zend_string_alloc(vsce_phe_server_enrollment_response_len(phe_server), 0);
    vsc_buffer_t *enrollment_response = vsc_buffer_new();
    vsc_buffer_use(enrollment_response, (byte *)ZSTR_VAL(out_enrollment_response), ZSTR_LEN(out_enrollment_response));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_server_get_enrollment(phe_server, server_private_key, server_public_key, enrollment_response);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_enrollment_response) = vsc_buffer_len(enrollment_response);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_enrollment_response);
        vsc_buffer_destroy(&enrollment_response);
    }
    else {
        zend_string_free(out_enrollment_response);
    }
}

//
// Wrap method: vsce_phe_server_verify_password_response_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_verify_password_response_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_verify_password_response_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);

    //
    // Call main function
    //
    size_t res =vsce_phe_server_verify_password_response_len(phe_server);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_server_verify_password
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_verify_password_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_public_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_verify_password_request, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_verify_password_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_server_private_key = NULL;
    size_t in_server_private_key_len = 0;
    char *in_server_public_key = NULL;
    size_t in_server_public_key_len = 0;
    char *in_verify_password_request = NULL;
    size_t in_verify_password_request_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_server_private_key, in_server_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_server_public_key, in_server_public_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_verify_password_request, in_verify_password_request_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);
    vsc_data_t server_private_key = vsc_data((const byte*)in_server_private_key, in_server_private_key_len);
    vsc_data_t server_public_key = vsc_data((const byte*)in_server_public_key, in_server_public_key_len);
    vsc_data_t verify_password_request = vsc_data((const byte*)in_verify_password_request, in_verify_password_request_len);

    //
    // Allocate output buffer for output 'verify_password_response'
    //
    zend_string *out_verify_password_response = zend_string_alloc(vsce_phe_server_verify_password_response_len(phe_server), 0);
    vsc_buffer_t *verify_password_response = vsc_buffer_new();
    vsc_buffer_use(verify_password_response, (byte *)ZSTR_VAL(out_verify_password_response), ZSTR_LEN(out_verify_password_response));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_server_verify_password(phe_server, server_private_key, server_public_key, verify_password_request, verify_password_response);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_verify_password_response) = vsc_buffer_len(verify_password_response);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_verify_password_response);
        vsc_buffer_destroy(&verify_password_response);
    }
    else {
        zend_string_free(out_verify_password_response);
    }
}

//
// Wrap method: vsce_phe_server_update_token_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_update_token_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_update_token_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);

    //
    // Call main function
    //
    size_t res =vsce_phe_server_update_token_len(phe_server);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_server_rotate_keys
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_rotate_keys_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_private_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_rotate_keys_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_server_private_key = NULL;
    size_t in_server_private_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_server_private_key, in_server_private_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);
    vsc_data_t server_private_key = vsc_data((const byte*)in_server_private_key, in_server_private_key_len);

    //
    // Allocate output buffer for output 'new_server_private_key'
    //
    zend_string *out_new_server_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *new_server_private_key = vsc_buffer_new();
    vsc_buffer_use(new_server_private_key, (byte *)ZSTR_VAL(out_new_server_private_key), ZSTR_LEN(out_new_server_private_key));

    //
    // Allocate output buffer for output 'new_server_public_key'
    //
    zend_string *out_new_server_public_key = zend_string_alloc(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH, 0);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new();
    vsc_buffer_use(new_server_public_key, (byte *)ZSTR_VAL(out_new_server_public_key), ZSTR_LEN(out_new_server_public_key));

    //
    // Allocate output buffer for output 'update_token'
    //
    zend_string *out_update_token = zend_string_alloc(vsce_phe_server_update_token_len(phe_server), 0);
    vsc_buffer_t *update_token = vsc_buffer_new();
    vsc_buffer_use(update_token, (byte *)ZSTR_VAL(out_update_token), ZSTR_LEN(out_update_token));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_server_rotate_keys(phe_server, server_private_key, new_server_private_key, new_server_public_key, update_token);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_new_server_private_key) = vsc_buffer_len(new_server_private_key);
    ZSTR_LEN(out_new_server_public_key) = vsc_buffer_len(new_server_public_key);
    ZSTR_LEN(out_update_token) = vsc_buffer_len(update_token);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_new_server_private_key);
        add_next_index_str(return_value, out_new_server_public_key);
        add_next_index_str(return_value, out_update_token);
        vsc_buffer_destroy(&new_server_private_key);
        vsc_buffer_destroy(&new_server_public_key);
        vsc_buffer_destroy(&update_token);
    }
    else {
        zend_string_free(out_new_server_private_key);
        zend_string_free(out_new_server_public_key);
        zend_string_free(out_update_token);
    }
}

//
// Wrap method: vsce_phe_server_use_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_use_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_random, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_use_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_random = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_random, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);
    vscf_impl_t *random = zend_fetch_resource_ex(in_random, vscf_impl_t_php_res_name, le_vscf_impl_t);

    //
    // Call main function
    //
    vsce_phe_server_use_random(phe_server, random);
}

//
// Wrap method: vsce_phe_server_use_operation_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_server_use_operation_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_operation_random, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_server_use_operation_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_operation_random = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_operation_random, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_server_t *phe_server = zend_fetch_resource_ex(in_ctx, vsce_phe_server_t_php_res_name, le_vsce_phe_server_t);
    vscf_impl_t *operation_random = zend_fetch_resource_ex(in_operation_random, vscf_impl_t_php_res_name, le_vscf_impl_t);

    //
    // Call main function
    //
    vsce_phe_server_use_operation_random(phe_server, operation_random);
}

//
// Wrap method: vsce_phe_client_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_new_php) {
    vsce_phe_client_t *phe_client = vsce_phe_client_new();
    zend_resource *phe_client_res = zend_register_resource(phe_client, le_vsce_phe_client_t);
    RETVAL_RES(phe_client_res);
}

//
// Wrap method: vsce_phe_client_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name,
    le_vsce_phe_client_t);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vsce_phe_client_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_setup_defaults(phe_client);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);
}

//
// Wrap method: vsce_phe_client_set_keys
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_set_keys_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_client_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_server_public_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_set_keys_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_client_private_key = NULL;
    size_t in_client_private_key_len = 0;
    char *in_server_public_key = NULL;
    size_t in_server_public_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_client_private_key, in_client_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_server_public_key, in_server_public_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t client_private_key = vsc_data((const byte*)in_client_private_key, in_client_private_key_len);
    vsc_data_t server_public_key = vsc_data((const byte*)in_server_public_key, in_server_public_key_len);

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_set_keys(phe_client, client_private_key, server_public_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);
}

//
// Wrap method: vsce_phe_client_generate_client_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_generate_client_private_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_generate_client_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);

    //
    // Allocate output buffer for output 'client_private_key'
    //
    zend_string *out_client_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *client_private_key = vsc_buffer_new();
    vsc_buffer_use(client_private_key, (byte *)ZSTR_VAL(out_client_private_key), ZSTR_LEN(out_client_private_key));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_generate_client_private_key(phe_client, client_private_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_client_private_key) = vsc_buffer_len(client_private_key);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_client_private_key);
        vsc_buffer_destroy(&client_private_key);
    }
    else {
        zend_string_free(out_client_private_key);
    }
}

//
// Wrap method: vsce_phe_client_enrollment_record_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_enrollment_record_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_enrollment_record_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);

    //
    // Call main function
    //
    size_t res =vsce_phe_client_enrollment_record_len(phe_client);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_client_enroll_account
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_enroll_account_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_enrollment_response, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_enroll_account_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_enrollment_response = NULL;
    size_t in_enrollment_response_len = 0;
    char *in_password = NULL;
    size_t in_password_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_enrollment_response, in_enrollment_response_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t enrollment_response = vsc_data((const byte*)in_enrollment_response, in_enrollment_response_len);
    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);

    //
    // Allocate output buffer for output 'enrollment_record'
    //
    zend_string *out_enrollment_record = zend_string_alloc(vsce_phe_client_enrollment_record_len(phe_client), 0);
    vsc_buffer_t *enrollment_record = vsc_buffer_new();
    vsc_buffer_use(enrollment_record, (byte *)ZSTR_VAL(out_enrollment_record), ZSTR_LEN(out_enrollment_record));

    //
    // Allocate output buffer for output 'account_key'
    //
    zend_string *out_account_key = zend_string_alloc(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, 0);
    vsc_buffer_t *account_key = vsc_buffer_new();
    vsc_buffer_use(account_key, (byte *)ZSTR_VAL(out_account_key), ZSTR_LEN(out_account_key));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_enroll_account(phe_client, enrollment_response, password, enrollment_record, account_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_enrollment_record) = vsc_buffer_len(enrollment_record);
    ZSTR_LEN(out_account_key) = vsc_buffer_len(account_key);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_enrollment_record);
        add_next_index_str(return_value, out_account_key);
        vsc_buffer_destroy(&enrollment_record);
        vsc_buffer_destroy(&account_key);
    }
    else {
        zend_string_free(out_enrollment_record);
        zend_string_free(out_account_key);
    }
}

//
// Wrap method: vsce_phe_client_verify_password_request_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_verify_password_request_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_verify_password_request_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);

    //
    // Call main function
    //
    size_t res =vsce_phe_client_verify_password_request_len(phe_client);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_client_create_verify_password_request
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_create_verify_password_request_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_enrollment_record, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_create_verify_password_request_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);
    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);

    //
    // Allocate output buffer for output 'verify_password_request'
    //
    zend_string *out_verify_password_request = zend_string_alloc(vsce_phe_client_verify_password_request_len(phe_client), 0);
    vsc_buffer_t *verify_password_request = vsc_buffer_new();
    vsc_buffer_use(verify_password_request, (byte *)ZSTR_VAL(out_verify_password_request), ZSTR_LEN(out_verify_password_request));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_create_verify_password_request(phe_client, password, enrollment_record, verify_password_request);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_verify_password_request) = vsc_buffer_len(verify_password_request);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_verify_password_request);
        vsc_buffer_destroy(&verify_password_request);
    }
    else {
        zend_string_free(out_verify_password_request);
    }
}

//
// Wrap method: vsce_phe_client_check_response_and_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_check_response_and_decrypt_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_enrollment_record, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_verify_password_response, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_check_response_and_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;
    char *in_verify_password_response = NULL;
    size_t in_verify_password_response_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_verify_password_response, in_verify_password_response_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);
    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);
    vsc_data_t verify_password_response = vsc_data((const byte*)in_verify_password_response, in_verify_password_response_len);

    //
    // Allocate output buffer for output 'account_key'
    //
    zend_string *out_account_key = zend_string_alloc(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, 0);
    vsc_buffer_t *account_key = vsc_buffer_new();
    vsc_buffer_use(account_key, (byte *)ZSTR_VAL(out_account_key), ZSTR_LEN(out_account_key));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_check_response_and_decrypt(phe_client, password, enrollment_record, verify_password_response, account_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_account_key) = vsc_buffer_len(account_key);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_account_key);
        vsc_buffer_destroy(&account_key);
    }
    else {
        zend_string_free(out_account_key);
    }
}

//
// Wrap method: vsce_phe_client_rotate_keys
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_rotate_keys_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_update_token, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_rotate_keys_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_update_token = NULL;
    size_t in_update_token_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_update_token, in_update_token_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t update_token = vsc_data((const byte*)in_update_token, in_update_token_len);

    //
    // Allocate output buffer for output 'new_client_private_key'
    //
    zend_string *out_new_client_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *new_client_private_key = vsc_buffer_new();
    vsc_buffer_use(new_client_private_key, (byte *)ZSTR_VAL(out_new_client_private_key), ZSTR_LEN(out_new_client_private_key));

    //
    // Allocate output buffer for output 'new_server_public_key'
    //
    zend_string *out_new_server_public_key = zend_string_alloc(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH, 0);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new();
    vsc_buffer_use(new_server_public_key, (byte *)ZSTR_VAL(out_new_server_public_key), ZSTR_LEN(out_new_server_public_key));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_rotate_keys(phe_client, update_token, new_client_private_key, new_server_public_key);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_new_client_private_key) = vsc_buffer_len(new_client_private_key);
    ZSTR_LEN(out_new_server_public_key) = vsc_buffer_len(new_server_public_key);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_new_client_private_key);
        add_next_index_str(return_value, out_new_server_public_key);
        vsc_buffer_destroy(&new_client_private_key);
        vsc_buffer_destroy(&new_server_public_key);
    }
    else {
        zend_string_free(out_new_client_private_key);
        zend_string_free(out_new_server_public_key);
    }
}

//
// Wrap method: vsce_phe_client_update_enrollment_record
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_update_enrollment_record_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_enrollment_record, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_update_token, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_update_enrollment_record_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;
    char *in_update_token = NULL;
    size_t in_update_token_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_update_token, in_update_token_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);
    vsc_data_t update_token = vsc_data((const byte*)in_update_token, in_update_token_len);

    //
    // Allocate output buffer for output 'new_enrollment_record'
    //
    zend_string *out_new_enrollment_record = zend_string_alloc(vsce_phe_client_enrollment_record_len(phe_client), 0);
    vsc_buffer_t *new_enrollment_record = vsc_buffer_new();
    vsc_buffer_use(new_enrollment_record, (byte *)ZSTR_VAL(out_new_enrollment_record), ZSTR_LEN(out_new_enrollment_record));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_client_update_enrollment_record(phe_client, enrollment_record, update_token, new_enrollment_record);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_new_enrollment_record) = vsc_buffer_len(new_enrollment_record);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_new_enrollment_record);
        vsc_buffer_destroy(&new_enrollment_record);
    }
    else {
        zend_string_free(out_new_enrollment_record);
    }
}

//
// Wrap method: vsce_phe_client_use_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_use_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_random, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_use_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_random = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_random, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vscf_impl_t *random = zend_fetch_resource_ex(in_random, vscf_impl_t_php_res_name, le_vscf_impl_t);

    //
    // Call main function
    //
    vsce_phe_client_use_random(phe_client, random);
}

//
// Wrap method: vsce_phe_client_use_operation_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_client_use_operation_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_operation_random, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_use_operation_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_operation_random = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_operation_random, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_ctx, vsce_phe_client_t_php_res_name, le_vsce_phe_client_t);
    vscf_impl_t *operation_random = zend_fetch_resource_ex(in_operation_random, vscf_impl_t_php_res_name, le_vscf_impl_t);

    //
    // Call main function
    //
    vsce_phe_client_use_operation_random(phe_client, operation_random);
}

//
// Wrap method: vsce_phe_cipher_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_cipher_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_new_php) {
    vsce_phe_cipher_t *phe_cipher = vsce_phe_cipher_new();
    zend_resource *phe_cipher_res = zend_register_resource(phe_cipher, le_vsce_phe_cipher_t);
    RETVAL_RES(phe_cipher_res);
}

//
// Wrap method: vsce_phe_cipher_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_cipher_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name,
    le_vsce_phe_cipher_t);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vsce_phe_cipher_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_cipher_setup_defaults(phe_cipher);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);
}

//
// Wrap method: vsce_phe_cipher_encrypt_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_encrypt_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_encrypt_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_plain_text_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_plain_text_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    size_t plain_text_len = in_plain_text_len;

    //
    // Call main function
    //
    size_t res =vsce_phe_cipher_encrypt_len(phe_cipher, plain_text_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_cipher_decrypt_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_decrypt_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_cipher_text_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_decrypt_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_cipher_text_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_cipher_text_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    size_t cipher_text_len = in_cipher_text_len;

    //
    // Call main function
    //
    size_t res =vsce_phe_cipher_decrypt_len(phe_cipher, cipher_text_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vsce_phe_cipher_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_account_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_plain_text = NULL;
    size_t in_plain_text_len = 0;
    char *in_account_key = NULL;
    size_t in_account_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_plain_text, in_plain_text_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_account_key, in_account_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    vsc_data_t plain_text = vsc_data((const byte*)in_plain_text, in_plain_text_len);
    vsc_data_t account_key = vsc_data((const byte*)in_account_key, in_account_key_len);

    //
    // Allocate output buffer for output 'cipher_text'
    //
    zend_string *out_cipher_text = zend_string_alloc(vsce_phe_cipher_encrypt_len(phe_cipher, plain_text.len), 0);
    vsc_buffer_t *cipher_text = vsc_buffer_new();
    vsc_buffer_use(cipher_text, (byte *)ZSTR_VAL(out_cipher_text), ZSTR_LEN(out_cipher_text));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_cipher_encrypt(phe_cipher, plain_text, account_key, cipher_text);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_cipher_text) = vsc_buffer_len(cipher_text);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_cipher_text);
        vsc_buffer_destroy(&cipher_text);
    }
    else {
        zend_string_free(out_cipher_text);
    }
}

//
// Wrap method: vsce_phe_cipher_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_cipher_text, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_account_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_cipher_text = NULL;
    size_t in_cipher_text_len = 0;
    char *in_account_key = NULL;
    size_t in_account_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_cipher_text, in_cipher_text_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_account_key, in_account_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    vsc_data_t cipher_text = vsc_data((const byte*)in_cipher_text, in_cipher_text_len);
    vsc_data_t account_key = vsc_data((const byte*)in_account_key, in_account_key_len);

    //
    // Allocate output buffer for output 'plain_text'
    //
    zend_string *out_plain_text = zend_string_alloc(vsce_phe_cipher_decrypt_len(phe_cipher, cipher_text.len), 0);
    vsc_buffer_t *plain_text = vsc_buffer_new();
    vsc_buffer_use(plain_text, (byte *)ZSTR_VAL(out_plain_text), ZSTR_LEN(out_plain_text));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_cipher_decrypt(phe_cipher, cipher_text, account_key, plain_text);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_plain_text) = vsc_buffer_len(plain_text);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_plain_text);
        vsc_buffer_destroy(&plain_text);
    }
    else {
        zend_string_free(out_plain_text);
    }
}

//
// Wrap method: vsce_phe_cipher_auth_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_auth_encrypt_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_additional_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_account_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_auth_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_plain_text = NULL;
    size_t in_plain_text_len = 0;
    char *in_additional_data = NULL;
    size_t in_additional_data_len = 0;
    char *in_account_key = NULL;
    size_t in_account_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_plain_text, in_plain_text_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_additional_data, in_additional_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_account_key, in_account_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    vsc_data_t plain_text = vsc_data((const byte*)in_plain_text, in_plain_text_len);
    vsc_data_t additional_data = vsc_data((const byte*)in_additional_data, in_additional_data_len);
    vsc_data_t account_key = vsc_data((const byte*)in_account_key, in_account_key_len);

    //
    // Allocate output buffer for output 'cipher_text'
    //
    zend_string *out_cipher_text = zend_string_alloc(vsce_phe_cipher_encrypt_len(phe_cipher, plain_text.len), 0);
    vsc_buffer_t *cipher_text = vsc_buffer_new();
    vsc_buffer_use(cipher_text, (byte *)ZSTR_VAL(out_cipher_text), ZSTR_LEN(out_cipher_text));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_cipher_auth_encrypt(phe_cipher, plain_text, additional_data, account_key, cipher_text);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_cipher_text) = vsc_buffer_len(cipher_text);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_cipher_text);
        vsc_buffer_destroy(&cipher_text);
    }
    else {
        zend_string_free(out_cipher_text);
    }
}

//
// Wrap method: vsce_phe_cipher_auth_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_auth_decrypt_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_cipher_text, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_additional_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_account_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_auth_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_cipher_text = NULL;
    size_t in_cipher_text_len = 0;
    char *in_additional_data = NULL;
    size_t in_additional_data_len = 0;
    char *in_account_key = NULL;
    size_t in_account_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_cipher_text, in_cipher_text_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_additional_data, in_additional_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_account_key, in_account_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    vsc_data_t cipher_text = vsc_data((const byte*)in_cipher_text, in_cipher_text_len);
    vsc_data_t additional_data = vsc_data((const byte*)in_additional_data, in_additional_data_len);
    vsc_data_t account_key = vsc_data((const byte*)in_account_key, in_account_key_len);

    //
    // Allocate output buffer for output 'plain_text'
    //
    zend_string *out_plain_text = zend_string_alloc(vsce_phe_cipher_decrypt_len(phe_cipher, cipher_text.len), 0);
    vsc_buffer_t *plain_text = vsc_buffer_new();
    vsc_buffer_use(plain_text, (byte *)ZSTR_VAL(out_plain_text), ZSTR_LEN(out_plain_text));

    //
    // Call main function
    //
    vsce_status_t status =vsce_phe_cipher_auth_decrypt(phe_cipher, cipher_text, additional_data, account_key, plain_text);

    //
    // Handle error
    //
    VSCE_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_plain_text) = vsc_buffer_len(plain_text);

    //
    // Write returned result
    //
    if (status == vsce_status_SUCCESS) {
        RETVAL_STR(out_plain_text);
        vsc_buffer_destroy(&plain_text);
    }
    else {
        zend_string_free(out_plain_text);
    }
}

//
// Wrap method: vsce_phe_cipher_use_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vsce_phe_cipher_use_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_random, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_cipher_use_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_random = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_random, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsce_phe_cipher_t *phe_cipher = zend_fetch_resource_ex(in_ctx, vsce_phe_cipher_t_php_res_name, le_vsce_phe_cipher_t);
    vscf_impl_t *random = zend_fetch_resource_ex(in_random, vscf_impl_t_php_res_name, le_vscf_impl_t);

    //
    // Call main function
    //
    vsce_phe_cipher_use_random(phe_cipher, random);
}

//
// Define all function entries
//
static zend_function_entry vsce_phe_php_functions[] = {
    PHP_FE(vsce_phe_server_new_php, arginfo_vsce_phe_server_new_php)
    PHP_FE(vsce_phe_server_delete_php, arginfo_vsce_phe_server_delete_php)
    PHP_FE(vsce_phe_server_setup_defaults_php, arginfo_vsce_phe_server_setup_defaults_php)
    PHP_FE(vsce_phe_server_generate_server_key_pair_php, arginfo_vsce_phe_server_generate_server_key_pair_php)
    PHP_FE(vsce_phe_server_enrollment_response_len_php, arginfo_vsce_phe_server_enrollment_response_len_php)
    PHP_FE(vsce_phe_server_get_enrollment_php, arginfo_vsce_phe_server_get_enrollment_php)
    PHP_FE(vsce_phe_server_verify_password_response_len_php, arginfo_vsce_phe_server_verify_password_response_len_php)
    PHP_FE(vsce_phe_server_verify_password_php, arginfo_vsce_phe_server_verify_password_php)
    PHP_FE(vsce_phe_server_update_token_len_php, arginfo_vsce_phe_server_update_token_len_php)
    PHP_FE(vsce_phe_server_rotate_keys_php, arginfo_vsce_phe_server_rotate_keys_php)
    PHP_FE(vsce_phe_server_use_random_php, arginfo_vsce_phe_server_use_random_php)
    PHP_FE(vsce_phe_server_use_operation_random_php, arginfo_vsce_phe_server_use_operation_random_php)
    PHP_FE(vsce_phe_client_new_php, arginfo_vsce_phe_client_new_php)
    PHP_FE(vsce_phe_client_delete_php, arginfo_vsce_phe_client_delete_php)
    PHP_FE(vsce_phe_client_setup_defaults_php, arginfo_vsce_phe_client_setup_defaults_php)
    PHP_FE(vsce_phe_client_set_keys_php, arginfo_vsce_phe_client_set_keys_php)
    PHP_FE(vsce_phe_client_generate_client_private_key_php, arginfo_vsce_phe_client_generate_client_private_key_php)
    PHP_FE(vsce_phe_client_enrollment_record_len_php, arginfo_vsce_phe_client_enrollment_record_len_php)
    PHP_FE(vsce_phe_client_enroll_account_php, arginfo_vsce_phe_client_enroll_account_php)
    PHP_FE(vsce_phe_client_verify_password_request_len_php, arginfo_vsce_phe_client_verify_password_request_len_php)
    PHP_FE(vsce_phe_client_create_verify_password_request_php, arginfo_vsce_phe_client_create_verify_password_request_php)
    PHP_FE(vsce_phe_client_check_response_and_decrypt_php, arginfo_vsce_phe_client_check_response_and_decrypt_php)
    PHP_FE(vsce_phe_client_rotate_keys_php, arginfo_vsce_phe_client_rotate_keys_php)
    PHP_FE(vsce_phe_client_update_enrollment_record_php, arginfo_vsce_phe_client_update_enrollment_record_php)
    PHP_FE(vsce_phe_client_use_random_php, arginfo_vsce_phe_client_use_random_php)
    PHP_FE(vsce_phe_client_use_operation_random_php, arginfo_vsce_phe_client_use_operation_random_php)
    PHP_FE(vsce_phe_cipher_new_php, arginfo_vsce_phe_cipher_new_php)
    PHP_FE(vsce_phe_cipher_delete_php, arginfo_vsce_phe_cipher_delete_php)
    PHP_FE(vsce_phe_cipher_setup_defaults_php, arginfo_vsce_phe_cipher_setup_defaults_php)
    PHP_FE(vsce_phe_cipher_encrypt_len_php, arginfo_vsce_phe_cipher_encrypt_len_php)
    PHP_FE(vsce_phe_cipher_decrypt_len_php, arginfo_vsce_phe_cipher_decrypt_len_php)
    PHP_FE(vsce_phe_cipher_encrypt_php, arginfo_vsce_phe_cipher_encrypt_php)
    PHP_FE(vsce_phe_cipher_decrypt_php, arginfo_vsce_phe_cipher_decrypt_php)
    PHP_FE(vsce_phe_cipher_auth_encrypt_php, arginfo_vsce_phe_cipher_auth_encrypt_php)
    PHP_FE(vsce_phe_cipher_auth_decrypt_php, arginfo_vsce_phe_cipher_auth_decrypt_php)
    PHP_FE(vsce_phe_cipher_use_random_php, arginfo_vsce_phe_cipher_use_random_php)
    PHP_FE_END
};

//
// Extension module definition
//
zend_module_entry vsce_phe_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCE_PHE_PHP_EXTNAME,
    vsce_phe_php_functions,
    PHP_MINIT(vsce_phe_php),
    PHP_MSHUTDOWN(vsce_phe_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCE_PHE_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vsce_phe_php)

//
// Extension init functions definition
//
static void vsce_phe_server_dtor_php(zend_resource *rsrc) {
    vsce_phe_server_delete((vsce_phe_server_t *)rsrc->ptr);
}
static void vsce_phe_client_dtor_php(zend_resource *rsrc) {
    vsce_phe_client_delete((vsce_phe_client_t *)rsrc->ptr);
}
static void vsce_phe_cipher_dtor_php(zend_resource *rsrc) {
    vsce_phe_cipher_delete((vsce_phe_cipher_t *)rsrc->ptr);
}
PHP_MINIT_FUNCTION(vsce_phe_php) {
    le_vsce_phe_server_t = zend_register_list_destructors_ex(vsce_phe_server_dtor_php, NULL, vsce_phe_server_t_php_res_name, module_number);
    le_vsce_phe_client_t = zend_register_list_destructors_ex(vsce_phe_client_dtor_php, NULL, vsce_phe_client_t_php_res_name, module_number);
    le_vsce_phe_cipher_t = zend_register_list_destructors_ex(vsce_phe_cipher_dtor_php, NULL, vsce_phe_cipher_t_php_res_name, module_number);
    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(vsce_phe_php) {
    return SUCCESS;
}
