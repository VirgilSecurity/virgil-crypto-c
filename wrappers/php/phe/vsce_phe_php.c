//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
// --------------------------------------------------------------------------
// @end


#include "vsce_assert.h"
#include "vsce_phe_client.h"
#include "vsce_phe_common.h"

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>


// --------------------------------------------------------------------------
//  Constants
// --------------------------------------------------------------------------
const char VSCE_PHE_CLIENT_PHP_VERSION[] = "0.5.0";
const char VSCE_PHE_CLIENT_PHP_EXTNAME[] = "vsce_phe_client_php";
const char VSCE_PHE_CLIENT_PHP_RES_NAME[] = "vsce_phe_client_t";


// --------------------------------------------------------------------------
//  Registered resources
// --------------------------------------------------------------------------
int le_vsce_phe_client;


// --------------------------------------------------------------------------
//  Extension init functions declaration
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vsce_phe_client_php);
PHP_MSHUTDOWN_FUNCTION(vsce_phe_client_php);


// --------------------------------------------------------------------------
//  Functions wrapping
// --------------------------------------------------------------------------

//
//  Wrap method: vsce_phe_client_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vsce_phe_client_new_php) {
    vsce_phe_client_t *phe_client = vsce_phe_client_new();
    zend_resource *phe_client_res = zend_register_resource(phe_client, le_vsce_phe_client);
    RETVAL_RES(phe_client_res);
}

//
//  Wrap method: vsce_phe_client_enrollment_record_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_enrollment_record_len_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_LONG /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_enrollment_record_len_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    RETVAL_LONG(vsce_phe_client_enrollment_record_len(phe_client));
}

//
//  Wrap method: vsce_phe_client_verify_password_request_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_verify_password_request_len_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_LONG /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_verify_password_request_len_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    RETVAL_LONG(vsce_phe_client_verify_password_request_len(phe_client));
}

//
//  Wrap method: vsce_phe_client_enroll_account
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_enroll_account_php /*name*/,
        0 /*return_reference*/,
        3 /*required_num_args*/,
        IS_ARRAY /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, enrollment_response, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_enroll_account_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_enrollment_response = NULL;
    size_t in_enrollment_response_len = 0;
    char *in_password = NULL;
    size_t in_password_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_enrollment_response, in_enrollment_response_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t enrollment_response = vsc_data((const byte*)in_enrollment_response, in_enrollment_response_len);
    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);

    //  Allocate output buffer for output 'enrollment_record'
    zend_string *out_enrollment_record = zend_string_alloc(vsce_phe_client_enrollment_record_len(phe_client), 0);
    vsc_buffer_t *enrollment_record = vsc_buffer_new();
    vsc_buffer_use(enrollment_record, (byte *)ZSTR_VAL(out_enrollment_record), ZSTR_LEN(out_enrollment_record));

    //  Allocate output buffer for output 'account_key'
    zend_string *out_account_key = zend_string_alloc(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, 0);
    vsc_buffer_t *account_key = vsc_buffer_new();
    vsc_buffer_use(account_key, (byte *)ZSTR_VAL(out_account_key), ZSTR_LEN(out_account_key));

    vsce_error_t status = vsce_phe_client_enroll_account(phe_client, enrollment_response, password, enrollment_record, account_key);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_enrollment_record) = vsc_buffer_len(enrollment_record);
    ZSTR_LEN(out_account_key) = vsc_buffer_len(account_key);

    //
    //  Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_enrollment_record);
    add_next_index_str(return_value, out_account_key);

    goto success;

fail:
    zend_string_free(out_enrollment_record);
    zend_string_free(out_account_key);
success:
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
}

//
//  Wrap method: vsce_phe_client_rotate_keys
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_rotate_keys_php /*name*/,
        0 /*return_reference*/,
        3 /*required_num_args*/,
        IS_ARRAY /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, update_token, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_rotate_keys_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_update_token = NULL;
    size_t in_update_token_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_update_token, in_update_token_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t update_token = vsc_data((const byte*)in_update_token, in_update_token_len);

    //  Allocate output buffer for output 'new_client_private_key'
    zend_string *out_new_client_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *new_client_private_key = vsc_buffer_new();
    vsc_buffer_use(new_client_private_key, (byte *)ZSTR_VAL(out_new_client_private_key), ZSTR_LEN(out_new_client_private_key));

    //  Allocate output buffer for output 'new_server_public_key'
    zend_string *out_new_server_public_key = zend_string_alloc(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH, 0);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new();
    vsc_buffer_use(new_server_public_key, (byte *)ZSTR_VAL(out_new_server_public_key), ZSTR_LEN(out_new_server_public_key));

    vsce_error_t status = vsce_phe_client_rotate_keys(phe_client, update_token, new_client_private_key, new_server_public_key);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_new_client_private_key) = vsc_buffer_len(new_client_private_key);
    ZSTR_LEN(out_new_server_public_key) = vsc_buffer_len(new_server_public_key);

    //
    //  Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_new_client_private_key);
    add_next_index_str(return_value, out_new_server_public_key);

    goto success;

fail:
    zend_string_free(out_new_client_private_key);
    zend_string_free(out_new_server_public_key);
success:
    vsc_buffer_destroy(&new_client_private_key);
    vsc_buffer_destroy(&new_server_public_key);
}

//
//  Wrap method: vsce_phe_client_generate_client_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_generate_client_private_key_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_generate_client_private_key_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    //  Allocate output buffer for output 'client_private_key'
    zend_string *out_client_private_key = zend_string_alloc(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, 0);
    vsc_buffer_t *client_private_key = vsc_buffer_new();
    vsc_buffer_use(client_private_key, (byte *)ZSTR_VAL(out_client_private_key), ZSTR_LEN(out_client_private_key));

    vsce_error_t status = vsce_phe_client_generate_client_private_key(phe_client, client_private_key);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_client_private_key) = vsc_buffer_len(client_private_key);

    //
    //  Write returned result
    //
    RETVAL_STR(out_client_private_key);

    goto success;

fail:
    zend_string_free(out_client_private_key);
success:
    vsc_buffer_destroy(&client_private_key);
}

//
//  Wrap method: vsce_phe_client_update_enrollment_record
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_update_enrollment_record_php /*name*/,
        0 /*return_reference*/,
        3 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_update_enrollment_record_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;
    char *in_update_token = NULL;
    size_t in_update_token_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_update_token, in_update_token_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);
    vsc_data_t update_token = vsc_data((const byte*)in_update_token, in_update_token_len);

    //  Allocate output buffer for output 'new_enrollment_record'
    zend_string *out_new_enrollment_record = zend_string_alloc(vsce_phe_client_enrollment_record_len(phe_client), 0);
    vsc_buffer_t *new_enrollment_record = vsc_buffer_new();
    vsc_buffer_use(new_enrollment_record, (byte *)ZSTR_VAL(out_new_enrollment_record), ZSTR_LEN(out_new_enrollment_record));

    vsce_error_t status = vsce_phe_client_update_enrollment_record(phe_client, enrollment_record, update_token, new_enrollment_record);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_new_enrollment_record) = vsc_buffer_len(new_enrollment_record);

    //
    //  Write returned result
    //
    RETVAL_STR(out_new_enrollment_record);

    goto success;

fail:
    zend_string_free(out_new_enrollment_record);
success:
    vsc_buffer_destroy(&new_enrollment_record);
}

//
//  Wrap method: vsce_phe_client_create_verify_password_request
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_create_verify_password_request_php /*name*/,
        0 /*return_reference*/,
        3 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_create_verify_password_request_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);
    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);

    //  Allocate output buffer for output 'verify_password_request'
    zend_string *out_verify_password_request = zend_string_alloc(vsce_phe_client_verify_password_request_len(phe_client), 0);
    vsc_buffer_t *verify_password_request = vsc_buffer_new();
    vsc_buffer_use(verify_password_request, (byte *)ZSTR_VAL(out_verify_password_request), ZSTR_LEN(out_verify_password_request));

    vsce_error_t status = vsce_phe_client_create_verify_password_request(phe_client, password, enrollment_record, verify_password_request);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_verify_password_request) = vsc_buffer_len(verify_password_request);

    //
    //  Write returned result
    //
    RETVAL_STR(out_verify_password_request);

    goto success;

fail:
    zend_string_free(out_verify_password_request);
success:
    vsc_buffer_destroy(&verify_password_request);
}

//
//  Wrap method: vsce_phe_client_check_response_and_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vsce_phe_client_check_response_and_decrypt_php /*name*/,
        0 /*return_reference*/,
        4 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_check_response_and_decrypt_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;
    char *in_enrollment_record = NULL;
    size_t in_enrollment_record_len = 0;
    char *in_verify_password_response = NULL;
    size_t in_verify_password_response_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_enrollment_record, in_enrollment_record_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_verify_password_response, in_verify_password_response_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);
    vsc_data_t enrollment_record = vsc_data((const byte*)in_enrollment_record, in_enrollment_record_len);
    vsc_data_t verify_password_response = vsc_data((const byte*)in_verify_password_response, in_verify_password_response_len);

    //  Allocate output buffer for output 'account_key'
    zend_string *out_account_key = zend_string_alloc(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, 0);
    vsc_buffer_t *account_key = vsc_buffer_new();
    vsc_buffer_use(account_key, (byte *)ZSTR_VAL(out_account_key), ZSTR_LEN(out_account_key));

    vsce_error_t status = vsce_phe_client_check_response_and_decrypt(phe_client, password, enrollment_record, verify_password_response, account_key);

    //
    //  Handle error
    //
    if(status != vsce_SUCCESS) {
        zend_throw_exception(NULL, "PHE Client error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_account_key) = vsc_buffer_len(account_key);

    //
    //  Write returned result
    //
    RETVAL_STR(out_account_key);

    goto success;

fail:
    zend_string_free(out_account_key);
success:
    vsc_buffer_destroy(&account_key);
}

//
//  Wrap method: vsce_phe_client_set_keys
//
ZEND_BEGIN_ARG_INFO(arginfo_vsce_phe_client_set_keys_php /*name*/, 0 /*return_reference*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vsce_phe_client_set_keys_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_client_private_key = NULL;
    size_t in_client_private_key_len = 0;
    char *in_server_public_key = NULL;
    size_t in_server_public_key_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_client_private_key, in_client_private_key_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_STRING_EX(in_server_public_key, in_server_public_key_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vsce_phe_client_t *phe_client = zend_fetch_resource_ex(in_cctx, VSCE_PHE_CLIENT_PHP_RES_NAME, le_vsce_phe_client);
    VSCE_ASSERT_PTR(phe_client);

    vsc_data_t client_private_key = vsc_data((const byte*)in_client_private_key, in_client_private_key_len);
    vsc_data_t server_public_key = vsc_data((const byte*)in_server_public_key, in_server_public_key_len);

    vsce_phe_client_set_keys(phe_client, client_private_key, server_public_key);

    RETURN_TRUE;
}

// --------------------------------------------------------------------------
//  Define all function entries
// --------------------------------------------------------------------------
static zend_function_entry vsce_phe_client_php_functions[] = {
    PHP_FE(vsce_phe_client_new_php, arginfo_vsce_phe_client_new_php)
    PHP_FE(vsce_phe_client_set_keys_php, arginfo_vsce_phe_client_set_keys_php)
    PHP_FE(vsce_phe_client_enrollment_record_len_php, arginfo_vsce_phe_client_enrollment_record_len_php)
    PHP_FE(vsce_phe_client_verify_password_request_len_php, arginfo_vsce_phe_client_verify_password_request_len_php)
    PHP_FE(vsce_phe_client_enroll_account_php, arginfo_vsce_phe_client_enroll_account_php)
    PHP_FE(vsce_phe_client_generate_client_private_key_php, arginfo_vsce_phe_client_generate_client_private_key_php)
    PHP_FE(vsce_phe_client_rotate_keys_php, arginfo_vsce_phe_client_rotate_keys_php)
    PHP_FE(vsce_phe_client_update_enrollment_record_php, arginfo_vsce_phe_client_update_enrollment_record_php)
    PHP_FE(vsce_phe_client_create_verify_password_request_php, arginfo_vsce_phe_client_create_verify_password_request_php)
    PHP_FE(vsce_phe_client_check_response_and_decrypt_php, arginfo_vsce_phe_client_check_response_and_decrypt_php)
//    PHP_FE(vsce_phe_client_delete_php, arginfo_vsce_phe_client_delete_php)
    PHP_FE_END
};


// --------------------------------------------------------------------------
//  Extension module definition
// --------------------------------------------------------------------------
zend_module_entry vsce_phe_client_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCE_PHE_CLIENT_PHP_EXTNAME,
    vsce_phe_client_php_functions,
    PHP_MINIT(vsce_phe_client_php),
    PHP_MSHUTDOWN(vsce_phe_client_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCE_PHE_CLIENT_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vsce_phe_client_php)


// --------------------------------------------------------------------------
//  Extension init functions definition
// --------------------------------------------------------------------------
static void vsce_phe_client_dtor_php(zend_resource *rsrc) {
    vsce_phe_client_delete((vsce_phe_client_t *)rsrc->ptr);
}

PHP_MINIT_FUNCTION(vsce_phe_client_php) {

    le_vsce_phe_client = zend_register_list_destructors_ex(vsce_phe_client_dtor_php, NULL, VSCE_PHE_CLIENT_PHP_RES_NAME,
     module_number);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(vsce_phe_client_php) {

    return SUCCESS;
}
