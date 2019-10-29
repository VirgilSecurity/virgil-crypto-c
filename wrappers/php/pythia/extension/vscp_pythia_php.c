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
#include "vscp_assert.h"
#include "vscp_pythia_php.h"
#include "vscp_pythia.h"

#define VSCP_HANDLE_STATUS(status) do { if(status != vscp_status_SUCCESS) { vscp_handle_throw_exception(status); } } while (false)

void
vscp_handle_throw_exception(vscp_status_t status) {
    switch(status) {

    case vscp_status_ERROR_BAD_ARGUMENTS:
        zend_throw_exception(NULL, "VSCP: This error should not be returned if assertions is enabled.", -1);
        break;
    case vscp_status_ERROR_PYTHIA_INNER_FAIL:
        zend_throw_exception(NULL, "VSCP: Underlying pythia library returns -1.", -200);
        break;
    case vscp_status_ERROR_RNG_FAILED:
        zend_throw_exception(NULL, "VSCP: Underlying random number generator failed.", -202);
        break;
    }
}

//
// Constants
//
const char VSCP_PYTHIA_PHP_VERSION[] = "0.10.4";
const char VSCP_PYTHIA_PHP_EXTNAME[] = "vscp_pythia_php";

//
// Registered resources
//

//
// Extension init functions declaration
//
PHP_MINIT_FUNCTION(vscp_pythia_php);
PHP_MSHUTDOWN_FUNCTION(vscp_pythia_php);

//
// Functions wrapping
//
//
// Wrap method: vscp_pythia_configure
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_configure_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_configure_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_configure();

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);
}

//
// Wrap method: vscp_pythia_cleanup
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_cleanup_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_cleanup_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    vscp_pythia_cleanup();
}

//
// Wrap method: vscp_pythia_blinded_password_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_blinded_password_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_blinded_password_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_blinded_password_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_deblinded_password_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_deblinded_password_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_deblinded_password_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_deblinded_password_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_blinding_secret_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_blinding_secret_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_blinding_secret_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_blinding_secret_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_transformation_private_key_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_transformation_private_key_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_transformation_private_key_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_transformation_private_key_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_transformation_public_key_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_transformation_public_key_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_transformation_public_key_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_transformation_public_key_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_transformed_password_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_transformed_password_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_transformed_password_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_transformed_password_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_transformed_tweak_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_transformed_tweak_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_transformed_tweak_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_transformed_tweak_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_proof_value_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_proof_value_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_proof_value_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_proof_value_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_password_update_token_buf_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_password_update_token_buf_len_php,
    0 /*return_reference*/,
    0 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)



ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_password_update_token_buf_len_php) {

    //
    // Declare input argument
    //

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Call main function
    //
    size_t res =vscp_pythia_password_update_token_buf_len();

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscp_pythia_blind
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_blind_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_blind_php) {

    //
    // Declare input argument
    //
    char *in_password = NULL;
    size_t in_password_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);

    //
    // Allocate output buffer for output 'blinded_password'
    //
    zend_string *out_blinded_password = zend_string_alloc(vscp_pythia_blinded_password_buf_len(), 0);
    vsc_buffer_t *blinded_password = vsc_buffer_new();
    vsc_buffer_use(blinded_password, (byte *)ZSTR_VAL(out_blinded_password), ZSTR_LEN(out_blinded_password));

    //
    // Allocate output buffer for output 'blinding_secret'
    //
    zend_string *out_blinding_secret = zend_string_alloc(vscp_pythia_blinding_secret_buf_len(), 0);
    vsc_buffer_t *blinding_secret = vsc_buffer_new();
    vsc_buffer_use(blinding_secret, (byte *)ZSTR_VAL(out_blinding_secret), ZSTR_LEN(out_blinding_secret));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_blind(password, blinded_password, blinding_secret);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_blinded_password) = vsc_buffer_len(blinded_password);
    ZSTR_LEN(out_blinding_secret) = vsc_buffer_len(blinding_secret);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_blinded_password);
        add_next_index_str(return_value, out_blinding_secret);
        vsc_buffer_destroy(&blinded_password);
        vsc_buffer_destroy(&blinding_secret);
    }
    else {
        zend_string_free(out_blinded_password);
        zend_string_free(out_blinding_secret);
    }
}

//
// Wrap method: vscp_pythia_deblind
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_deblind_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_transformed_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_blinding_secret, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_deblind_php) {

    //
    // Declare input argument
    //
    char *in_transformed_password = NULL;
    size_t in_transformed_password_len = 0;
    char *in_blinding_secret = NULL;
    size_t in_blinding_secret_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_STRING_EX(in_transformed_password, in_transformed_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_blinding_secret, in_blinding_secret_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t transformed_password = vsc_data((const byte*)in_transformed_password, in_transformed_password_len);
    vsc_data_t blinding_secret = vsc_data((const byte*)in_blinding_secret, in_blinding_secret_len);

    //
    // Allocate output buffer for output 'deblinded_password'
    //
    zend_string *out_deblinded_password = zend_string_alloc(vscp_pythia_deblinded_password_buf_len(), 0);
    vsc_buffer_t *deblinded_password = vsc_buffer_new();
    vsc_buffer_use(deblinded_password, (byte *)ZSTR_VAL(out_deblinded_password), ZSTR_LEN(out_deblinded_password));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_deblind(transformed_password, blinding_secret, deblinded_password);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_deblinded_password) = vsc_buffer_len(deblinded_password);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        RETVAL_STR(out_deblinded_password);
        vsc_buffer_destroy(&deblinded_password);
    }
    else {
        zend_string_free(out_deblinded_password);
    }
}

//
// Wrap method: vscp_pythia_compute_transformation_key_pair
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_compute_transformation_key_pair_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_transformation_key_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_pythia_secret, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_pythia_scope_secret, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_compute_transformation_key_pair_php) {

    //
    // Declare input argument
    //
    char *in_transformation_key_id = NULL;
    size_t in_transformation_key_id_len = 0;
    char *in_pythia_secret = NULL;
    size_t in_pythia_secret_len = 0;
    char *in_pythia_scope_secret = NULL;
    size_t in_pythia_scope_secret_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_STRING_EX(in_transformation_key_id, in_transformation_key_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_pythia_secret, in_pythia_secret_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_pythia_scope_secret, in_pythia_scope_secret_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t transformation_key_id = vsc_data((const byte*)in_transformation_key_id, in_transformation_key_id_len);
    vsc_data_t pythia_secret = vsc_data((const byte*)in_pythia_secret, in_pythia_secret_len);
    vsc_data_t pythia_scope_secret = vsc_data((const byte*)in_pythia_scope_secret, in_pythia_scope_secret_len);

    //
    // Allocate output buffer for output 'transformation_private_key'
    //
    zend_string *out_transformation_private_key = zend_string_alloc(vscp_pythia_transformation_private_key_buf_len(), 0);
    vsc_buffer_t *transformation_private_key = vsc_buffer_new();
    vsc_buffer_use(transformation_private_key, (byte *)ZSTR_VAL(out_transformation_private_key), ZSTR_LEN(out_transformation_private_key));

    //
    // Allocate output buffer for output 'transformation_public_key'
    //
    zend_string *out_transformation_public_key = zend_string_alloc(vscp_pythia_transformation_public_key_buf_len(), 0);
    vsc_buffer_t *transformation_public_key = vsc_buffer_new();
    vsc_buffer_use(transformation_public_key, (byte *)ZSTR_VAL(out_transformation_public_key), ZSTR_LEN(out_transformation_public_key));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_compute_transformation_key_pair(transformation_key_id, pythia_secret, pythia_scope_secret, transformation_private_key, transformation_public_key);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_transformation_private_key) = vsc_buffer_len(transformation_private_key);
    ZSTR_LEN(out_transformation_public_key) = vsc_buffer_len(transformation_public_key);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_transformation_private_key);
        add_next_index_str(return_value, out_transformation_public_key);
        vsc_buffer_destroy(&transformation_private_key);
        vsc_buffer_destroy(&transformation_public_key);
    }
    else {
        zend_string_free(out_transformation_private_key);
        zend_string_free(out_transformation_public_key);
    }
}

//
// Wrap method: vscp_pythia_transform
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_transform_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_blinded_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_tweak, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_transformation_private_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_transform_php) {

    //
    // Declare input argument
    //
    char *in_blinded_password = NULL;
    size_t in_blinded_password_len = 0;
    char *in_tweak = NULL;
    size_t in_tweak_len = 0;
    char *in_transformation_private_key = NULL;
    size_t in_transformation_private_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_STRING_EX(in_blinded_password, in_blinded_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_tweak, in_tweak_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_transformation_private_key, in_transformation_private_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t blinded_password = vsc_data((const byte*)in_blinded_password, in_blinded_password_len);
    vsc_data_t tweak = vsc_data((const byte*)in_tweak, in_tweak_len);
    vsc_data_t transformation_private_key = vsc_data((const byte*)in_transformation_private_key, in_transformation_private_key_len);

    //
    // Allocate output buffer for output 'transformed_password'
    //
    zend_string *out_transformed_password = zend_string_alloc(vscp_pythia_transformed_password_buf_len(), 0);
    vsc_buffer_t *transformed_password = vsc_buffer_new();
    vsc_buffer_use(transformed_password, (byte *)ZSTR_VAL(out_transformed_password), ZSTR_LEN(out_transformed_password));

    //
    // Allocate output buffer for output 'transformed_tweak'
    //
    zend_string *out_transformed_tweak = zend_string_alloc(vscp_pythia_transformed_tweak_buf_len(), 0);
    vsc_buffer_t *transformed_tweak = vsc_buffer_new();
    vsc_buffer_use(transformed_tweak, (byte *)ZSTR_VAL(out_transformed_tweak), ZSTR_LEN(out_transformed_tweak));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_transform(blinded_password, tweak, transformation_private_key, transformed_password, transformed_tweak);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_transformed_password) = vsc_buffer_len(transformed_password);
    ZSTR_LEN(out_transformed_tweak) = vsc_buffer_len(transformed_tweak);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_transformed_password);
        add_next_index_str(return_value, out_transformed_tweak);
        vsc_buffer_destroy(&transformed_password);
        vsc_buffer_destroy(&transformed_tweak);
    }
    else {
        zend_string_free(out_transformed_password);
        zend_string_free(out_transformed_tweak);
    }
}

//
// Wrap method: vscp_pythia_prove
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_prove_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_transformed_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_blinded_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_transformed_tweak, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_transformation_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_transformation_public_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_prove_php) {

    //
    // Declare input argument
    //
    char *in_transformed_password = NULL;
    size_t in_transformed_password_len = 0;
    char *in_blinded_password = NULL;
    size_t in_blinded_password_len = 0;
    char *in_transformed_tweak = NULL;
    size_t in_transformed_tweak_len = 0;
    char *in_transformation_private_key = NULL;
    size_t in_transformation_private_key_len = 0;
    char *in_transformation_public_key = NULL;
    size_t in_transformation_public_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_STRING_EX(in_transformed_password, in_transformed_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_blinded_password, in_blinded_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_transformed_tweak, in_transformed_tweak_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_transformation_private_key, in_transformation_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_transformation_public_key, in_transformation_public_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t transformed_password = vsc_data((const byte*)in_transformed_password, in_transformed_password_len);
    vsc_data_t blinded_password = vsc_data((const byte*)in_blinded_password, in_blinded_password_len);
    vsc_data_t transformed_tweak = vsc_data((const byte*)in_transformed_tweak, in_transformed_tweak_len);
    vsc_data_t transformation_private_key = vsc_data((const byte*)in_transformation_private_key, in_transformation_private_key_len);
    vsc_data_t transformation_public_key = vsc_data((const byte*)in_transformation_public_key, in_transformation_public_key_len);

    //
    // Allocate output buffer for output 'proof_value_c'
    //
    zend_string *out_proof_value_c = zend_string_alloc(vscp_pythia_proof_value_buf_len(), 0);
    vsc_buffer_t *proof_value_c = vsc_buffer_new();
    vsc_buffer_use(proof_value_c, (byte *)ZSTR_VAL(out_proof_value_c), ZSTR_LEN(out_proof_value_c));

    //
    // Allocate output buffer for output 'proof_value_u'
    //
    zend_string *out_proof_value_u = zend_string_alloc(vscp_pythia_proof_value_buf_len(), 0);
    vsc_buffer_t *proof_value_u = vsc_buffer_new();
    vsc_buffer_use(proof_value_u, (byte *)ZSTR_VAL(out_proof_value_u), ZSTR_LEN(out_proof_value_u));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_prove(transformed_password, blinded_password, transformed_tweak, transformation_private_key, transformation_public_key, proof_value_c, proof_value_u);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_proof_value_c) = vsc_buffer_len(proof_value_c);
    ZSTR_LEN(out_proof_value_u) = vsc_buffer_len(proof_value_u);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        array_init(return_value);
        add_next_index_str(return_value, out_proof_value_c);
        add_next_index_str(return_value, out_proof_value_u);
        vsc_buffer_destroy(&proof_value_c);
        vsc_buffer_destroy(&proof_value_u);
    }
    else {
        zend_string_free(out_proof_value_c);
        zend_string_free(out_proof_value_u);
    }
}

//
// Wrap method: vscp_pythia_verify
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_verify_php,
    0 /*return_reference*/,
    6 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_transformed_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_blinded_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_tweak, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_transformation_public_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_proof_value_c, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_proof_value_u, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_verify_php) {

    //
    // Declare input argument
    //
    char *in_transformed_password = NULL;
    size_t in_transformed_password_len = 0;
    char *in_blinded_password = NULL;
    size_t in_blinded_password_len = 0;
    char *in_tweak = NULL;
    size_t in_tweak_len = 0;
    char *in_transformation_public_key = NULL;
    size_t in_transformation_public_key_len = 0;
    char *in_proof_value_c = NULL;
    size_t in_proof_value_c_len = 0;
    char *in_proof_value_u = NULL;
    size_t in_proof_value_u_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 6, 6)
        Z_PARAM_STRING_EX(in_transformed_password, in_transformed_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_blinded_password, in_blinded_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_tweak, in_tweak_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_transformation_public_key, in_transformation_public_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_proof_value_c, in_proof_value_c_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_proof_value_u, in_proof_value_u_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t transformed_password = vsc_data((const byte*)in_transformed_password, in_transformed_password_len);
    vsc_data_t blinded_password = vsc_data((const byte*)in_blinded_password, in_blinded_password_len);
    vsc_data_t tweak = vsc_data((const byte*)in_tweak, in_tweak_len);
    vsc_data_t transformation_public_key = vsc_data((const byte*)in_transformation_public_key, in_transformation_public_key_len);
    vsc_data_t proof_value_c = vsc_data((const byte*)in_proof_value_c, in_proof_value_c_len);
    vsc_data_t proof_value_u = vsc_data((const byte*)in_proof_value_u, in_proof_value_u_len);
    vscp_error_t error;
    vscp_error_reset(&error);

    //
    // Call main function
    //
    zend_bool res =vscp_pythia_verify(transformed_password, blinded_password, tweak, transformation_public_key, proof_value_c, proof_value_u, &error);

    //
    // Handle error
    //
    vscp_status_t status = vscp_error_status(&error);
    VSCP_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        RETVAL_BOOL(res);
    }
}

//
// Wrap method: vscp_pythia_get_password_update_token
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_get_password_update_token_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_previous_transformation_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_new_transformation_private_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_get_password_update_token_php) {

    //
    // Declare input argument
    //
    char *in_previous_transformation_private_key = NULL;
    size_t in_previous_transformation_private_key_len = 0;
    char *in_new_transformation_private_key = NULL;
    size_t in_new_transformation_private_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_STRING_EX(in_previous_transformation_private_key, in_previous_transformation_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_new_transformation_private_key, in_new_transformation_private_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t previous_transformation_private_key = vsc_data((const byte*)in_previous_transformation_private_key, in_previous_transformation_private_key_len);
    vsc_data_t new_transformation_private_key = vsc_data((const byte*)in_new_transformation_private_key, in_new_transformation_private_key_len);

    //
    // Allocate output buffer for output 'password_update_token'
    //
    zend_string *out_password_update_token = zend_string_alloc(vscp_pythia_password_update_token_buf_len(), 0);
    vsc_buffer_t *password_update_token = vsc_buffer_new();
    vsc_buffer_use(password_update_token, (byte *)ZSTR_VAL(out_password_update_token), ZSTR_LEN(out_password_update_token));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_get_password_update_token(previous_transformation_private_key, new_transformation_private_key, password_update_token);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_password_update_token) = vsc_buffer_len(password_update_token);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        RETVAL_STR(out_password_update_token);
        vsc_buffer_destroy(&password_update_token);
    }
    else {
        zend_string_free(out_password_update_token);
    }
}

//
// Wrap method: vscp_pythia_update_deblinded_with_token
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscp_pythia_update_deblinded_with_token_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_deblinded_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_password_update_token, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscp_pythia_update_deblinded_with_token_php) {

    //
    // Declare input argument
    //
    char *in_deblinded_password = NULL;
    size_t in_deblinded_password_len = 0;
    char *in_password_update_token = NULL;
    size_t in_password_update_token_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_STRING_EX(in_deblinded_password, in_deblinded_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_password_update_token, in_password_update_token_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t deblinded_password = vsc_data((const byte*)in_deblinded_password, in_deblinded_password_len);
    vsc_data_t password_update_token = vsc_data((const byte*)in_password_update_token, in_password_update_token_len);

    //
    // Allocate output buffer for output 'updated_deblinded_password'
    //
    zend_string *out_updated_deblinded_password = zend_string_alloc(vscp_pythia_deblinded_password_buf_len(), 0);
    vsc_buffer_t *updated_deblinded_password = vsc_buffer_new();
    vsc_buffer_use(updated_deblinded_password, (byte *)ZSTR_VAL(out_updated_deblinded_password), ZSTR_LEN(out_updated_deblinded_password));

    //
    // Call main function
    //
    vscp_status_t status =vscp_pythia_update_deblinded_with_token(deblinded_password, password_update_token, updated_deblinded_password);

    //
    // Handle error
    //
    VSCP_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_updated_deblinded_password) = vsc_buffer_len(updated_deblinded_password);

    //
    // Write returned result
    //
    if (status == vscp_status_SUCCESS) {
        RETVAL_STR(out_updated_deblinded_password);
        vsc_buffer_destroy(&updated_deblinded_password);
    }
    else {
        zend_string_free(out_updated_deblinded_password);
    }
}

//
// Define all function entries
//
static zend_function_entry vscp_pythia_php_functions[] = {
    PHP_FE(vscp_pythia_configure_php, arginfo_vscp_pythia_configure_php)
    PHP_FE(vscp_pythia_cleanup_php, arginfo_vscp_pythia_cleanup_php)
    PHP_FE(vscp_pythia_blinded_password_buf_len_php, arginfo_vscp_pythia_blinded_password_buf_len_php)
    PHP_FE(vscp_pythia_deblinded_password_buf_len_php, arginfo_vscp_pythia_deblinded_password_buf_len_php)
    PHP_FE(vscp_pythia_blinding_secret_buf_len_php, arginfo_vscp_pythia_blinding_secret_buf_len_php)
    PHP_FE(vscp_pythia_transformation_private_key_buf_len_php, arginfo_vscp_pythia_transformation_private_key_buf_len_php)
    PHP_FE(vscp_pythia_transformation_public_key_buf_len_php, arginfo_vscp_pythia_transformation_public_key_buf_len_php)
    PHP_FE(vscp_pythia_transformed_password_buf_len_php, arginfo_vscp_pythia_transformed_password_buf_len_php)
    PHP_FE(vscp_pythia_transformed_tweak_buf_len_php, arginfo_vscp_pythia_transformed_tweak_buf_len_php)
    PHP_FE(vscp_pythia_proof_value_buf_len_php, arginfo_vscp_pythia_proof_value_buf_len_php)
    PHP_FE(vscp_pythia_password_update_token_buf_len_php, arginfo_vscp_pythia_password_update_token_buf_len_php)
    PHP_FE(vscp_pythia_blind_php, arginfo_vscp_pythia_blind_php)
    PHP_FE(vscp_pythia_deblind_php, arginfo_vscp_pythia_deblind_php)
    PHP_FE(vscp_pythia_compute_transformation_key_pair_php, arginfo_vscp_pythia_compute_transformation_key_pair_php)
    PHP_FE(vscp_pythia_transform_php, arginfo_vscp_pythia_transform_php)
    PHP_FE(vscp_pythia_prove_php, arginfo_vscp_pythia_prove_php)
    PHP_FE(vscp_pythia_verify_php, arginfo_vscp_pythia_verify_php)
    PHP_FE(vscp_pythia_get_password_update_token_php, arginfo_vscp_pythia_get_password_update_token_php)
    PHP_FE(vscp_pythia_update_deblinded_with_token_php, arginfo_vscp_pythia_update_deblinded_with_token_php)
    PHP_FE_END
};

//
// Extension module definition
//
zend_module_entry vscp_pythia_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCP_PYTHIA_PHP_EXTNAME,
    vscp_pythia_php_functions,
    PHP_MINIT(vscp_pythia_php),
    PHP_MSHUTDOWN(vscp_pythia_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCP_PYTHIA_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscp_pythia_php)

//
// Extension init functions definition
//

PHP_MINIT_FUNCTION(vscp_pythia_php) {

    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(vscp_pythia_php) {
    return SUCCESS;
}
