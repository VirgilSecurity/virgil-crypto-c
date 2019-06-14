//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#include "vscf_sha256.h"
#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"
#include "vscf_status.h"

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>


// --------------------------------------------------------------------------
//  Constants
// --------------------------------------------------------------------------
const char VSCF_PHP_VERSION[] = "0.1.0";
const char VSCF_PHP_EXTNAME[] = "vscf_php";

const char VSCF_SHA256_PHP_RES_NAME[] = "vscf_sha256_t";


// --------------------------------------------------------------------------
//  Registered resources
// --------------------------------------------------------------------------
int le_vscf_sha256;


// --------------------------------------------------------------------------
//  Extension init functions declaration
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vscf_php);
PHP_MSHUTDOWN_FUNCTION(vscf_php);


// --------------------------------------------------------------------------
//  Functions wrapping
// --------------------------------------------------------------------------
//
//  Wrap method: vscf_sha256_new_php
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_new_php) {
    vscf_sha256_t *sha256 = vscf_sha256_new();
    zend_resource *sha256_res = zend_register_resource(sha256, le_vscf_sha256);
    RETVAL_RES(sha256_res);
}

//
//  Wrap method: vscf_sha256_delete_php
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_delete_php /*name*/,
        0 /*_unused*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_delete_php) {
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
    //  Fetch for type checking and then release
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256);
    VSCF_ASSERT_PTR(sha256);
    zend_list_close(Z_RES_P(in_cctx));
    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_hash_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_hash_php) {
    //
    //  Declare input arguments
    //
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256);
    VSCF_ASSERT_PTR(sha256);

    //  Allocate output buffer for output 'digest'
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    vscf_status_t status = vscf_sha256_hash(sha256, digest);

    //
    //  Handle error
    //
    if(status != vscf_status_SUCCESS) {
        zend_throw_exception(NULL, "SHA256 error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    //  Write returned result
    //
    RETVAL_STR(out_digest);

    goto success;

fail:
    zend_string_free(out_digest);
success:
    vsc_buffer_destroy(&digest);
}

//
//  Wrap method: vscf_sha256_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_start_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_start_php) {
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
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256);
    VSCF_ASSERT_PTR(sha256);

    vscf_status_t status = vscf_sha256_start(sha256);
    if(status != vscf_status_SUCCESS) {
        zend_throw_exception(NULL, "SHA256 error", status);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_update_php /*name*/,
        0 /*return_reference*/,
        2 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_update_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256);
    VSCF_ASSERT_PTR(sha256);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    //
    //  Handle error
    //

    vscf_status_t status = vscf_sha256_update(sha256, data);
    if(status != vscf_status_SUCCESS) {
        zend_throw_exception(NULL, "SHA256 error", status);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_finish_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_finish_php) {
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
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256);
    VSCF_ASSERT_PTR(sha256);

    //  Allocate output buffer for output 'digest'
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    vscf_status_t status = vscf_sha256_finish(sha256, digest);

    //
    //  Handle error
    //
    if(status != vscf_status_SUCCESS) {
        zend_throw_exception(NULL, "SHA256 error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    //  Write returned result
    //
    RETVAL_STR(out_digest);

    goto success;

fail:
    zend_string_free(out_digest);
success:
    vsc_buffer_destroy(&digest);
}


// --------------------------------------------------------------------------
//  Define all function entries
// --------------------------------------------------------------------------
static zend_function_entry vscf_php_functions[] = {
    PHP_FE(vscf_sha256_new_php, arginfo_vscf_sha256_new_php)
    PHP_FE_END
};


// --------------------------------------------------------------------------
//  Extension module definition
// --------------------------------------------------------------------------
zend_module_entry vscf_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCF_PHP_EXTNAME,
    vscf_php_functions,
    PHP_MINIT(vscf_php),
    PHP_MSHUTDOWN(vscf_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCF_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscf_php)


// --------------------------------------------------------------------------
//  Extension init functions definition
// --------------------------------------------------------------------------
static void vscf_sha256_dtor_php(zend_resource *rsrc) {
    vscf_sha256_delete((vscf_sha256_t *)rsrc->ptr);
}

PHP_MINIT_FUNCTION(vscf_php) {

    le_vscf_sha256 = zend_register_list_destructors_ex(
            vscf_sha256_dtor_php, NULL, VSCF_SHA256_PHP_RES_NAME, module_number);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(vscf_php) {

    return SUCCESS;
}