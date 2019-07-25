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


#include "vscp_assert.h"
#include "vscp_pythia.h"

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>


// --------------------------------------------------------------------------
//  Constants
// --------------------------------------------------------------------------
const char VSCP_PYTHIA_PHP_VERSION[] = "0.9.0";
const char VSCP_PYTHIA_PHP_EXTNAME[] = "vscp_pythia_php";
const char VSCP_PYTHIA_PHP_RES_NAME[] = "vscp_pythia_t";


// --------------------------------------------------------------------------
//  Extension init functions declaration
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vscp_pythia_php);
PHP_MSHUTDOWN_FUNCTION(vscp_pythia_php);


// --------------------------------------------------------------------------
//  Functions wrapping
// --------------------------------------------------------------------------

//
//  Wrap method: vscp_pythia_blind
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscp_pythia_blind_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_ARRAY /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscp_pythia_blind_php) {
    //
    //  Declare input arguments
    //
    char *in_password = NULL;
    size_t in_password_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);

    //  Allocate output buffer for output 'blinded_password'
    zend_string *out_blinded_password = zend_string_alloc(vscp_pythia_blinded_password_buf_len(), 0);
    vsc_buffer_t *blinded_password = vsc_buffer_new();
    vsc_buffer_use(blinded_password, (byte *)ZSTR_VAL(out_blinded_password), ZSTR_LEN(out_blinded_password));

    //  Allocate output buffer for output 'blinding_secret'
    zend_string *out_blinding_secret = zend_string_alloc(vscp_pythia_blinding_secret_buf_len(), 0);
    vsc_buffer_t *blinding_secret = vsc_buffer_new();
    vsc_buffer_use(blinding_secret, (byte *)ZSTR_VAL(out_blinding_secret), ZSTR_LEN(out_blinding_secret));

    vscp_status_t status = vscp_pythia_blind(password, blinded_password, blinding_secret);

    //
    //  Handle error
    //
    if(status != vscp_status_SUCCESS) {
        zend_throw_exception(NULL, "Pythia error", status);
        goto fail;
    }

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_blinded_password) = vsc_buffer_len(blinded_password);
    ZSTR_LEN(out_blinding_secret) = vsc_buffer_len(blinding_secret);

    //
    //  Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_blinded_password);
    add_next_index_str(return_value, out_blinding_secret);

    goto success;

fail:
    zend_string_free(out_blinded_password);
    zend_string_free(out_blinding_secret);
success:
    vsc_buffer_destroy(&blinded_password);
    vsc_buffer_destroy(&blinding_secret);
}


// --------------------------------------------------------------------------
//  Define all function entries
// --------------------------------------------------------------------------
static zend_function_entry vscp_pythia_php_functions[] = {
    PHP_FE(vscp_pythia_blind_php, arginfo_vscp_pythia_blind_php)
    PHP_FE_END
};


// --------------------------------------------------------------------------
//  Extension module definition
// --------------------------------------------------------------------------
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


// --------------------------------------------------------------------------
//  Extension init functions definition
// --------------------------------------------------------------------------

PHP_MINIT_FUNCTION(vscp_pythia_php) {

    vscp_status_t status = vscp_pythia_configure();
    if (status == vscp_status_SUCCESS) {
        return SUCCESS;
    }

    return FAILURE;
}

PHP_MSHUTDOWN_FUNCTION(vscp_pythia_php) {

    vscp_pythia_cleanup();

    return SUCCESS;
}
