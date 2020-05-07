//
// Copyright (C) 2015-2020 Virgil Security, Inc.
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
#include "vscs_core_assert.h"
#include "vscs_core_core sdk_php.h"
#include "vscf_foundation_php.h"
#include "vscs_core_jwt_generator.h"

#define VSCS_CORE_HANDLE_STATUS(status) do { if(status != vscs_core_status_SUCCESS) { vscs_core_handle_throw_exception(status); } } while (false)

zend_class_entry* vscs_core_exception_ce;

void
vscs_core_handle_throw_exception(vscs_core_status_t status) {

    switch(status) {

    case vscs_core_status_INTERNAL_ERROR:
        zend_throw_exception_ex(vscs_core_exception_ce, -1, "Met internal inconsistency.");
        break;
    }
}

//
// Constants
//
const char VSCS_CORE_CORE SDK_PHP_VERSION[] = "0.16.0";
const char VSCS_CORE_CORE SDK_PHP_EXTNAME[] = "vscs_core_core sdk_php";

//
// Constants func wrapping
//

//
// Registered resources
//

//
// Registered resources func wrapping
//

//
// Extension init functions declaration
//
PHP_MINIT_FUNCTION(vscs_core_core sdk_php);
PHP_MSHUTDOWN_FUNCTION(vscs_core_core sdk_php);

//
// Functions wrapping
//

//
// Define all function entries
//
static zend_function_entry vscs_core_core sdk_php_functions[] = {

    PHP_FE_END
};

//
// Extension module definition
//
zend_module_entry vscs_core_core sdk_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCS_CORE_CORE SDK_PHP_EXTNAME,
    vscs_core_core sdk_php_functions,
    PHP_MINIT(vscs_core_core sdk_php),
    PHP_MSHUTDOWN(vscs_core_core sdk_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCS_CORE_CORE SDK_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscs_core_core sdk_php)

//
// Extension init functions definition
//

PHP_MINIT_FUNCTION(vscs_core_core sdk_php) {
    zend_class_entry vscs_core_ce;
    INIT_CLASS_ENTRY(vscs_core_ce, "CoreSdkException", NULL);
    vscs_core_exception_ce = zend_register_internal_class_ex(&vscs_core_ce, zend_exception_get_default());

    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(vscs_core_core sdk_php) {
    return SUCCESS;
}
