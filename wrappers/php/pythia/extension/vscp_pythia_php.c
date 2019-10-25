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
// Define all function entries
//
static zend_function_entry vscp_pythia_php_functions[] = {

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
