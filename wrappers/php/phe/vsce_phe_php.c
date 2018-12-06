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

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>


// --------------------------------------------------------------------------
//  Constants
// --------------------------------------------------------------------------
const char VSCP_PHE_PHP_VERSION[] = "0.5.0";
const char VSCP_PHE_PHP_EXTNAME[] = "vsce_phe_php";
const char VSCP_PHE_PHP_RES_NAME[] = "vsce_phe_t";


// --------------------------------------------------------------------------
//  Registered resources
// --------------------------------------------------------------------------
int le_vsce_phe;


// --------------------------------------------------------------------------
//  Extension init functions declaration
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vsce_phe_php);
PHP_MSHUTDOWN_FUNCTION(vsce_phe_php);


// --------------------------------------------------------------------------
//  Functions wrapping
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Define all function entries
// --------------------------------------------------------------------------
static zend_function_entry vsce_phe_php_functions[] = {
    PHP_FE_END
};


// --------------------------------------------------------------------------
//  Extension module definition
// --------------------------------------------------------------------------
zend_module_entry vsce_phe_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCP_PHE_PHP_EXTNAME,
    vsce_phe_php_functions,
    PHP_MINIT(vsce_phe_php),
    PHP_MSHUTDOWN(vsce_phe_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCP_PHE_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vsce_phe_php)


// --------------------------------------------------------------------------
//  Extension init functions definition
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vsce_phe_php) {
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(vsce_phe_php) {
    return SUCCESS;
}
