//
// Copyright (C) 2015-2022 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// (1) Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// (2) Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in
// the documentation and/or other materials provided with the
// distribution.
//
// (3) Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
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
#include "vsce_phe_cipher.h"
#include "vsce_phe_client.h"
#include "vsce_phe_common.h"
#include "vsce_phe_server.h"
#include "vsce_uokms_client.h"
#include "vsce_uokms_server.h"
#include "vsce_uokms_wrap_rotation.h"

#define VSCE_HANDLE_STATUS(status) do { if(status != vsce_status_SUCCESS) { vsce_handle_throw_exception(status); } } while (false)

zend_class_entry* vsce_exception_ce;

void
vsce_handle_throw_exception(vsce_status_t status) {

    switch(status) {

    case vsce_status_SUCCESS:
        break;
    case vsce_status_ERROR_INVALID_SUCCESS_PROOF:
        zend_throw_exception_ex(vsce_exception_ce, -1, "Success proof check failed.");
        break;
    case vsce_status_ERROR_INVALID_FAIL_PROOF:
        zend_throw_exception_ex(vsce_exception_ce, -2, "Failure proof check failed.");
        break;
    case vsce_status_ERROR_RNG_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -3, "RNG returned error.");
        break;
    case vsce_status_ERROR_PROTOBUF_DECODE_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -4, "Protobuf decode failed.");
        break;
    case vsce_status_ERROR_INVALID_PUBLIC_KEY:
        zend_throw_exception_ex(vsce_exception_ce, -5, "Invalid public key.");
        break;
    case vsce_status_ERROR_INVALID_PRIVATE_KEY:
        zend_throw_exception_ex(vsce_exception_ce, -6, "Invalid private key.");
        break;
    case vsce_status_ERROR_AES_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -7, "AES error occurred.");
        break;
    }
}
