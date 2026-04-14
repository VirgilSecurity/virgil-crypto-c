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
#include "vscp_assert.h"
#include "vscp_pythia_php.h"
#include "vscp_pythia.h"

#define VSCP_HANDLE_STATUS(status) do { if(status != vscp_status_SUCCESS) { vscp_handle_throw_exception(status); } } while (false)

zend_class_entry* vscp_exception_ce;

void
vscp_handle_throw_exception(vscp_status_t status) {

    switch(status) {

    case vscp_status_SUCCESS:
        break;
    case vscp_status_ERROR_BAD_ARGUMENTS:
        zend_throw_exception_ex(vscp_exception_ce, -1, "This error should not be returned if assertions is enabled.");
        break;
    case vscp_status_ERROR_PYTHIA_INNER_FAIL:
        zend_throw_exception_ex(vscp_exception_ce, -200, "Underlying pythia library returns -1.");
        break;
    case vscp_status_ERROR_RNG_FAILED:
        zend_throw_exception_ex(vscp_exception_ce, -202, "Underlying random number generator failed.");
        break;
    }
}
