//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_base64.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

#include <mbedtls/base64.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Calculate length in bytes required to hold an encoded base64 string.
//
VSCF_PUBLIC size_t
vscf_base64_encoded_len(size_t data_len) {

    size_t len = 4 * VSCF_CEIL(data_len, 3);

    if (len > 0) {
        len += 1;
    }

    return len;
}

//
//  Encode given data to the base64 format.
//  Note, written buffer is NOT null-terminated.
//
VSCF_PUBLIC void
vscf_base64_encode(vsc_data_t data, vsc_buffer_t *str) {

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(str);
    VSCF_ASSERT(vsc_buffer_is_valid(str));
    VSCF_ASSERT(vsc_buffer_unused_len(str) >= vscf_base64_encoded_len(data.len));

    size_t len = 0;
    int status =
            mbedtls_base64_encode(vsc_buffer_unused_bytes(str), vsc_buffer_unused_len(str), &len, data.bytes, data.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vsc_buffer_inc_used(str, len);
}

//
//  Calculate length in bytes required to hold a decoded base64 string.
//
VSCF_PUBLIC size_t
vscf_base64_decoded_len(size_t str_len) {

    size_t len = 3 * VSCF_CEIL(str_len, 4);

    if (len > 0) {
        len += 1;
    }

    return len;
}

//
//  Decode given data from the base64 format.
//
VSCF_PUBLIC vscf_status_t
vscf_base64_decode(vsc_data_t str, vsc_buffer_t *data) {

    VSCF_ASSERT(vsc_data_is_valid(str));
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT(vsc_buffer_is_valid(data));
    VSCF_ASSERT(vsc_buffer_unused_len(data) >= vscf_base64_decoded_len(str.len));

    size_t len = 0;
    int status =
            mbedtls_base64_decode(vsc_buffer_unused_bytes(data), vsc_buffer_unused_len(data), &len, str.bytes, str.len);

    switch (status) {
    case 0:
        break;

    case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
        return vscf_status_ERROR_BAD_BASE64;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(status);
        return vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR;
    }

    vsc_buffer_inc_used(data, len);

    return vscf_status_SUCCESS;
}
