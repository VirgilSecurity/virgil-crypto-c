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
//  Prvodes Base64URL encoding and decoding suitable for JWT.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscs_core_base64_url.h"
#include "vscs_core_memory.h"
#include "vscs_core_assert.h"

#include <virgil/crypto/foundation/vscf_base64.h>
#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>

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
//  Calculate length in bytes required to hold an encoded base64url string.
//
VSCS_CORE_PUBLIC size_t
vscs_core_base64_url_encoded_len(size_t data_len) {

    return vscf_base64_encoded_len(data_len);
}

//
//  Encode given data to the base64url format.
//  Note, written buffer is NOT null-terminated.
//
VSCS_CORE_PUBLIC void
vscs_core_base64_url_encode(vsc_data_t data, vsc_str_buffer_t *str) {

    VSCS_CORE_ASSERT(vsc_data_is_valid(data));
    VSCS_CORE_ASSERT(vsc_str_buffer_is_valid(str));

    vscf_base64_encode(data, &str->buffer);

    vsc_str_buffer_replace_char(str, '+', '-');
    vsc_str_buffer_replace_char(str, '/', '_');
    vsc_str_buffer_rtrim(str, '=');
}

//
//  Calculate length in bytes required to hold a decoded base64url string.
//
VSCS_CORE_PUBLIC size_t
vscs_core_base64_url_decoded_len(size_t str_len) {

    return vscf_base64_decoded_len(str_len);
}

//
//  Decode given data from the base64url format.
//
VSCS_CORE_PUBLIC vscs_core_status_t
vscs_core_base64_url_decode(vsc_str_t str, vsc_buffer_t *data) {

    VSCS_CORE_ASSERT(vsc_str_is_valid(str));
    VSCS_CORE_ASSERT(vsc_buffer_is_valid(data));

    const size_t pad_length = (4 - (str.len % 4)) % 4;

    vsc_str_buffer_t *str_buffer = vsc_str_buffer_new_with_capacity(str.len + pad_length);
    vsc_str_buffer_write_str(str_buffer, str);

    vsc_str_buffer_replace_char(str_buffer, '-', '+');
    vsc_str_buffer_replace_char(str_buffer, '_', '/');

    while (!vsc_str_buffer_is_full(str_buffer)) {
        vsc_str_buffer_write_char(str_buffer, '=');
    }

    const vscf_status_t status = vscf_base64_decode(vsc_str_buffer_data(str_buffer), data);

    vsc_str_buffer_destroy(&str_buffer);

    if (status != vscf_status_SUCCESS) {
        return vscs_core_status_DECODE_BASE64_URL_FAILED;
    }

    return vscs_core_status_SUCCESS;
}
