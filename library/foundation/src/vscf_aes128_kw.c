//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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
//  //
//  //  This module contains 'aes128 kw' implementation.
//  //
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_aes128_kw.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_aes128_kw_defs.h"
#include "vscf_aes128_kw_internal.h"

#include <mbedtls/nist_kw.h>

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
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_aes128_kw_alg_id(const vscf_aes128_kw_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_AES128_KW;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes128_kw_produce_alg_info(const vscf_aes128_kw_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_AES128_KW));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_aes128_kw_restore_alg_info(vscf_aes128_kw_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_AES128_KW);

    return vscf_status_SUCCESS;
}

//
//  Return buffer length required to hold a wrapped key for the given plain key length.
//
VSCF_PUBLIC size_t
vscf_aes128_kw_wrapped_len(const vscf_aes128_kw_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len + 8;
}

//
//  Return buffer length required to hold an unwrapped key for the given wrapped key length.
//
VSCF_PUBLIC size_t
vscf_aes128_kw_unwrapped_len(const vscf_aes128_kw_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(data_len >= 8);

    return data_len - 8;
}

//
//  Wrap given key data using the Key Encryption Key (KEK).
//
VSCF_PUBLIC vscf_status_t
vscf_aes128_kw_wrap(vscf_aes128_kw_t *self, vsc_data_t kek, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(kek));
    VSCF_ASSERT(kek.len == 16);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(data.len >= 16 && data.len % 8 == 0);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes128_kw_wrapped_len(self, data.len));

    mbedtls_nist_kw_context kw_ctx;
    mbedtls_nist_kw_init(&kw_ctx);

    int status = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES, kek.bytes, 128, 1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    size_t out_len = 0;
    status = mbedtls_nist_kw_wrap(&kw_ctx, MBEDTLS_KW_MODE_KW, data.bytes, data.len, vsc_buffer_unused_bytes(out),
            &out_len, vsc_buffer_unused_len(out));

    mbedtls_nist_kw_free(&kw_ctx);

    if (status != 0) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    vsc_buffer_inc_used(out, out_len);

    return vscf_status_SUCCESS;
}

//
//  Unwrap given key data using the Key Encryption Key (KEK).
//
VSCF_PUBLIC vscf_status_t
vscf_aes128_kw_unwrap(vscf_aes128_kw_t *self, vsc_data_t kek, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(kek));
    VSCF_ASSERT(kek.len == 16);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(data.len >= 24 && data.len % 8 == 0);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes128_kw_unwrapped_len(self, data.len));

    mbedtls_nist_kw_context kw_ctx;
    mbedtls_nist_kw_init(&kw_ctx);

    int status = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES, kek.bytes, 128, 0);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    size_t out_len = 0;
    status = mbedtls_nist_kw_unwrap(&kw_ctx, MBEDTLS_KW_MODE_KW, data.bytes, data.len, vsc_buffer_unused_bytes(out),
            &out_len, vsc_buffer_unused_len(out));

    mbedtls_nist_kw_free(&kw_ctx);

    if (status == MBEDTLS_ERR_CIPHER_AUTH_FAILED) {
        return vscf_status_ERROR_AUTH_FAILED;
    }
    if (status != 0) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    vsc_buffer_inc_used(out, out_len);

    return vscf_status_SUCCESS;
}
