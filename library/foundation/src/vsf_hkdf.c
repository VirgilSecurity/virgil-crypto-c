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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'hkdf' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_hkdf.h"
#include "vsf_assert.h"
#include "vsf_memory.h"
#include "vsf_hmac_stream.h"
#include "vsf_hkdf_impl.h"
#include "vsf_hkdf_internal.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vsf_hkdf_extract(vsf_hkdf_impl_t* hkdf_impl, const byte* data, size_t data_len, const byte* salt, size_t salt_len,
        byte* pr_key, size_t pr_key_len);

//
//  Expands the pseudorandom key to the desired length.
//
static void
vsf_hkdf_expand(vsf_hkdf_impl_t* hkdf_impl, byte* pr_key, size_t pr_key_len, const byte* info, size_t info_len,
        byte* key, size_t key_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vsf_hkdf_extract(vsf_hkdf_impl_t* hkdf_impl, const byte* data, size_t data_len, const byte* salt, size_t salt_len,
        byte* pr_key, size_t pr_key_len) {

    vsf_hmac_stream_reset(hkdf_impl->hmac);
    vsf_hmac_stream_start(hkdf_impl->hmac, salt, salt_len);
    vsf_hmac_stream_update(hkdf_impl->hmac, data, data_len);
    vsf_hmac_stream_finish(hkdf_impl->hmac, pr_key, pr_key_len);
}

//
//  Expands the pseudorandom key to the desired length.
//
static void
vsf_hkdf_expand(vsf_hkdf_impl_t* hkdf_impl, byte* pr_key, size_t pr_key_len, const byte* info, size_t info_len,
        byte* key, size_t key_len) {

    unsigned char counter = 0x00;
    vsf_hmac_stream_start(hkdf_impl->hmac, pr_key, pr_key_len);
    do {
        ++counter;
        size_t need = key_len - ((counter - 1) * pr_key_len);
        vsf_hmac_stream_reset(hkdf_impl->hmac);
        if (counter > 1) {
            vsf_hmac_stream_update(hkdf_impl->hmac, key + ((counter - 2) * pr_key_len), pr_key_len);
        }
        vsf_hmac_stream_update(hkdf_impl->hmac, info, info_len);
        vsf_hmac_stream_update(hkdf_impl->hmac, &counter, 1);

        if (need >= pr_key_len) {
            vsf_hmac_stream_finish(hkdf_impl->hmac, key + ((counter - 1) * pr_key_len), pr_key_len);
        } else {
            vsf_hmac_stream_finish(hkdf_impl->hmac, pr_key, pr_key_len);
            memcpy(key + ((counter - 1) * pr_key_len), pr_key, need);
        }
    } while (counter * pr_key_len < key_len);
}

//
//  Calculate hash over given data.
//
VSF_PUBLIC void
vsf_hkdf_derive(vsf_hkdf_impl_t* hkdf_impl, const byte* data, size_t data_len, const byte* salt, size_t salt_len,
        const byte* info, size_t info_len, byte* key, size_t key_len) {

    VSF_ASSERT_PTR(hkdf_impl);
    VSF_ASSERT_PTR(hkdf_impl->hmac);
    VSF_ASSERT_PTR(data);
    VSF_ASSERT_PTR(salt);
    VSF_ASSERT_PTR(info);
    VSF_ASSERT_PTR(key);

    size_t pr_key_len = vsf_hmac_info_digest_size(vsf_hmac_info_api(hkdf_impl->hmac));

    unsigned char* pr_key = vsf_alloc(pr_key_len);

    VSF_ASSERT_PTR(pr_key);

    vsf_hkdf_extract(hkdf_impl, data, data_len, salt, salt_len, pr_key, pr_key_len);
    if (key_len < 255 * pr_key_len) {
        vsf_hkdf_expand(hkdf_impl, pr_key, pr_key_len, info, info_len, key, key_len);
    } else {
        VSF_ASSERT_OPT("Key size is large!!!");
    }

    vsf_dealloc(pr_key);
}
