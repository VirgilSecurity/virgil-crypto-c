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

#include "vscf_hkdf.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_hmac_stream.h"
#include "vscf_hkdf_impl.h"
#include "vscf_hkdf_internal.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vscf_hkdf_HASH_COUNTER_MAX = 255
};

//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vscf_hkdf_extract(vscf_hkdf_impl_t *hkdf_impl, const byte *data, size_t data_len, const byte *salt, size_t salt_len,
        byte *pr_key, size_t pr_key_len);

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_impl_t *hkdf_impl, byte *pr_key, size_t pr_key_len, const byte *info, size_t info_len,
        byte *key, size_t key_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vscf_hkdf_extract(vscf_hkdf_impl_t *hkdf_impl, const byte *data, size_t data_len, const byte *salt, size_t salt_len,
        byte *pr_key, size_t pr_key_len) {

    vscf_hmac_stream_reset(hkdf_impl->hmac);
    vscf_hmac_stream_start(hkdf_impl->hmac, salt, salt_len);
    vscf_hmac_stream_update(hkdf_impl->hmac, data, data_len);
    vscf_hmac_stream_finish(hkdf_impl->hmac, pr_key, pr_key_len);
}

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_impl_t *hkdf_impl, byte *pr_key, size_t pr_key_len, const byte *info, size_t info_len,
        byte *key, size_t key_len) {

    unsigned char counter = 0x00;
    vscf_hmac_stream_start(hkdf_impl->hmac, pr_key, pr_key_len);
    do {
        ++counter;
        size_t need = key_len - ((counter - 1) * pr_key_len);
        vscf_hmac_stream_reset(hkdf_impl->hmac);
        if (counter > 1) {
            vscf_hmac_stream_update(hkdf_impl->hmac, key + ((counter - 2) * pr_key_len), pr_key_len);
        }
        vscf_hmac_stream_update(hkdf_impl->hmac, info, info_len);
        vscf_hmac_stream_update(hkdf_impl->hmac, &counter, 1);

        if (need >= pr_key_len) {
            vscf_hmac_stream_finish(hkdf_impl->hmac, key + ((counter - 1) * pr_key_len), pr_key_len);
        } else {
            vscf_hmac_stream_finish(hkdf_impl->hmac, pr_key, pr_key_len);
            memcpy(key + ((counter - 1) * pr_key_len), pr_key, need);
        }
    } while (counter * pr_key_len < key_len);
}

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_hkdf_derive(vscf_hkdf_impl_t *hkdf_impl, const byte *data, size_t data_len, const byte *salt, size_t salt_len,
        const byte *info, size_t info_len, byte *key, size_t key_len) {

    VSCF_ASSERT_PTR(hkdf_impl);
    VSCF_ASSERT_PTR(hkdf_impl->hmac);
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT_PTR(salt);
    VSCF_ASSERT_PTR(info);
    VSCF_ASSERT_PTR(key);

    size_t pr_key_len = vscf_hmac_info_digest_size(vscf_hmac_info_api(hkdf_impl->hmac));
    VSCF_ASSERT_OPT(key_len <= vscf_hkdf_HASH_COUNTER_MAX * pr_key_len);

    unsigned char *pr_key = vscf_alloc(pr_key_len);
    VSCF_ASSERT_PTR(pr_key);

    vscf_hkdf_extract(hkdf_impl, data, data_len, salt, salt_len, pr_key, pr_key_len);

    vscf_hkdf_expand(hkdf_impl, pr_key, pr_key_len, info, info_len, key, key_len);

    vscf_dealloc(pr_key);
}
