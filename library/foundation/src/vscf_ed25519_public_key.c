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
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  This module contains 'ed25519 public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ed25519_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_ed25519_public_key_impl.h"
#include "vscf_ed25519_public_key_internal.h"

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
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_ed25519_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ed25519_public_key_init_ctx(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    memset(ed25519_public_key_impl->public_key, 0, sizeof(ed25519_public_key_impl->public_key));
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ed25519_public_key_cleanup_ctx(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    memset(ed25519_public_key_impl->public_key, 0, sizeof(ed25519_public_key_impl->public_key));
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_ed25519_public_key_key_len(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    return sizeof(ed25519_public_key_impl->public_key);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_ed25519_public_key_key_bitlen(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    return (8*sizeof(ed25519_public_key_impl->public_key));
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_public_key_encrypt(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl, vsc_data_t data,
        vsc_buffer_t *out) {

    //  TODO: This is STUB. Implement me.
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ed25519_public_key_encrypted_len(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl, size_t data_len) {

    //  TODO: This is STUB. Implement me.
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_ed25519_public_key_verify(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl, vsc_data_t data,
        vsc_data_t signature) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT_PTR(data.bytes);
    int ret = ed25519_verify(signature.bytes, ed25519_public_key_impl->public_key, data.bytes, data.len);
    return (ret == 0);
}

//
//  Export public key in the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_public_key_export_public_key(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    byte* ptr = vsc_buffer_ptr(out);
    size_t available = vsc_buffer_left(out);
    VSCF_ASSERT(available >= sizeof(ed25519_public_key_impl->public_key));
    conv_cpymem(ptr, ed25519_public_key_impl->public_key, sizeof(ed25519_public_key_impl->public_key), 0);
    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_ed25519_public_key_exported_public_key_len(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    return sizeof(ed25519_public_key_impl->public_key);
}

//
//  Import public key from the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_public_key_import_public_key(vscf_ed25519_public_key_impl_t *ed25519_public_key_impl, vsc_data_t data) {

    VSCF_ASSERT_PTR(ed25519_public_key_impl);
    VSCF_ASSERT_PTR(data.bytes);
    VSCF_ASSERT(data.len <= sizeof(ed25519_public_key_impl->public_key));
    conv_cpymem(ed25519_public_key_impl->public_key, data.bytes, data.len, 1);
    return vscf_SUCCESS;
}
