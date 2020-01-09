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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_padding_cipher_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_padding_cipher_defs.h"
#include "vscf_cipher_info.h"
#include "vscf_cipher_info_api.h"
#include "vscf_encrypt.h"
#include "vscf_encrypt_api.h"
#include "vscf_decrypt.h"
#include "vscf_decrypt_api.h"
#include "vscf_cipher.h"
#include "vscf_cipher_api.h"
#include "vscf_cipher.h"
#include "vscf_padding.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_padding_cipher_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'cipher info api'.
//
static const vscf_cipher_info_api_t cipher_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_info' MUST be equal to the 'vscf_api_tag_CIPHER_INFO'.
    //
    vscf_api_tag_CIPHER_INFO,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PADDING_CIPHER,
    //
    //  Return cipher's nonce length or IV length in bytes,
    //  or 0 if nonce is not required.
    //
    (vscf_cipher_info_api_nonce_len_fn)vscf_padding_cipher_nonce_len,
    //
    //  Return cipher's key length in bytes.
    //
    (vscf_cipher_info_api_key_len_fn)vscf_padding_cipher_key_len,
    //
    //  Return cipher's key length in bits.
    //
    (vscf_cipher_info_api_key_bitlen_fn)vscf_padding_cipher_key_bitlen,
    //
    //  Return cipher's block length in bytes.
    //
    (vscf_cipher_info_api_block_len_fn)vscf_padding_cipher_block_len
};

//
//  Configuration of the interface API 'encrypt api'.
//
static const vscf_encrypt_api_t encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'encrypt' MUST be equal to the 'vscf_api_tag_ENCRYPT'.
    //
    vscf_api_tag_ENCRYPT,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PADDING_CIPHER,
    //
    //  Encrypt given data.
    //
    (vscf_encrypt_api_encrypt_fn)vscf_padding_cipher_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_encrypt_api_encrypted_len_fn)vscf_padding_cipher_encrypted_len,
    //
    //  Precise length calculation of encrypted data.
    //
    (vscf_encrypt_api_precise_encrypted_len_fn)vscf_padding_cipher_precise_encrypted_len
};

//
//  Configuration of the interface API 'decrypt api'.
//
static const vscf_decrypt_api_t decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'decrypt' MUST be equal to the 'vscf_api_tag_DECRYPT'.
    //
    vscf_api_tag_DECRYPT,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PADDING_CIPHER,
    //
    //  Decrypt given data.
    //
    (vscf_decrypt_api_decrypt_fn)vscf_padding_cipher_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_decrypt_api_decrypted_len_fn)vscf_padding_cipher_decrypted_len
};

//
//  Configuration of the interface API 'cipher api'.
//
static const vscf_cipher_api_t cipher_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher' MUST be equal to the 'vscf_api_tag_CIPHER'.
    //
    vscf_api_tag_CIPHER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PADDING_CIPHER,
    //
    //  Link to the inherited interface API 'encrypt'.
    //
    &encrypt_api,
    //
    //  Link to the inherited interface API 'decrypt'.
    //
    &decrypt_api,
    //
    //  Link to the inherited interface API 'cipher info'.
    //
    &cipher_info_api,
    //
    //  Setup IV or nonce.
    //
    (vscf_cipher_api_set_nonce_fn)vscf_padding_cipher_set_nonce,
    //
    //  Set cipher encryption / decryption key.
    //
    (vscf_cipher_api_set_key_fn)vscf_padding_cipher_set_key,
    //
    //  Return cipher's current state.
    //
    (vscf_cipher_api_state_fn)vscf_padding_cipher_state,
    //
    //  Start sequential encryption.
    //
    (vscf_cipher_api_start_encryption_fn)vscf_padding_cipher_start_encryption,
    //
    //  Start sequential decryption.
    //
    (vscf_cipher_api_start_decryption_fn)vscf_padding_cipher_start_decryption,
    //
    //  Process encryption or decryption of the given data chunk.
    //
    (vscf_cipher_api_update_fn)vscf_padding_cipher_update,
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an current mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    (vscf_cipher_api_out_len_fn)vscf_padding_cipher_out_len,
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an encryption mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    (vscf_cipher_api_encrypted_out_len_fn)vscf_padding_cipher_encrypted_out_len,
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an decryption mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    (vscf_cipher_api_decrypted_out_len_fn)vscf_padding_cipher_decrypted_out_len,
    //
    //  Accomplish encryption or decryption process.
    //
    (vscf_cipher_api_finish_fn)vscf_padding_cipher_finish
};

//
//  Compile-time known information about 'padding cipher' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_PADDING_CIPHER,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_padding_cipher_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_padding_cipher_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_padding_cipher_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_padding_cipher_init(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_padding_cipher_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_padding_cipher_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_padding_cipher_init()'.
//
VSCF_PUBLIC void
vscf_padding_cipher_cleanup(vscf_padding_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_padding_cipher_release_cipher(self);
    vscf_padding_cipher_release_padding(self);

    vscf_padding_cipher_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_padding_cipher_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_new(void) {

    vscf_padding_cipher_t *self = (vscf_padding_cipher_t *) vscf_alloc(sizeof (vscf_padding_cipher_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_padding_cipher_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_padding_cipher_new()'.
//
VSCF_PUBLIC void
vscf_padding_cipher_delete(vscf_padding_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_padding_cipher_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_padding_cipher_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_padding_cipher_destroy(vscf_padding_cipher_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_padding_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscf_padding_cipher_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_shallow_copy(vscf_padding_cipher_t *self) {

    // Proxy to the parent implementation.
    return (vscf_padding_cipher_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_padding_cipher_t' type.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_impl_size(void) {

    return sizeof (vscf_padding_cipher_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_padding_cipher_impl(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_padding_cipher_impl_const(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = vscf_impl_shallow_copy(cipher);
}

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_padding_cipher_take_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_cipher(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher);
}

//
//  Setup dependency to the interface 'padding' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT(self->padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(padding));

    self->padding = vscf_impl_shallow_copy(padding);
}

//
//  Setup dependency to the interface 'padding' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_padding_cipher_take_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT(self->padding == NULL);

    VSCF_ASSERT(vscf_padding_is_implemented(padding));

    self->padding = padding;
}

//
//  Release dependency to the interface 'padding'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_padding(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->padding);
}

static const vscf_api_t *
vscf_padding_cipher_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_CIPHER:
            return (const vscf_api_t *) &cipher_api;
        case vscf_api_tag_CIPHER_INFO:
            return (const vscf_api_t *) &cipher_info_api;
        case vscf_api_tag_DECRYPT:
            return (const vscf_api_t *) &decrypt_api;
        case vscf_api_tag_ENCRYPT:
            return (const vscf_api_t *) &encrypt_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
