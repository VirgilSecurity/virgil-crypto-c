//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  This module contains 'compound private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compound_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_private_key.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key_defs.h"
#include "vscf_compound_private_key_internal.h"

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
//  Note, this method is called automatically when method vscf_compound_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_compound_private_key_init_ctx(vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_compound_private_key_cleanup_ctx(vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    vscf_impl_destroy(&self->cipher_key);
    vscf_impl_destroy(&self->signer_key);
    vscf_impl_destroy(&self->alg_info);
}

//
//  Create a compound private key with a cipher private key and
//  a signer private key.
//
VSCF_PUBLIC void
vscf_compound_private_key_init_ctx_with_keys(vscf_compound_private_key_t *self, vscf_impl_t **alg_info_ref,
        const vscf_impl_t *cipher_key, const vscf_impl_t *signer_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info_ref);
    VSCF_ASSERT_PTR(*alg_info_ref);
    VSCF_ASSERT_PTR(cipher_key);
    VSCF_ASSERT_PTR(signer_key);
    VSCF_ASSERT(vscf_alg_info_is_implemented(*alg_info_ref));
    VSCF_ASSERT(vscf_alg_info_alg_id(*alg_info_ref) != vscf_alg_id_NONE);
    VSCF_ASSERT(vscf_private_key_is_implemented(cipher_key));
    VSCF_ASSERT(vscf_private_key_is_implemented(signer_key));

    self->alg_info = *alg_info_ref;
    self->cipher_key = (vscf_impl_t *)vscf_impl_shallow_copy_const(cipher_key);
    self->signer_key = (vscf_impl_t *)vscf_impl_shallow_copy_const(signer_key);

    *alg_info_ref = NULL;
}

//
//  Create a compound private key with a cipher private key and
//  a signer private key.
//
VSCF_PUBLIC void
vscf_compound_private_key_init_ctx_with_keys_disown(vscf_compound_private_key_t *self, const vscf_impl_t *alg_info,
        vscf_impl_t **cipher_key_ref, vscf_impl_t **signer_key_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(cipher_key_ref);
    VSCF_ASSERT_PTR(*cipher_key_ref);
    VSCF_ASSERT_PTR(signer_key_ref);
    VSCF_ASSERT_PTR(*signer_key_ref);
    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) != vscf_alg_id_NONE);
    VSCF_ASSERT(vscf_private_key_is_implemented(*cipher_key_ref));
    VSCF_ASSERT(vscf_private_key_is_implemented(*signer_key_ref));

    self->alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(alg_info);
    self->cipher_key = *cipher_key_ref;
    self->signer_key = *signer_key_ref;

    *cipher_key_ref = NULL;
    *signer_key_ref = NULL;
}

//
//  Return primary private key suitable for a final decryption.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_private_key_cipher_key(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher_key);

    return self->cipher_key;
}

//
//  Return private key suitable for signing.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_private_key_signer_key(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_key);

    return self->signer_key;
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_compound_private_key_alg_id(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return vscf_alg_info_alg_id(self->alg_info);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_private_key_alg_info(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_compound_private_key_len(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_OPT(0 && "Unsupported algorithm");
    return 0;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_compound_private_key_bitlen(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_OPT(0 && "Unsupported algorithm");
    return 0;
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_compound_private_key_impl_tag(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_impl_tag_COMPOUND_KEY_ALG;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_compound_private_key_is_valid(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->cipher_key || NULL == self->signer_key || NULL == self->alg_info) {
        return false;
    }

    const bool is_cipher_key_valid = vscf_key_is_valid(self->cipher_key);
    const bool is_signer_key_valid = vscf_key_is_valid(self->signer_key);
    return is_cipher_key_valid && is_signer_key_valid;
}

//
//  Extract public key from the private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_private_key_extract_public_key(const vscf_compound_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_SAFE(vscf_compound_private_key_is_valid(self));

    vscf_impl_t *cipher_public_key = vscf_private_key_extract_public_key(self->cipher_key);
    vscf_impl_t *signer_public_key = vscf_private_key_extract_public_key(self->signer_key);

    vscf_compound_public_key_t *public_key =
            vscf_compound_public_key_new_with_keys_disown(self->alg_info, &cipher_public_key, &signer_public_key);
    return vscf_compound_public_key_impl(public_key);
}
