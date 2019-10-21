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
//  This module contains 'compound public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compound_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_compound_public_key_defs.h"
#include "vscf_compound_public_key_internal.h"

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
//  Note, this method is called automatically when method vscf_compound_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_compound_public_key_init_ctx(vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_compound_public_key_cleanup_ctx(vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->alg_info);
    vscf_impl_destroy(&self->encryption_key);
    vscf_impl_destroy(&self->verifying_key);
    vsc_buffer_destroy(&self->encryption_key_signature);
}

//
//  Create compound public key with an encryption public key and
//  a verifying public key.
//
//  Note, keys ownership is transferred.
//
VSCF_PUBLIC void
vscf_compound_public_key_init_ctx_with_members(vscf_compound_public_key_t *self, const vscf_impl_t *alg_info,
        vscf_impl_t **encryption_key_ref, vscf_impl_t **verifying_key_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(encryption_key_ref);
    VSCF_ASSERT_PTR(*encryption_key_ref);
    VSCF_ASSERT_PTR(verifying_key_ref);
    VSCF_ASSERT_PTR(*verifying_key_ref);
    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));
    VSCF_ASSERT(vscf_public_key_is_implemented(*encryption_key_ref));
    VSCF_ASSERT(vscf_public_key_is_implemented(*verifying_key_ref));

    self->alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(alg_info);
    self->encryption_key = *encryption_key_ref;
    self->verifying_key = *verifying_key_ref;

    *encryption_key_ref = NULL;
    *verifying_key_ref = NULL;
}

//
//  Return public key suitable for encryption.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_public_key_get_encryption_key(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->encryption_key);

    return self->encryption_key;
}

//
//  Return public key suitable for verifying.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_public_key_get_verifying_key(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->verifying_key);

    return self->verifying_key;
}

//
//  Setup the encryption key signature.
//
VSCF_PUBLIC void
vscf_compound_public_key_set_encryption_key_signature(
        vscf_compound_public_key_t *self, vsc_data_t encryption_key_signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(encryption_key_signature));

    vsc_buffer_destroy(&self->encryption_key_signature);
    self->encryption_key_signature = vsc_buffer_new_with_data(encryption_key_signature);
}

//
//  Setup the encryption key signature.
//
VSCF_PUBLIC vsc_data_t
vscf_compound_public_key_get_encryption_key_signature(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->encryption_key_signature);

    return vsc_buffer_data(self->encryption_key_signature);
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_compound_public_key_alg_id(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return vscf_alg_info_alg_id(self->alg_info);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_public_key_alg_info(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_compound_public_key_len(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_OPT(0 && "Unsupported algorithm");
    return 0;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_compound_public_key_bitlen(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_OPT(0 && "Unsupported algorithm");
    return 0;
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_compound_public_key_impl_tag(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_impl_tag_COMPOUND_KEY_ALG;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_compound_public_key_is_valid(const vscf_compound_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->alg_info || NULL == self->encryption_key || NULL == self->verifying_key) {
        return false;
    }

    const bool is_encryption_key_valid = vscf_key_is_valid(self->verifying_key);
    const bool is_verifying_key_valid = vscf_key_is_valid(self->encryption_key);
    return is_encryption_key_valid && is_verifying_key_valid;
}
