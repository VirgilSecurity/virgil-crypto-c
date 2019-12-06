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
//  This module contains 'compound key alg info' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compound_key_alg_info.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_compound_key_alg_info_defs.h"
#include "vscf_compound_key_alg_info_internal.h"

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
//  Note, this method is called automatically when method vscf_compound_key_alg_info_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_compound_key_alg_info_init_ctx(vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_compound_key_alg_info_cleanup_ctx(vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher_alg_info);
    vscf_impl_destroy(&self->signer_alg_info);
    vscf_impl_destroy(&self->signer_hash_alg_info);
}

//
//  Create compound algorithm information.
//
//  Note, keys ownership is preserved.
//
VSCF_PUBLIC void
vscf_compound_key_alg_info_init_ctx_with_infos(vscf_compound_key_alg_info_t *self, vscf_alg_id_t alg_id,
        const vscf_impl_t *cipher_alg_info, const vscf_impl_t *signer_alg_info,
        const vscf_impl_t *signer_hash_alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(cipher_alg_info);
    VSCF_ASSERT_PTR(signer_alg_info);
    VSCF_ASSERT_PTR(signer_hash_alg_info);

    self->alg_id = alg_id;
    self->cipher_alg_info = vscf_impl_shallow_copy((vscf_impl_t *)cipher_alg_info);
    self->signer_alg_info = vscf_impl_shallow_copy((vscf_impl_t *)signer_alg_info);
    self->signer_hash_alg_info = vscf_impl_shallow_copy((vscf_impl_t *)signer_hash_alg_info);
}

//
//  Create compound algorithm information.
//
//  Note, keys ownership is transferred.
//
VSCF_PUBLIC void
vscf_compound_key_alg_info_init_ctx_with_infos_disown(vscf_compound_key_alg_info_t *self, vscf_alg_id_t alg_id,
        vscf_impl_t **cipher_alg_info_ref, vscf_impl_t **signer_alg_info_ref, vscf_impl_t **signer_hash_alg_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(cipher_alg_info_ref);
    VSCF_ASSERT_PTR(*cipher_alg_info_ref);
    VSCF_ASSERT_PTR(signer_alg_info_ref);
    VSCF_ASSERT_PTR(*signer_alg_info_ref);
    VSCF_ASSERT_PTR(signer_hash_alg_info_ref);
    VSCF_ASSERT_PTR(*signer_hash_alg_info_ref);

    self->alg_id = alg_id;

    self->cipher_alg_info = *cipher_alg_info_ref;
    self->signer_alg_info = *signer_alg_info_ref;
    self->signer_hash_alg_info = *signer_hash_alg_info_ref;

    *cipher_alg_info_ref = NULL;
    *signer_alg_info_ref = NULL;
    *signer_hash_alg_info_ref = NULL;
}

//
//  Return information about encrypt/decrypt algorithm.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_key_alg_info_cipher_alg_info(const vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher_alg_info);

    return self->cipher_alg_info;
}

//
//  Return information about sign/verify algorithm.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_key_alg_info_signer_alg_info(const vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_alg_info);

    return self->signer_alg_info;
}

//
//  Return information about hash algorithm that is used with signing.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_compound_key_alg_info_signer_hash_alg_info(const vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_hash_alg_info);

    return self->signer_hash_alg_info;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_compound_key_alg_info_alg_id(const vscf_compound_key_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_id != vscf_alg_id_NONE);

    return self->alg_id;
}
