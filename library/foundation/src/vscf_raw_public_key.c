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
//  This module contains 'raw public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_raw_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_raw_public_key_defs.h"
#include "vscf_raw_public_key_internal.h"

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
//  Note, this method is called automatically when method vscf_raw_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_raw_public_key_init_ctx(vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    self->impl_tag = vscf_impl_tag_BEGIN;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_raw_public_key_cleanup_ctx(vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy((vscf_impl_t **)(&self->alg_info));
    vsc_buffer_destroy((vsc_buffer_t **)(&self->buffer));
}

//
//  Creates raw key defined with data and algorithm.
//  Note, data is copied.
//
VSCF_PUBLIC void
vscf_raw_public_key_init_ctx_with_data(vscf_raw_public_key_t *self, vsc_data_t key_data, vscf_impl_t **alg_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT(!vsc_data_is_empty(key_data));
    VSCF_ASSERT_PTR(alg_info_ref);
    VSCF_ASSERT_PTR(*alg_info_ref);

    self->alg_info = *alg_info_ref;
    self->buffer = vsc_buffer_new_with_data(key_data);

    *alg_info_ref = NULL;
}

//
//  Creates raw key defined with buffer and algorithm.
//  Note, data is not copied.
//
VSCF_PUBLIC void
vscf_raw_public_key_init_ctx_with_buffer(
        vscf_raw_public_key_t *self, vsc_buffer_t **key_data_ref, vscf_impl_t **alg_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key_data_ref);
    VSCF_ASSERT_PTR(*key_data_ref);
    VSCF_ASSERT(vsc_buffer_is_valid(*key_data_ref));
    VSCF_ASSERT(vsc_buffer_len(*key_data_ref) > 0);
    VSCF_ASSERT_PTR(alg_info_ref);
    VSCF_ASSERT_PTR(*alg_info_ref);

    self->alg_info = *alg_info_ref;
    self->buffer = *key_data_ref;

    *alg_info_ref = NULL;
    *key_data_ref = NULL;
}

//
//  Creates raw key defined another raw key and new impl tag.
//  Note, data is not copied, but new instance of key is created.s
//
VSCF_PUBLIC void
vscf_raw_public_key_init_ctx_with_redefined_impl_tag(
        vscf_raw_public_key_t *self, const vscf_raw_public_key_t *other, vscf_impl_tag_t impl_tag) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(other);
    VSCF_ASSERT_PTR(other->alg_info);
    VSCF_ASSERT(vscf_impl_tag_BEGIN < impl_tag && impl_tag < vscf_impl_tag_END);

    self->buffer = vsc_buffer_shallow_copy((vsc_buffer_t *)other->buffer);
    self->alg_info = vscf_impl_shallow_copy((vscf_impl_t *)other->alg_info);
    self->impl_tag = impl_tag;
}

//
//  Return key data.
//
VSCF_PUBLIC vsc_data_t
vscf_raw_public_key_data(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->buffer);

    return vsc_buffer_data(self->buffer);
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_raw_public_key_alg_id(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return vscf_alg_info_alg_id(self->alg_info);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_raw_public_key_alg_info(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_raw_public_key_len(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->buffer);

    return vsc_buffer_len(self->buffer);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_raw_public_key_bitlen(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->buffer);

    return 8 * vsc_buffer_len(self->buffer);
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_raw_public_key_impl_tag(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->impl_tag;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_raw_public_key_is_valid(const vscf_raw_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->alg_info || vscf_alg_info_alg_id(self->alg_info) == vscf_alg_id_NONE) {
        return false;
    }

    if (NULL == self->buffer || vsc_buffer_len(self->buffer) == 0) {
        return false;
    }

    return true;
}
