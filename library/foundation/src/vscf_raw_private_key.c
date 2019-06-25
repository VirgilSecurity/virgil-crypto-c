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
//  This module contains 'raw private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_raw_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_raw_private_key_defs.h"
#include "vscf_raw_private_key_internal.h"

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
//  Note, this method is called automatically when method vscf_raw_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_raw_private_key_init_ctx(vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    self->impl_tag = vscf_impl_tag_BEGIN;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_raw_private_key_cleanup_ctx(vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Creates fully defined raw public key.
//
VSCF_PUBLIC void
vscf_raw_private_key_init_ctx_with_raw_key(
        vscf_raw_private_key_t *self, vscf_impl_tag_t impl_tag, const vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(impl_tag != vscf_impl_tag_BEGIN);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(vscf_raw_key_alg_id(raw_key) != vscf_alg_id_NONE);
    VSCF_ASSERT(vscf_raw_key_is_private(raw_key));

    self->impl_tag = impl_tag;
    self->raw_key = vscf_raw_key_shallow_copy((vscf_raw_key_t *)raw_key);
}

//
//  Return key data.
//
VSCF_PUBLIC vsc_data_t
vscf_raw_private_key_data(const vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->raw_key);

    return vscf_raw_key_data(self->raw_key);
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_raw_private_key_alg_id(const vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->raw_key);

    return vscf_raw_key_alg_id(self->raw_key);
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_raw_private_key_len(const vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->raw_key);

    return vscf_raw_key_data(self->raw_key).len;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_raw_private_key_bitlen(const vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->raw_key);

    return vscf_raw_key_data(self->raw_key).len * 8;
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_raw_private_key_impl_tag(const vscf_raw_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->impl_tag;
}
