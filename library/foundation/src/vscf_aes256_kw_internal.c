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
//  //  This module contains logic for interface/implementation architecture.
//  //  Do not use this module in any part of the code.
//  //
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_aes256_kw_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_aes256_kw_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_key_wrap.h"
#include "vscf_key_wrap_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_aes256_kw_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the  'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_AES256_KW,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_aes256_kw_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_aes256_kw_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_aes256_kw_restore_alg_info
};

//
//  Configuration of the interface API 'key wrap api'.
//
static const vscf_key_wrap_api_t key_wrap_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key wrap' MUST be equal to the  'vscf_api_tag_KEY_WRAP'.
    //
    vscf_api_tag_KEY_WRAP,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_AES256_KW,
    //
    //  Link to the inherited interface API 'alg'.
    //
    &alg_api,
    //
    //  Return buffer length required to hold a wrapped key for the given plain key length.
    //
    (vscf_key_wrap_api_wrapped_len_fn)vscf_aes256_kw_wrapped_len,
    //
    //  Return buffer length required to hold an unwrapped key for the given wrapped key length.
    //
    (vscf_key_wrap_api_unwrapped_len_fn)vscf_aes256_kw_unwrapped_len,
    //
    //  Wrap given key data using the Key Encryption Key (KEK).
    //
    (vscf_key_wrap_api_wrap_fn)vscf_aes256_kw_wrap,
    //
    //  Unwrap given key data using the Key Encryption Key (KEK).
    //
    (vscf_key_wrap_api_unwrap_fn)vscf_aes256_kw_unwrap
};

//
//  Compile-time known information about 'aes256 kw' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_AES256_KW,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_aes256_kw_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_aes256_kw_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_aes256_kw_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_aes256_kw_init(vscf_aes256_kw_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_aes256_kw_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_aes256_kw_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_aes256_kw_init()'.
//
VSCF_PUBLIC void
vscf_aes256_kw_cleanup(vscf_aes256_kw_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_aes256_kw_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_aes256_kw_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_aes256_kw_t *
vscf_aes256_kw_new(void) {

    vscf_aes256_kw_t *self = (vscf_aes256_kw_t *) vscf_alloc(sizeof (vscf_aes256_kw_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_aes256_kw_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_kw_new()'.
//
VSCF_PUBLIC void
vscf_aes256_kw_delete(vscf_aes256_kw_t *self) {

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

    vscf_aes256_kw_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_kw_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_aes256_kw_destroy(vscf_aes256_kw_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_aes256_kw_t *self = *self_ref;
    *self_ref = NULL;

    vscf_aes256_kw_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_aes256_kw_t *
vscf_aes256_kw_shallow_copy(vscf_aes256_kw_t *self) {

    // Proxy to the parent implementation.
    return (vscf_aes256_kw_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_aes256_kw_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_aes256_kw_init_ctx(vscf_aes256_kw_t *self) {

    VSCF_UNUSED(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_aes256_kw_cleanup_ctx(vscf_aes256_kw_t *self) {

    VSCF_UNUSED(self);
}

//
//  Return size of 'vscf_aes256_kw_t' type.
//
VSCF_PUBLIC size_t
vscf_aes256_kw_impl_size(void) {

    return sizeof (vscf_aes256_kw_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes256_kw_impl(vscf_aes256_kw_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_aes256_kw_impl_const(const vscf_aes256_kw_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_aes256_kw_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
        return (const vscf_api_t *)                 &alg_api;
        case vscf_api_tag_KEY_WRAP:
        return (const vscf_api_t *)                 &key_wrap_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
