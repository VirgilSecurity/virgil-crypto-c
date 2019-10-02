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
//  Handle information about signer that is defined by an identifer and
//  a Public Key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_signer_info.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_signer_info_defs.h"
#include "vscf_alg_info.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_signer_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_signer_info_init_ctx(vscf_signer_info_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_signer_info_cleanup_ctx(vscf_signer_info_t *self);

//
//  Create object and define all properties.
//
static void
vscf_signer_info_init_ctx_with_members(vscf_signer_info_t *self, vsc_data_t signer_id,
        vscf_impl_t **signer_alg_info_ref, vsc_buffer_t **signature_ref);

//
//  Return size of 'vscf_signer_info_t'.
//
VSCF_PUBLIC size_t
vscf_signer_info_ctx_size(void) {

    return sizeof(vscf_signer_info_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_signer_info_init(vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_signer_info_t));

    self->refcnt = 1;

    vscf_signer_info_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_signer_info_cleanup(vscf_signer_info_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_signer_info_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_signer_info_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_signer_info_t *
vscf_signer_info_new(void) {

    vscf_signer_info_t *self = (vscf_signer_info_t *) vscf_alloc(sizeof (vscf_signer_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_signer_info_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object and define all properties.
//
VSCF_PRIVATE void
vscf_signer_info_init_with_members(vscf_signer_info_t *self, vsc_data_t signer_id, vscf_impl_t **signer_alg_info_ref,
        vsc_buffer_t **signature_ref) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_signer_info_t));

    self->refcnt = 1;

    vscf_signer_info_init_ctx_with_members(self, signer_id, signer_alg_info_ref, signature_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create object and define all properties.
//
VSCF_PRIVATE vscf_signer_info_t *
vscf_signer_info_new_with_members(vsc_data_t signer_id, vscf_impl_t **signer_alg_info_ref,
        vsc_buffer_t **signature_ref) {

    vscf_signer_info_t *self = (vscf_signer_info_t *) vscf_alloc(sizeof (vscf_signer_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_signer_info_init_with_members(self, signer_id, signer_alg_info_ref, signature_ref);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_signer_info_delete(vscf_signer_info_t *self) {

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

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_signer_info_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_signer_info_new ()'.
//
VSCF_PUBLIC void
vscf_signer_info_destroy(vscf_signer_info_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_signer_info_t *self = *self_ref;
    *self_ref = NULL;

    vscf_signer_info_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_signer_info_t *
vscf_signer_info_shallow_copy(vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_signer_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_signer_info_init_ctx(vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_signer_info_cleanup_ctx(vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->signer_id);
    vsc_buffer_destroy(&self->signature);
    vscf_impl_destroy(&self->signer_alg_info);
}

//
//  Create object and define all properties.
//
static void
vscf_signer_info_init_ctx_with_members(vscf_signer_info_t *self, vsc_data_t signer_id,
        vscf_impl_t **signer_alg_info_ref, vsc_buffer_t **signature_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_alg_info_ref);
    VSCF_ASSERT_PTR(*signer_alg_info_ref);
    VSCF_ASSERT(vscf_alg_info_is_implemented(*signer_alg_info_ref));
    VSCF_ASSERT(vsc_data_is_valid(signer_id));
    VSCF_ASSERT_PTR(signature_ref);
    VSCF_ASSERT_PTR(*signature_ref);
    VSCF_ASSERT(vsc_buffer_is_valid(*signature_ref));

    self->signer_id = vsc_buffer_new_with_data(signer_id);
    self->signature = *signature_ref;
    self->signer_alg_info = *signer_alg_info_ref;

    *signature_ref = NULL;
    *signer_alg_info_ref = NULL;
}

//
//  Return signer identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_signer_info_signer_id(const vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_id);

    return vsc_buffer_data(self->signer_id);
}

//
//  Return algorithm information that was used for data signing.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_signer_info_signer_alg_info(const vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_alg_info);

    return self->signer_alg_info;
}

//
//  Return data signature.
//
VSCF_PUBLIC vsc_data_t
vscf_signer_info_signature(const vscf_signer_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signature);

    return vsc_buffer_data(self->signature);
}
