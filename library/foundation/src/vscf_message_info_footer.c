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
//  Handle message signatures and related information.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_footer.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_message_info_footer_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_info_footer_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_footer_init_ctx(vscf_message_info_footer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_footer_cleanup_ctx(vscf_message_info_footer_t *self);

//
//  Return size of 'vscf_message_info_footer_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_footer_ctx_size(void) {

    return sizeof(vscf_message_info_footer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_footer_init(vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_info_footer_t));

    self->refcnt = 1;

    vscf_message_info_footer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_footer_cleanup(vscf_message_info_footer_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_message_info_footer_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_message_info_footer_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_footer_t *
vscf_message_info_footer_new(void) {

    vscf_message_info_footer_t *self = (vscf_message_info_footer_t *) vscf_alloc(sizeof (vscf_message_info_footer_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_info_footer_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_info_footer_delete(vscf_message_info_footer_t *self) {

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

    vscf_message_info_footer_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_footer_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_footer_destroy(vscf_message_info_footer_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_info_footer_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_info_footer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_footer_t *
vscf_message_info_footer_shallow_copy(vscf_message_info_footer_t *self) {

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
//  Note, this method is called automatically when method vscf_message_info_footer_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_info_footer_init_ctx(vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->signer_infos = vscf_signer_info_list_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_info_footer_cleanup_ctx(vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_signer_info_list_destroy(&self->signer_infos);
    vscf_impl_destroy(&self->signer_hash_alg_info);
    vsc_buffer_destroy(&self->signer_digest);
}

//
//  Return true if at least one signer info presents.
//
VSCF_PUBLIC bool
vscf_message_info_footer_has_signer_infos(const vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->signer_infos != NULL && vscf_signer_info_list_has_item(self->signer_infos);
}

//
//  Add signer that is defined by Private Key.
//
VSCF_PRIVATE void
vscf_message_info_footer_add_signer_info(vscf_message_info_footer_t *self, vscf_signer_info_t **signer_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_infos);
    VSCF_ASSERT_PTR(signer_info_ref);
    VSCF_ASSERT_PTR(*signer_info_ref);

    vscf_signer_info_list_add(self->signer_infos, signer_info_ref);
}

//
//  Remove all "signer info" elements.
//
VSCF_PRIVATE void
vscf_message_info_footer_clear_signer_infos(vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_infos);

    vscf_signer_info_list_clear(self->signer_infos);
}

//
//  Return list with a "signer info" elements.
//
VSCF_PUBLIC const vscf_signer_info_list_t *
vscf_message_info_footer_signer_infos(const vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_infos);

    return self->signer_infos;
}

//
//  Set information about algorithm that was used for data hashing.
//
VSCF_PRIVATE void
vscf_message_info_footer_set_signer_hash_alg_info(
        vscf_message_info_footer_t *self, vscf_impl_t **signer_hash_alg_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_hash_alg_info_ref);
    VSCF_ASSERT_PTR(*signer_hash_alg_info_ref);

    vscf_impl_destroy(&self->signer_hash_alg_info);
    self->signer_hash_alg_info = *signer_hash_alg_info_ref;
    *signer_hash_alg_info_ref = NULL;
}

//
//  Return information about algorithm that was used for data hashing.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_message_info_footer_signer_hash_alg_info(const vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_hash_alg_info);

    return self->signer_hash_alg_info;
}

//
//  Set plain text digest that was used to produce signature.
//
VSCF_PRIVATE void
vscf_message_info_footer_set_signer_digest(vscf_message_info_footer_t *self, vsc_buffer_t **digest_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(digest_ref);
    VSCF_ASSERT_PTR(*digest_ref);
    VSCF_ASSERT(vsc_buffer_is_valid(*digest_ref));

    vsc_buffer_destroy(&self->signer_digest);
    self->signer_digest = *digest_ref;
    *digest_ref = NULL;
}

//
//  Return plain text digest that was used to produce signature.
//
VSCF_PUBLIC vsc_data_t
vscf_message_info_footer_signer_digest(const vscf_message_info_footer_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->signer_digest);

    return vsc_buffer_data(self->signer_digest);
}
