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
//  Handles public key or private key and it's identifier.
//
//  Note, that public key identifier equals to the private key identifier.
//  Note, a key identifier can be calculated with "key provider" class from the foundation library.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_key_handler.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_key_handler_private.h"
#include "vssc_key_handler_defs.h"

#include <virgil/crypto/common/vsc_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_key_handler_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_key_handler_init_ctx(vssc_key_handler_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_key_handler_cleanup_ctx(vssc_key_handler_t *self);

//
//  Constructor.
//
static void
vssc_key_handler_init_ctx_with(vssc_key_handler_t *self, vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key);

//
//  Constructor.
//
static void
vssc_key_handler_init_ctx_with_disown(vssc_key_handler_t *self, vsc_str_t identity, vsc_buffer_t **key_id_ref,
        vscf_impl_t **key_ref);

//
//  Return size of 'vssc_key_handler_t'.
//
VSSC_PUBLIC size_t
vssc_key_handler_ctx_size(void) {

    return sizeof(vssc_key_handler_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_key_handler_init(vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_key_handler_t));

    self->refcnt = 1;

    vssc_key_handler_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_key_handler_cleanup(vssc_key_handler_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_key_handler_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_key_handler_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_new(void) {

    vssc_key_handler_t *self = (vssc_key_handler_t *) vssc_alloc(sizeof (vssc_key_handler_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_key_handler_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Constructor.
//
VSSC_PUBLIC void
vssc_key_handler_init_with(vssc_key_handler_t *self, vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_key_handler_t));

    self->refcnt = 1;

    vssc_key_handler_init_ctx_with(self, identity, key_id, key);
}

//
//  Allocate class context and perform it's initialization.
//  Constructor.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_new_with(vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key) {

    vssc_key_handler_t *self = (vssc_key_handler_t *) vssc_alloc(sizeof (vssc_key_handler_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_key_handler_init_with(self, identity, key_id, key);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Constructor.
//
VSSC_PUBLIC void
vssc_key_handler_init_with_disown(vssc_key_handler_t *self, vsc_str_t identity, vsc_buffer_t **key_id_ref,
        vscf_impl_t **key_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_key_handler_t));

    self->refcnt = 1;

    vssc_key_handler_init_ctx_with_disown(self, identity, key_id_ref, key_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Constructor.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_new_with_disown(vsc_str_t identity, vsc_buffer_t **key_id_ref, vscf_impl_t **key_ref) {

    vssc_key_handler_t *self = (vssc_key_handler_t *) vssc_alloc(sizeof (vssc_key_handler_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_key_handler_init_with_disown(self, identity, key_id_ref, key_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_key_handler_delete(const vssc_key_handler_t *self) {

    vssc_key_handler_t *local_self = (vssc_key_handler_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssc_key_handler_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_key_handler_new ()'.
//
VSSC_PUBLIC void
vssc_key_handler_destroy(vssc_key_handler_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_key_handler_t *self = *self_ref;
    *self_ref = NULL;

    vssc_key_handler_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_key_handler_t *
vssc_key_handler_shallow_copy(vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_key_handler_t *
vssc_key_handler_shallow_copy_const(const vssc_key_handler_t *self) {

    return vssc_key_handler_shallow_copy((vssc_key_handler_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_key_handler_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_key_handler_init_ctx(vssc_key_handler_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_key_handler_cleanup_ctx(vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->identity);
    vsc_buffer_delete(self->key_id);
    vscf_impl_delete(self->key);
}

//
//  Constructor.
//
static void
vssc_key_handler_init_ctx_with(
        vssc_key_handler_t *self, vsc_str_t identity, vsc_data_t key_id, const vscf_impl_t *key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT(vsc_data_is_valid_and_non_empty(key_id));
    VSSC_ASSERT_PTR(key);

    self->identity = vsc_str_mutable_from_str(identity);
    self->key_id = vsc_buffer_new_with_data(key_id);
    self->key = vscf_impl_shallow_copy_const(key);
}

//
//  Constructor.
//
static void
vssc_key_handler_init_ctx_with_disown(
        vssc_key_handler_t *self, vsc_str_t identity, vsc_buffer_t **key_id_ref, vscf_impl_t **key_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT_PTR(key_id_ref);
    VSSC_ASSERT(vsc_buffer_is_valid(*key_id_ref));
    VSSC_ASSERT(vsc_buffer_len(*key_id_ref) > 0);
    VSSC_ASSERT_REF(key_ref);

    self->identity = vsc_str_mutable_from_str(identity);
    self->key_id = *key_id_ref;
    self->key = *key_ref;

    *key_id_ref = NULL;
    *key_ref = NULL;
}

//
//  Return user's identity associated with the key.
//
VSSC_PUBLIC vsc_str_t
vssc_key_handler_identity(const vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->identity);
}

//
//  Return public key identifier regardless of the underlying key - public or private.
//
VSSC_PUBLIC vsc_data_t
vssc_key_handler_key_id(const vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->key_id);

    return vsc_buffer_data(self->key_id);
}

//
//  Return key.
//
VSSC_PUBLIC const vscf_impl_t *
vssc_key_handler_key(const vssc_key_handler_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->key);

    return self->key;
}
