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
//  Handle information about recipient that is defined by a Public Key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_recipient_info.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_key_recipient_info_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_recipient_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_recipient_info_init_ctx(vscf_key_recipient_info_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_recipient_info_cleanup_ctx(vscf_key_recipient_info_t *self);

//
//  Create object and define all properties.
//
static void
vscf_key_recipient_info_init_ctx_with_buffer(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_buffer_t **encrypted_key_ref);

//
//  Create object and define all properties.
//
static void
vscf_key_recipient_info_init_ctx_with_data(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_data_t encrypted_key);

//
//  Return size of 'vscf_key_recipient_info_t'.
//
VSCF_PUBLIC size_t
vscf_key_recipient_info_ctx_size(void) {

    return sizeof(vscf_key_recipient_info_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_recipient_info_init(vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_recipient_info_t));

    self->refcnt = 1;

    vscf_key_recipient_info_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_recipient_info_cleanup(vscf_key_recipient_info_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_key_recipient_info_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_key_recipient_info_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new(void) {

    vscf_key_recipient_info_t *self = (vscf_key_recipient_info_t *) vscf_alloc(sizeof (vscf_key_recipient_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_recipient_info_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object and define all properties.
//
VSCF_PRIVATE void
vscf_key_recipient_info_init_with_buffer(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_buffer_t **encrypted_key_ref) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_recipient_info_t));

    self->refcnt = 1;

    vscf_key_recipient_info_init_ctx_with_buffer(self, recipient_id, key_encryption_algorithm, encrypted_key_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create object and define all properties.
//
VSCF_PRIVATE vscf_key_recipient_info_t *
vscf_key_recipient_info_new_with_buffer(vsc_data_t recipient_id, const vscf_impl_t *key_encryption_algorithm,
        vsc_buffer_t **encrypted_key_ref) {

    vscf_key_recipient_info_t *self = (vscf_key_recipient_info_t *) vscf_alloc(sizeof (vscf_key_recipient_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_recipient_info_init_with_buffer(self, recipient_id, key_encryption_algorithm, encrypted_key_ref);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object and define all properties.
//
VSCF_PUBLIC void
vscf_key_recipient_info_init_with_data(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_data_t encrypted_key) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_key_recipient_info_t));

    self->refcnt = 1;

    vscf_key_recipient_info_init_ctx_with_data(self, recipient_id, key_encryption_algorithm, encrypted_key);
}

//
//  Allocate class context and perform it's initialization.
//  Create object and define all properties.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new_with_data(vsc_data_t recipient_id, const vscf_impl_t *key_encryption_algorithm,
        vsc_data_t encrypted_key) {

    vscf_key_recipient_info_t *self = (vscf_key_recipient_info_t *) vscf_alloc(sizeof (vscf_key_recipient_info_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_key_recipient_info_init_with_data(self, recipient_id, key_encryption_algorithm, encrypted_key);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_recipient_info_delete(vscf_key_recipient_info_t *self) {

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

    vscf_key_recipient_info_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_recipient_info_new ()'.
//
VSCF_PUBLIC void
vscf_key_recipient_info_destroy(vscf_key_recipient_info_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_key_recipient_info_t *self = *self_ref;
    *self_ref = NULL;

    vscf_key_recipient_info_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_shallow_copy(vscf_key_recipient_info_t *self) {

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
//  Note, this method is called automatically when method vscf_key_recipient_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_recipient_info_init_ctx(vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_recipient_info_cleanup_ctx(vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->recipient_id);
    vscf_impl_destroy((vscf_impl_t **)&self->key_encryption_algorithm);
    vsc_buffer_destroy(&self->encrypted_key);
}

//
//  Create object and define all properties.
//
static void
vscf_key_recipient_info_init_ctx_with_buffer(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_buffer_t **encrypted_key_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(key_encryption_algorithm);
    VSCF_ASSERT_PTR(encrypted_key_ref);
    VSCF_ASSERT_PTR(*encrypted_key_ref);
    VSCF_ASSERT(vsc_buffer_is_valid(*encrypted_key_ref));

    self->recipient_id = vsc_buffer_new_with_data(recipient_id);
    self->key_encryption_algorithm = vscf_impl_shallow_copy_const(key_encryption_algorithm);
    self->encrypted_key = *encrypted_key_ref;

    *encrypted_key_ref = NULL;
}

//
//  Create object and define all properties.
//
static void
vscf_key_recipient_info_init_ctx_with_data(vscf_key_recipient_info_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *key_encryption_algorithm, vsc_data_t encrypted_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(recipient_id));
    VSCF_ASSERT_PTR(key_encryption_algorithm);
    VSCF_ASSERT(vsc_data_is_valid(encrypted_key));
    VSCF_ASSERT(encrypted_key.len > 0);


    vsc_buffer_t *encrypted_key_buffer = vsc_buffer_new_with_data(encrypted_key);
    vscf_key_recipient_info_init_ctx_with_buffer(self, recipient_id, key_encryption_algorithm, &encrypted_key_buffer);
}

//
//  Return recipient identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_key_recipient_info_recipient_id(const vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->recipient_id));

    return vsc_buffer_data(self->recipient_id);
}

//
//  Return algorithm information that was used for encryption
//  a data encryption key.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_key_recipient_info_key_encryption_algorithm(const vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_encryption_algorithm);

    return self->key_encryption_algorithm;
}

//
//  Return an encrypted data encryption key.
//
VSCF_PUBLIC vsc_data_t
vscf_key_recipient_info_encrypted_key(const vscf_key_recipient_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->encrypted_key));

    return vsc_buffer_data(self->encrypted_key);
}
