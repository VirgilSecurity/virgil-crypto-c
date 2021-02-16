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
//  Handles Brainkey hardened point returned by the service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssb_brainkey_hardened_point.h"
#include "vssb_memory.h"
#include "vssb_assert.h"
#include "vssb_brainkey_hardened_point_private.h"
#include "vssb_brainkey_hardened_point_defs.h"

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
//  Note, this method is called automatically when method vssb_brainkey_hardened_point_init() is called.
//  Note, that context is already zeroed.
//
static void
vssb_brainkey_hardened_point_init_ctx(vssb_brainkey_hardened_point_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssb_brainkey_hardened_point_cleanup_ctx(vssb_brainkey_hardened_point_t *self);

//
//  Create object with a given Brainkey hardened point.
//
static void
vssb_brainkey_hardened_point_init_ctx_with_value_disown(vssb_brainkey_hardened_point_t *self,
        vsc_buffer_t **hardened_point_ref);

//
//  Return size of 'vssb_brainkey_hardened_point_t'.
//
VSSB_PUBLIC size_t
vssb_brainkey_hardened_point_ctx_size(void) {

    return sizeof(vssb_brainkey_hardened_point_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_init(vssb_brainkey_hardened_point_t *self) {

    VSSB_ASSERT_PTR(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_hardened_point_t));

    self->refcnt = 1;

    vssb_brainkey_hardened_point_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_cleanup(vssb_brainkey_hardened_point_t *self) {

    if (self == NULL) {
        return;
    }

    vssb_brainkey_hardened_point_cleanup_ctx(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_hardened_point_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_new(void) {

    vssb_brainkey_hardened_point_t *self = (vssb_brainkey_hardened_point_t *) vssb_alloc(sizeof (vssb_brainkey_hardened_point_t));
    VSSB_ASSERT_ALLOC(self);

    vssb_brainkey_hardened_point_init(self);

    self->self_dealloc_cb = vssb_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object with a given Brainkey hardened point.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_init_with_value_disown(vssb_brainkey_hardened_point_t *self,
        vsc_buffer_t **hardened_point_ref) {

    VSSB_ASSERT_PTR(self);

    vssb_zeroize(self, sizeof(vssb_brainkey_hardened_point_t));

    self->refcnt = 1;

    vssb_brainkey_hardened_point_init_ctx_with_value_disown(self, hardened_point_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create object with a given Brainkey hardened point.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_new_with_value_disown(vsc_buffer_t **hardened_point_ref) {

    vssb_brainkey_hardened_point_t *self = (vssb_brainkey_hardened_point_t *) vssb_alloc(sizeof (vssb_brainkey_hardened_point_t));
    VSSB_ASSERT_ALLOC(self);

    vssb_brainkey_hardened_point_init_with_value_disown(self, hardened_point_ref);

    self->self_dealloc_cb = vssb_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_delete(const vssb_brainkey_hardened_point_t *self) {

    vssb_brainkey_hardened_point_t *local_self = (vssb_brainkey_hardened_point_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSB_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSB_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssb_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssb_brainkey_hardened_point_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssb_brainkey_hardened_point_new ()'.
//
VSSB_PUBLIC void
vssb_brainkey_hardened_point_destroy(vssb_brainkey_hardened_point_t **self_ref) {

    VSSB_ASSERT_PTR(self_ref);

    vssb_brainkey_hardened_point_t *self = *self_ref;
    *self_ref = NULL;

    vssb_brainkey_hardened_point_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSB_PUBLIC vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_shallow_copy(vssb_brainkey_hardened_point_t *self) {

    VSSB_ASSERT_PTR(self);

    #if defined(VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSB_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSB_PUBLIC const vssb_brainkey_hardened_point_t *
vssb_brainkey_hardened_point_shallow_copy_const(const vssb_brainkey_hardened_point_t *self) {

    return vssb_brainkey_hardened_point_shallow_copy((vssb_brainkey_hardened_point_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssb_brainkey_hardened_point_init() is called.
//  Note, that context is already zeroed.
//
static void
vssb_brainkey_hardened_point_init_ctx(vssb_brainkey_hardened_point_t *self) {

    VSSB_UNUSED(self);
    VSSB_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssb_brainkey_hardened_point_cleanup_ctx(vssb_brainkey_hardened_point_t *self) {

    VSSB_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->hardened_point);
}

//
//  Create object with a given Brainkey hardened point.
//
static void
vssb_brainkey_hardened_point_init_ctx_with_value_disown(
        vssb_brainkey_hardened_point_t *self, vsc_buffer_t **hardened_point_ref) {

    VSSB_ASSERT_PTR(self);
    VSSB_ASSERT_REF(hardened_point_ref);
    VSSB_ASSERT(vsc_buffer_is_valid(*hardened_point_ref));

    self->hardened_point = *hardened_point_ref;

    *hardened_point_ref = NULL;
}

//
//  Return Brainkey hardened point.
//
VSSB_PUBLIC vsc_data_t
vssb_brainkey_hardened_point_value(const vssb_brainkey_hardened_point_t *self) {

    VSSB_ASSERT_PTR(self);
    VSSB_ASSERT_PTR(self->hardened_point);

    return vsc_buffer_data(self->hardened_point);
}
