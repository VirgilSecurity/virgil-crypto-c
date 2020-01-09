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
//  Handles padding parameters and constraints.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_padding_params.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_padding_params_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_padding_params_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_padding_params_init_ctx(vscf_padding_params_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_padding_params_cleanup_ctx(vscf_padding_params_t *self);

//
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
static void
vscf_padding_params_init_ctx_with_constraints(vscf_padding_params_t *self, size_t frame, size_t frame_max);

//
//  Return size of 'vscf_padding_params_t'.
//
VSCF_PUBLIC size_t
vscf_padding_params_ctx_size(void) {

    return sizeof(vscf_padding_params_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_padding_params_init(vscf_padding_params_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_padding_params_t));

    self->refcnt = 1;

    vscf_padding_params_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_padding_params_cleanup(vscf_padding_params_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_padding_params_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_padding_params_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_new(void) {

    vscf_padding_params_t *self = (vscf_padding_params_t *) vscf_alloc(sizeof (vscf_padding_params_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_padding_params_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
VSCF_PUBLIC void
vscf_padding_params_init_with_constraints(vscf_padding_params_t *self, size_t frame, size_t frame_max) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_padding_params_t));

    self->refcnt = 1;

    vscf_padding_params_init_ctx_with_constraints(self, frame, frame_max);
}

//
//  Allocate class context and perform it's initialization.
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_new_with_constraints(size_t frame, size_t frame_max) {

    vscf_padding_params_t *self = (vscf_padding_params_t *) vscf_alloc(sizeof (vscf_padding_params_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_padding_params_init_with_constraints(self, frame, frame_max);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_padding_params_delete(vscf_padding_params_t *self) {

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

    vscf_padding_params_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_padding_params_new ()'.
//
VSCF_PUBLIC void
vscf_padding_params_destroy(vscf_padding_params_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_padding_params_t *self = *self_ref;
    *self_ref = NULL;

    vscf_padding_params_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_padding_params_t *
vscf_padding_params_shallow_copy(vscf_padding_params_t *self) {

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
//  Note, this method is called automatically when method vscf_padding_params_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_padding_params_init_ctx(vscf_padding_params_t *self) {

    VSCF_ASSERT_PTR(self);

    self->frame = vscf_padding_params_DEFAULT_FRAME;
    self->frame_max = vscf_padding_params_DEFAULT_FRAME_MAX;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_padding_params_cleanup_ctx(vscf_padding_params_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Build padding params with given constraints.
//  Next formula can clarify what frame is: padding_length = data_length MOD frame
//
static void
vscf_padding_params_init_ctx_with_constraints(vscf_padding_params_t *self, size_t frame, size_t frame_max) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT((vscf_padding_params_DEFAULT_FRAME_MIN <= frame) && (frame <= frame_max));

    self->frame = frame;
    self->frame_max = frame_max;
}

//
//  Return padding frame in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_params_frame(const vscf_padding_params_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->frame;
}

//
//  Return maximum padding frame in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_params_frame_max(const vscf_padding_params_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->frame_max;
}
