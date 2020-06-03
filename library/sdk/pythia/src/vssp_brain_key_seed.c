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
//  Handles seed returned by the servie.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssp_brain_key_seed.h"
#include "vssp_memory.h"
#include "vssp_assert.h"
#include "vssp_brain_key_seed_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssp_brain_key_seed_init() is called.
//  Note, that context is already zeroed.
//
static void
vssp_brain_key_seed_init_ctx(vssp_brain_key_seed_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssp_brain_key_seed_cleanup_ctx(vssp_brain_key_seed_t *self);

//
//  Create object with a given seed.
//
static void
vssp_brain_key_seed_init_ctx_with_seed_disown(vssp_brain_key_seed_t *self, vsc_buffer_t **seed_ref);

//
//  Return size of 'vssp_brain_key_seed_t'.
//
VSSP_PUBLIC size_t
vssp_brain_key_seed_ctx_size(void) {

    return sizeof(vssp_brain_key_seed_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSP_PUBLIC void
vssp_brain_key_seed_init(vssp_brain_key_seed_t *self) {

    VSSP_ASSERT_PTR(self);

    vssp_zeroize(self, sizeof(vssp_brain_key_seed_t));

    self->refcnt = 1;

    vssp_brain_key_seed_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSP_PUBLIC void
vssp_brain_key_seed_cleanup(vssp_brain_key_seed_t *self) {

    if (self == NULL) {
        return;
    }

    vssp_brain_key_seed_cleanup_ctx(self);

    vssp_zeroize(self, sizeof(vssp_brain_key_seed_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_brain_key_seed_new(void) {

    vssp_brain_key_seed_t *self = (vssp_brain_key_seed_t *) vssp_alloc(sizeof (vssp_brain_key_seed_t));
    VSSP_ASSERT_ALLOC(self);

    vssp_brain_key_seed_init(self);

    self->self_dealloc_cb = vssp_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object with a given seed.
//
VSSP_PUBLIC void
vssp_brain_key_seed_init_with_seed_disown(vssp_brain_key_seed_t *self, vsc_buffer_t **seed_ref) {

    VSSP_ASSERT_PTR(self);

    vssp_zeroize(self, sizeof(vssp_brain_key_seed_t));

    self->refcnt = 1;

    vssp_brain_key_seed_init_ctx_with_seed_disown(self, seed_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create object with a given seed.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_brain_key_seed_new_with_seed_disown(vsc_buffer_t **seed_ref) {

    vssp_brain_key_seed_t *self = (vssp_brain_key_seed_t *) vssp_alloc(sizeof (vssp_brain_key_seed_t));
    VSSP_ASSERT_ALLOC(self);

    vssp_brain_key_seed_init_with_seed_disown(self, seed_ref);

    self->self_dealloc_cb = vssp_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSP_PUBLIC void
vssp_brain_key_seed_delete(const vssp_brain_key_seed_t *self) {

    vssp_brain_key_seed_t *local_self = (vssp_brain_key_seed_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSP_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSP_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssp_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssp_brain_key_seed_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssp_brain_key_seed_new ()'.
//
VSSP_PUBLIC void
vssp_brain_key_seed_destroy(vssp_brain_key_seed_t **self_ref) {

    VSSP_ASSERT_PTR(self_ref);

    vssp_brain_key_seed_t *self = *self_ref;
    *self_ref = NULL;

    vssp_brain_key_seed_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSP_PUBLIC vssp_brain_key_seed_t *
vssp_brain_key_seed_shallow_copy(vssp_brain_key_seed_t *self) {

    VSSP_ASSERT_PTR(self);

    #if defined(VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSP_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSP_PUBLIC const vssp_brain_key_seed_t *
vssp_brain_key_seed_shallow_copy_const(const vssp_brain_key_seed_t *self) {

    return vssp_brain_key_seed_shallow_copy((vssp_brain_key_seed_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssp_brain_key_seed_init() is called.
//  Note, that context is already zeroed.
//
static void
vssp_brain_key_seed_init_ctx(vssp_brain_key_seed_t *self) {

    VSSP_UNUSED(self);
    VSSP_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssp_brain_key_seed_cleanup_ctx(vssp_brain_key_seed_t *self) {

    VSSP_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->seed);
}

//
//  Create object with a given seed.
//
static void
vssp_brain_key_seed_init_ctx_with_seed_disown(vssp_brain_key_seed_t *self, vsc_buffer_t **seed_ref) {

    VSSP_ASSERT_PTR(self);
    VSSP_ASSERT_REF(seed_ref);
    VSSP_ASSERT(vsc_buffer_is_valid(*seed_ref));

    self->seed = *seed_ref;

    *seed_ref = NULL;
}

//
//  Return BrainKey seed.
//
VSSP_PUBLIC vsc_data_t
vssp_brain_key_seed_get(const vssp_brain_key_seed_t *self) {

    VSSP_ASSERT_PTR(self);
    VSSP_ASSERT_PTR(self->seed);

    return vsc_buffer_data(self->seed);
}
