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
//  This class filter incoming data stream to keep a tail of the given length.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_tail_filter.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_tail_filter_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_tail_filter_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_tail_filter_init_ctx(vscf_tail_filter_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_tail_filter_cleanup_ctx(vscf_tail_filter_t *self);

//
//  Shift tail left for a given distance.
//
static void
vscf_tail_filter_shift(vscf_tail_filter_t *self, size_t distance);

//
//  Return size of 'vscf_tail_filter_t'.
//
VSCF_PUBLIC size_t
vscf_tail_filter_ctx_size(void) {

    return sizeof(vscf_tail_filter_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_tail_filter_init(vscf_tail_filter_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_tail_filter_t));

    self->refcnt = 1;

    vscf_tail_filter_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_tail_filter_cleanup(vscf_tail_filter_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_tail_filter_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_tail_filter_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_tail_filter_t *
vscf_tail_filter_new(void) {

    vscf_tail_filter_t *self = (vscf_tail_filter_t *) vscf_alloc(sizeof (vscf_tail_filter_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_tail_filter_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_tail_filter_delete(vscf_tail_filter_t *self) {

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

    vscf_tail_filter_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_tail_filter_new ()'.
//
VSCF_PUBLIC void
vscf_tail_filter_destroy(vscf_tail_filter_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_tail_filter_t *self = *self_ref;
    *self_ref = NULL;

    vscf_tail_filter_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_tail_filter_t *
vscf_tail_filter_shallow_copy(vscf_tail_filter_t *self) {

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
//  Note, this method is called automatically when method vscf_tail_filter_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_tail_filter_init_ctx(vscf_tail_filter_t *self) {

    VSCF_ASSERT_PTR(self);
    self->tail = vsc_buffer_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_tail_filter_cleanup_ctx(vscf_tail_filter_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->tail);
}

//
//  Prepare filter for a new byte stream.
//
VSCF_PUBLIC void
vscf_tail_filter_reset(vscf_tail_filter_t *self, size_t len) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_release(self->tail);
    vsc_buffer_alloc(self->tail, len);
}

//
//  Return filtered tail.
//
VSCF_PUBLIC vsc_data_t
vscf_tail_filter_tail(vscf_tail_filter_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_buffer_is_valid(self->tail));

    return vsc_buffer_data(self->tail);
}

//
//  Process given data and return filtered data guaranteed without a tail.
//
VSCF_PUBLIC void
vscf_tail_filter_process(vscf_tail_filter_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= data.len);

    const size_t tail_free_len = vsc_buffer_unused_len(self->tail);
    const size_t tail_total_len = vsc_buffer_capacity(self->tail);

    if (data.len <= tail_free_len) {
        vsc_buffer_write_data(self->tail, data);

    } else if (data.len >= tail_total_len) {
        vsc_buffer_write_data(out, vsc_buffer_data(self->tail));
        vsc_buffer_write_data(out, vsc_data_slice_beg(data, 0, data.len - tail_total_len));
        vsc_buffer_reset(self->tail);
        vsc_buffer_write_data(self->tail, vsc_data_slice_end(data, 0, tail_total_len));

    } else {
        vsc_buffer_write_data(out, vsc_data_slice_beg(vsc_buffer_data(self->tail), 0, data.len - tail_free_len));
        vscf_tail_filter_shift(self, data.len - tail_free_len);
        vsc_buffer_write_data(self->tail, data);
    }
}

//
//  Shift tail left for a given distance.
//
static void
vscf_tail_filter_shift(vscf_tail_filter_t *self, size_t distance) {

    VSCF_ASSERT_PTR(self);

    if (0 == distance) {
        return;
    }

    if (distance >= vsc_buffer_len(self->tail)) {
        vsc_buffer_reset(self->tail);
    }

    byte *tail_begin = vsc_buffer_begin(self->tail);

    memmove(tail_begin, tail_begin + distance, vsc_buffer_len(self->tail) - distance);

    vsc_buffer_dec_used(self->tail, distance);
}
