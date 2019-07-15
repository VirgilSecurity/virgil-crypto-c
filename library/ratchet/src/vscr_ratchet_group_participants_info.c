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
//  Container for array of participants' info
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_group_participants_info.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_group_participants_info_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_participants_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participants_info_init_ctx(vscr_ratchet_group_participants_info_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participants_info_cleanup_ctx(vscr_ratchet_group_participants_info_t *self);

//
//  Creates new array for size elements
//
static void
vscr_ratchet_group_participants_info_init_ctx_size(vscr_ratchet_group_participants_info_t *self, uint32_t size);

//
//  Return size of 'vscr_ratchet_group_participants_info_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_participants_info_ctx_size(void) {

    return sizeof(vscr_ratchet_group_participants_info_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_init(vscr_ratchet_group_participants_info_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participants_info_t));

    self->refcnt = 1;

    vscr_ratchet_group_participants_info_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_cleanup(vscr_ratchet_group_participants_info_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_group_participants_info_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participants_info_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_new(void) {

    vscr_ratchet_group_participants_info_t *self = (vscr_ratchet_group_participants_info_t *) vscr_alloc(sizeof (vscr_ratchet_group_participants_info_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_participants_info_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Creates new array for size elements
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_init_size(vscr_ratchet_group_participants_info_t *self, uint32_t size) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participants_info_t));

    self->refcnt = 1;

    vscr_ratchet_group_participants_info_init_ctx_size(self, size);
}

//
//  Allocate class context and perform it's initialization.
//  Creates new array for size elements
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_new_size(uint32_t size) {

    vscr_ratchet_group_participants_info_t *self = (vscr_ratchet_group_participants_info_t *) vscr_alloc(sizeof (vscr_ratchet_group_participants_info_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_participants_info_init_size(self, size);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_delete(vscr_ratchet_group_participants_info_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCR_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCR_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_group_participants_info_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_participants_info_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_participants_info_destroy(vscr_ratchet_group_participants_info_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_participants_info_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_participants_info_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_participants_info_t *
vscr_ratchet_group_participants_info_shallow_copy(vscr_ratchet_group_participants_info_t *self) {

    VSCR_ASSERT_PTR(self);

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
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
//  Note, this method is called automatically when method vscr_ratchet_group_participants_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participants_info_init_ctx(vscr_ratchet_group_participants_info_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(false);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participants_info_cleanup_ctx(vscr_ratchet_group_participants_info_t *self) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->count; i++) {
        vscr_ratchet_group_participant_info_destroy(&self->participants[i]);
    }

    vscr_dealloc(self->participants);
    vscr_ratchet_key_utils_destroy(&self->key_utils);
}

//
//  Creates new array for size elements
//
static void
vscr_ratchet_group_participants_info_init_ctx_size(vscr_ratchet_group_participants_info_t *self, uint32_t size) {

    VSCR_ASSERT_PTR(self);

    self->key_utils = vscr_ratchet_key_utils_new();

    if (size != 0) {
        self->participants = vscr_alloc(size * sizeof(vscr_ratchet_group_participant_info_t *));
    }
    self->size = size;
    self->count = 0;
}

//
//  Add participant info
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_participants_info_add_participant(
        vscr_ratchet_group_participants_info_t *self, vsc_data_t id, vsc_data_t pub_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->count < self->size);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT(vsc_data_is_valid(id));
    VSCR_ASSERT(id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    vscr_error_t error;
    vscr_error_reset(&error);

    vsc_buffer_t *public_key =
            vscr_ratchet_key_utils_extract_ratchet_public_key(self->key_utils, pub_key, true, false, false, &error);

    if (!public_key) {
        return error.status;
    }

    vscr_ratchet_group_participant_info_t *info = vscr_ratchet_group_participant_info_new();

    memcpy(info->pub_key, vsc_buffer_bytes(public_key), vscr_ratchet_common_hidden_KEY_LEN);
    memcpy(info->id, id.bytes, id.len);

    self->participants[self->count++] = info;

    vsc_buffer_destroy(&public_key);

    return vscr_status_SUCCESS;
}
