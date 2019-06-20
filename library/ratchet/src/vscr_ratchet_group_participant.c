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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_group_participant.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_participant_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participant_init_ctx(vscr_ratchet_group_participant_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participant_cleanup_ctx(vscr_ratchet_group_participant_t *self);

//
//  Return size of 'vscr_ratchet_group_participant_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_participant_ctx_size(void) {

    return sizeof(vscr_ratchet_group_participant_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_init(vscr_ratchet_group_participant_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participant_t));

    self->refcnt = 1;

    vscr_ratchet_group_participant_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_cleanup(vscr_ratchet_group_participant_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_group_participant_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participant_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_participant_t *
vscr_ratchet_group_participant_new(void) {

    vscr_ratchet_group_participant_t *self = (vscr_ratchet_group_participant_t *) vscr_alloc(sizeof (vscr_ratchet_group_participant_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_participant_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_delete(vscr_ratchet_group_participant_t *self) {

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

    vscr_ratchet_group_participant_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_participant_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_destroy(vscr_ratchet_group_participant_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_participant_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_participant_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_participant_t *
vscr_ratchet_group_participant_shallow_copy(vscr_ratchet_group_participant_t *self) {

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
//  Note, this method is called automatically when method vscr_ratchet_group_participant_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participant_init_ctx(vscr_ratchet_group_participant_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participant_cleanup_ctx(vscr_ratchet_group_participant_t *self) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; i++) {
        vscr_ratchet_group_participant_epoch_destroy(&self->epochs[i]);
    }
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_add_epoch(
        vscr_ratchet_group_participant_t *self, uint32_t epoch, vscr_ratchet_chain_key_t **chain_key_ref) {

    VSCR_ASSERT_PTR(self);

    size_t last_epoch = 0;

    if (self->epochs[0]) {
        last_epoch = self->epochs[0]->epoch;
        VSCR_ASSERT(epoch > last_epoch);
    }

    size_t shift = epoch - last_epoch;

    if (shift != 0) {
        for (size_t i = 0; i < shift && i < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; i++) {
            vscr_ratchet_group_participant_epoch_destroy(
                    &self->epochs[vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT - i - 1]);
        }

        for (size_t i = vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT - 1; i >= shift; i--) {
            self->epochs[i] = self->epochs[i - shift];
        }
    }

    self->epochs[0] = vscr_ratchet_group_participant_epoch_new();
    self->epochs[0]->epoch = epoch;
    self->epochs[0]->chain_key = *chain_key_ref;
    *chain_key_ref = NULL;
}

VSCR_PUBLIC vscr_ratchet_group_participant_epoch_t *
vscr_ratchet_group_participant_find_epoch(const vscr_ratchet_group_participant_t *self, uint32_t epoch) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; i++) {
        if (self->epochs[i] && self->epochs[i]->epoch == epoch)
            return self->epochs[i];
    }

    return NULL;
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_serialize(const vscr_ratchet_group_participant_t *self, ParticipantData *data_pb) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(data_pb);

    memcpy(data_pb->id, self->info.id, sizeof(self->info.id));
    memcpy(data_pb->pub_key, self->info.pub_key, sizeof(self->info.pub_key));

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; i++) {
        if (self->epochs[i]) {
            vscr_ratchet_group_participant_epoch_serialize(self->epochs[i], &data_pb->epochs[i]);
        } else {
            data_pb->epochs[i].is_empty = true;
        }
    }
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_deserialize(const ParticipantData *data_pb, vscr_ratchet_group_participant_t *data) {

    VSCR_ASSERT_PTR(data_pb);
    VSCR_ASSERT_PTR(data);

    memcpy(data->info.id, data_pb->id, sizeof(data->info.id));
    memcpy(data->info.pub_key, data_pb->pub_key, sizeof(data->info.pub_key));

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; i++) {
        if (!data_pb->epochs[i].is_empty) {
            data->epochs[i] = vscr_ratchet_group_participant_epoch_new();
            vscr_ratchet_group_participant_epoch_deserialize(&data_pb->epochs[i], data->epochs[i]);
        }
    }
}
