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

#include "vscr_ratchet_group_participant_data.h"
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
//  Note, this method is called automatically when method vscr_ratchet_group_participant_data_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participant_data_init_ctx(vscr_ratchet_group_participant_data_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participant_data_cleanup_ctx(vscr_ratchet_group_participant_data_t *self);

//
//  Return size of 'vscr_ratchet_group_participant_data_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_participant_data_ctx_size(void) {

    return sizeof(vscr_ratchet_group_participant_data_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_data_init(vscr_ratchet_group_participant_data_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_participant_data_t));

    self->refcnt = 1;

    vscr_ratchet_group_participant_data_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_data_cleanup(vscr_ratchet_group_participant_data_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_group_participant_data_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_group_participant_data_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_participant_data_t *
vscr_ratchet_group_participant_data_new(void) {

    vscr_ratchet_group_participant_data_t *self = (vscr_ratchet_group_participant_data_t *) vscr_alloc(sizeof (vscr_ratchet_group_participant_data_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_participant_data_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_data_delete(vscr_ratchet_group_participant_data_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_group_participant_data_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_participant_data_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_participant_data_destroy(vscr_ratchet_group_participant_data_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_participant_data_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_participant_data_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_participant_data_t *
vscr_ratchet_group_participant_data_shallow_copy(vscr_ratchet_group_participant_data_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_participant_data_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_participant_data_init_ctx(vscr_ratchet_group_participant_data_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_participant_data_cleanup_ctx(vscr_ratchet_group_participant_data_t *self) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->epoch_count; i++) {
        vscr_ratchet_group_participant_epoch_destroy(&self->epoches[i]);
    }
}

VSCR_PUBLIC vscr_ratchet_group_participant_epoch_t *
vscr_ratchet_group_participant_data_add_epoch(vscr_ratchet_group_participant_data_t *self, size_t epoch) {

    VSCR_ASSERT_PTR(self);
    // FIXME
    VSCR_ASSERT(self->epoch_count == 0 || self->epoches[self->epoch_count - 1]->epoch < epoch);

    if (self->epoch_count == vscr_ratchet_common_hidden_MAX_EPOCHES_COUNT) {
        vscr_ratchet_group_participant_epoch_destroy(&self->epoches[0]);
        for (size_t i = 1; i < vscr_ratchet_common_hidden_MAX_EPOCHES_COUNT; i++) {
            self->epoches[i - 1] = self->epoches[i];
        }
        self->epoches[--self->epoch_count] = NULL;
    }

    vscr_ratchet_group_participant_epoch_t *new_epoch = vscr_ratchet_group_participant_epoch_new();
    new_epoch->epoch = epoch;

    self->epoches[self->epoch_count++] = new_epoch;

    return new_epoch;
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_data_delete_epoch(vscr_ratchet_group_participant_data_t *self, size_t epoch) {

    VSCR_ASSERT_PTR(self);

    size_t i = 0;
    for (; i < self->epoch_count; i++) {
        if (self->epoches[i]->epoch == epoch) {
            break;
        }
    }

    VSCR_ASSERT(i != self->epoch_count);

    vscr_ratchet_group_participant_epoch_destroy(&self->epoches[i]);

    for (size_t j = i; j < self->epoch_count - 1; i++) {
        self->epoches[j] = self->epoches[j + 1];
    }

    self->epoches[--self->epoch_count] = NULL;
}

VSCR_PUBLIC vscr_ratchet_group_participant_epoch_t *
vscr_ratchet_group_participant_data_find_epoch(const vscr_ratchet_group_participant_data_t *self, size_t epoch) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->epoch_count; i++) {
        if (self->epoches[i]->epoch == epoch)
            return self->epoches[i];
    }

    return NULL;
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_data_serialize(
        const vscr_ratchet_group_participant_data_t *self, ParticipantData *data_pb) {

    VSCR_ASSERT(self);
    VSCR_ASSERT(data_pb);

    memcpy(data_pb->id, self->id, sizeof(self->id));
    memcpy(data_pb->pub_key, self->pub_key, sizeof(self->pub_key));

    data_pb->epochs_count = self->epoch_count;

    for (size_t i = 0; i < self->epoch_count; i++) {
        vscr_ratchet_group_participant_epoch_serialize(self->epoches[i], &data_pb->epochs[i]);
    }
}

VSCR_PUBLIC void
vscr_ratchet_group_participant_data_deserialize(ParticipantData *data_pb, vscr_ratchet_group_participant_data_t *data) {

    VSCR_ASSERT(data_pb);
    VSCR_ASSERT(data);

    memcpy(data->pub_key, data_pb->pub_key, sizeof(data->pub_key));
    memcpy(data->id, data_pb->id, sizeof(data->id));

    data->epoch_count = data_pb->epochs_count;

    for (size_t i = 0; i < data->epoch_count; i++) {
        data->epoches[i] = vscr_ratchet_group_participant_epoch_new();
        vscr_ratchet_group_participant_epoch_deserialize(&data_pb->epochs[i], data->epoches[i]);
    }
}
