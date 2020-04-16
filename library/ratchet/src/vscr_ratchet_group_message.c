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
//  Class represents ratchet group message
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_group_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_group_message_internal.h"
#include "vscr_ratchet_group_message_defs.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_common.h"

#include <pb_decode.h>
#include <pb_encode.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_message_init_ctx(vscr_ratchet_group_message_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_message_cleanup_ctx(vscr_ratchet_group_message_t *self);

//
//  Return size of 'vscr_ratchet_group_message_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_ctx_size(void) {

    return sizeof(vscr_ratchet_group_message_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_init(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_message_t));

    self->refcnt = 1;

    vscr_ratchet_group_message_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_cleanup(vscr_ratchet_group_message_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_group_message_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_message_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_new(void) {

    vscr_ratchet_group_message_t *self = (vscr_ratchet_group_message_t *) vscr_alloc(sizeof (vscr_ratchet_group_message_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_message_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_delete(vscr_ratchet_group_message_t *self) {

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

    vscr_ratchet_group_message_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_destroy(vscr_ratchet_group_message_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_message_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_message_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_shallow_copy(vscr_ratchet_group_message_t *self) {

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
//  Note, this method is called automatically when method vscr_ratchet_group_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_message_init_ctx(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_GroupMessage msg = vscr_GroupMessage_init_zero;

    self->message_pb = msg;
    self->message_pb.version = vscr_ratchet_common_hidden_GROUP_MESSAGE_VERSION;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_message_cleanup_ctx(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_dealloc(self->header_pb);
    pb_release(vscr_GroupMessage_fields, &self->message_pb);
}

//
//  Returns message type.
//
VSCR_PUBLIC vscr_group_msg_type_t
vscr_ratchet_group_message_get_type(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT(self);

    if (self->message_pb.has_regular_message) {
        return vscr_group_msg_type_REGULAR;
    } else {
        VSCR_ASSERT(self->message_pb.has_group_info);
        return vscr_group_msg_type_GROUP_INFO;
    }
}

//
//  Returns session id.
//  This method should be called only for group info type.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_message_get_session_id(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->message_pb.has_group_info) {
        return vsc_data(self->message_pb.group_info.session_id, sizeof(self->message_pb.group_info.session_id));
    } else {
        VSCR_ASSERT_PTR(self->header_pb);
        return vsc_data(self->header_pb->session_id, sizeof(self->header_pb->session_id));
    }
}

//
//  Returns message counter in current epoch.
//
VSCR_PUBLIC uint32_t
vscr_ratchet_group_message_get_counter(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (!self->message_pb.has_regular_message) {
        return 0;
    }

    VSCR_ASSERT_PTR(self->header_pb);

    return self->header_pb->counter;
}

//
//  Returns message epoch.
//
VSCR_PUBLIC uint32_t
vscr_ratchet_group_message_get_epoch(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->message_pb.has_regular_message) {
        VSCR_ASSERT_PTR(self->header_pb);
        return self->header_pb->epoch;
    } else {
        return self->message_pb.group_info.epoch;
    }
}

VSCR_PUBLIC void
vscr_ratchet_group_message_set_type(vscr_ratchet_group_message_t *self, vscr_group_msg_type_t type) {

    VSCR_ASSERT_PTR(self);

    vscr_GroupMessage msg = vscr_GroupMessage_init_zero;
    self->message_pb = msg;

    switch (type) {
    case vscr_group_msg_type_REGULAR:
        self->message_pb.has_regular_message = true;
        self->message_pb.has_group_info = false;
        self->header_pb = vscr_alloc(sizeof(vscr_RegularGroupMessageHeader));
        vscr_RegularGroupMessageHeader hdr = vscr_RegularGroupMessageHeader_init_zero;
        *self->header_pb = hdr;
        break;

    case vscr_group_msg_type_GROUP_INFO:
        self->message_pb.has_regular_message = false;
        self->message_pb.has_group_info = true;
        break;
    }
}

//
//  Buffer len to serialize this class.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_serialize_len(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->message_pb.has_group_info != self->message_pb.has_regular_message);

    size_t len = 0;
    VSCR_ASSERT(pb_get_encoded_size(&len, vscr_GroupMessage_fields, &self->message_pb));

    return len;
}

//
//  Serializes instance.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_serialize(const vscr_ratchet_group_message_t *self, vsc_buffer_t *output) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(output);
    VSCR_ASSERT(self->message_pb.has_group_info != self->message_pb.has_regular_message);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_group_message_serialize_len(self));

    if (self->message_pb.has_regular_message) {
        VSCR_ASSERT(self->message_pb.regular_message.header.size > 0);
    }

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_unused_len(output));

    VSCR_ASSERT(pb_encode(&ostream, vscr_GroupMessage_fields, &self->message_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);
}

//
//  Deserializes instance.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_deserialize(vsc_data_t input, vscr_error_t *error) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > vscr_ratchet_common_MAX_GROUP_MESSAGE_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        return NULL;
    }

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_group_message_t *message = vscr_ratchet_group_message_new();

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool pb_status = pb_decode(&istream, vscr_GroupMessage_fields, &message->message_pb);

    if (!pb_status || message->message_pb.has_group_info == message->message_pb.has_regular_message) {
        status = vscr_status_ERROR_PROTOBUF_DECODE;
        goto err;
    }

    if (message->message_pb.has_regular_message) {
        pb_istream_t sub_istream = pb_istream_from_buffer(
                message->message_pb.regular_message.header.bytes, message->message_pb.regular_message.header.size);

        message->header_pb = vscr_alloc(sizeof(vscr_RegularGroupMessageHeader));
        pb_status = pb_decode(&sub_istream, vscr_RegularGroupMessageHeader_fields, message->header_pb);

        if (!pb_status) {
            status = vscr_status_ERROR_PROTOBUF_DECODE;
            goto err;
        }
    }

err:
    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, status);
        vscr_ratchet_group_message_destroy(&message);
    }

    return message;
}
