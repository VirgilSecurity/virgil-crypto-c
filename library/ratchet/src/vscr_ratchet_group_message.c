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

static bool
vscr_ratchet_group_message_buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void**arg);

static void
vscr_ratchet_group_message_set_pb_encode_callback(vscr_ratchet_group_message_t *self);

static void
vscr_ratchet_group_message_set_pb_decode_callback(vscr_ratchet_group_message_t *self);

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

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_group_message_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_group_message_t));
    }
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
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_delete(vscr_ratchet_group_message_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_group_message_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
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
//  Note, this method is called automatically when method vscr_ratchet_group_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_message_init_ctx(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    GroupMessage msg = GroupMessage_init_zero;

    self->message_pb = msg;
    self->key_id = vscr_ratchet_key_id_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_message_cleanup_ctx(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->message_pb.has_regular_message) {
        if (self->message_pb.regular_message.cipher_text.arg) {
            vsc_buffer_destroy((vsc_buffer_t **)&self->message_pb.regular_message.cipher_text.arg);
        }
    }

    vscr_dealloc(self->header_pb);

    vscr_ratchet_key_id_destroy(&self->key_id);
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
        switch (self->message_pb.group_info.type) {
        case MessageGroupInfo_Type_START:
            return vscr_group_msg_type_START_GROUP;
        case MessageGroupInfo_Type_ADD:
            return vscr_group_msg_type_ADD_MEMBERS;
        case MessageGroupInfo_Type_CHANGE:
            return vscr_group_msg_type_EPOCH_CHANGE;
        }
    }

    return vscr_group_msg_type_REGULAR;
}

VSCR_PRIVATE void
vscr_ratchet_group_message_set_type(vscr_ratchet_group_message_t *self, vscr_group_msg_type_t type) {

    VSCR_ASSERT_PTR(self);

    GroupMessage msg = GroupMessage_init_zero;
    self->message_pb = msg;

    switch (type) {
    case vscr_group_msg_type_REGULAR:
        self->message_pb.has_regular_message = true;
        self->message_pb.has_group_info = false;
        self->header_pb = vscr_alloc(sizeof(RegularGroupMessageHeader));
        RegularGroupMessageHeader hdr = RegularGroupMessageHeader_init_zero;
        *self->header_pb = hdr;
        break;

    case vscr_group_msg_type_START_GROUP:
    case vscr_group_msg_type_ADD_MEMBERS:
    case vscr_group_msg_type_EPOCH_CHANGE:
        self->message_pb.has_regular_message = false;
        self->message_pb.has_group_info = true;
        break;
    }

    switch (type) {
    case vscr_group_msg_type_REGULAR:
        break;

    case vscr_group_msg_type_START_GROUP:
        self->message_pb.group_info.type = MessageGroupInfo_Type_START;
        break;
    case vscr_group_msg_type_ADD_MEMBERS:
        self->message_pb.group_info.type = MessageGroupInfo_Type_ADD;
        break;
    case vscr_group_msg_type_EPOCH_CHANGE:
        self->message_pb.group_info.type = MessageGroupInfo_Type_CHANGE;
        break;
    }
}

//
//  Returns number of public keys.
//  This method should be called only for start group info message type.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_get_pub_key_count(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);

    VSCR_ASSERT(self->message_pb.has_group_info);
    return self->message_pb.group_info.participants_count;
}

//
//  Returns public key id for some participant id.
//  This method should be called only for start group info message type.
//
VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_group_message_get_pub_key_id(const vscr_ratchet_group_message_t *self, vsc_data_t participant_id) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_id);
    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    VSCR_ASSERT(self->message_pb.has_group_info);
    const MessageGroupInfo *info = &self->message_pb.group_info;

    for (size_t i = 0; i < info->participants_count; i++) {
        if (memcmp(info->participants[i].id, participant_id.bytes, participant_id.len) == 0) {

            vsc_buffer_t *key_id = vsc_buffer_new_with_capacity(vscr_ratchet_common_KEY_ID_LEN);

            vscr_status_t status = vscr_ratchet_key_id_compute_public_key_id(self->key_id,
                    vsc_data(info->participants[i].pub_key, sizeof(info->participants[i].pub_key)), key_id);

            if (status == vscr_status_SUCCESS) {
                return key_id;
            }

            return NULL;
        }
    }

    return NULL;
}

//
//  Returns message sender id.
//  This method should be called only for regular message type.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_message_get_sender_id(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->message_pb.has_regular_message);
    VSCR_ASSERT_PTR(self->header_pb);

    return vsc_data(self->header_pb->sender_id, sizeof(self->header_pb->sender_id));
}

//
//  Returns message sender id.
//  This method should be called only for regular message type.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_message_get_session_id(const vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->message_pb.has_group_info);

    return vsc_data(self->message_pb.group_info.session_id, sizeof(self->message_pb.group_info.session_id));
}

//
//  Buffer len to serialize this class.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_serialize_len(vscr_ratchet_group_message_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->message_pb.has_group_info != self->message_pb.has_regular_message);

    if (self->message_pb.has_group_info) {
        const MessageGroupInfo *info = &self->message_pb.group_info;

        return vscr_ratchet_common_hidden_MAX_GROUP_INFO_MESSAGE_LEN -
               (vscr_ratchet_common_MAX_PARTICIPANTS_COUNT - info->participants_count) *
                       vscr_ratchet_common_hidden_PARTICIPANT_LEN;
    } else if (self->message_pb.has_regular_message) {
        VSCR_ASSERT(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN >=
                    vsc_buffer_len(self->message_pb.regular_message.cipher_text.arg));
        return vscr_ratchet_common_hidden_MAX_GROUP_REGULAR_MESSAGE_LEN -
               vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN +
               vsc_buffer_len(self->message_pb.regular_message.cipher_text.arg);
    }

    VSCR_ASSERT(false);

    return 0;
}

//
//  Serializes instance.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_serialize(vscr_ratchet_group_message_t *self, vsc_buffer_t *output) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(output);
    VSCR_ASSERT(self->message_pb.has_group_info != self->message_pb.has_regular_message);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_group_message_serialize_len(self));

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_unused_len(output));

    vscr_ratchet_group_message_set_pb_encode_callback(self);

    VSCR_ASSERT(pb_encode(&ostream, GroupMessage_fields, &self->message_pb));
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

    vscr_ratchet_group_message_set_pb_decode_callback(message);

    bool pb_status = pb_decode(&istream, GroupMessage_fields, &message->message_pb);

    if (!pb_status || message->message_pb.has_group_info == message->message_pb.has_regular_message) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);
        goto err;
    }

    if (message->message_pb.has_group_info) {
        MessageGroupInfo *info = &message->message_pb.group_info;

        // Checking for duplicates
        for (size_t i = 0; i < info->participants_count; i++) {
            for (size_t j = 0; j < i; j++) {
                if (memcmp(info->participants[i].id, info->participants[j].id, sizeof(info->participants[i].id)) == 0) {
                    status = vscr_status_ERROR_DUPLICATE_ID;
                    goto err;
                }
            }
        }
    } else {
        pb_istream_t sub_istream = pb_istream_from_buffer(
                message->message_pb.regular_message.header, sizeof(message->message_pb.regular_message.header));

        message->header_pb = vscr_alloc(sizeof(RegularGroupMessageHeader));
        pb_status = pb_decode(&sub_istream, RegularGroupMessageHeader_fields, message->header_pb);

        if (!pb_status) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);
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

static bool
vscr_ratchet_group_message_buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void **arg) {

    return vscr_ratchet_common_hidden_buffer_decode_callback(
            stream, field, arg, vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);
}

static void
vscr_ratchet_group_message_set_pb_encode_callback(vscr_ratchet_group_message_t *self) {

    self->message_pb.regular_message.cipher_text.funcs.encode = vscr_ratchet_common_hidden_buffer_encode_callback;
}

static void
vscr_ratchet_group_message_set_pb_decode_callback(vscr_ratchet_group_message_t *self) {

    self->message_pb.regular_message.cipher_text.funcs.decode = vscr_ratchet_group_message_buffer_decode_callback;
}
