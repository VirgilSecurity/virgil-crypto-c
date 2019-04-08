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
//  Class represents ratchet message
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_common.h"

#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
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
//  Note, this method is called automatically when method vscr_ratchet_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *self);

static bool
vscr_ratchet_message_buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void**arg);

static void
vscr_ratchet_message_set_pb_encode_callback(vscr_ratchet_message_t *self);

static void
vscr_ratchet_message_set_pb_decode_callback(vscr_ratchet_message_t *self);

//
//  Return size of 'vscr_ratchet_message_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_message_ctx_size(void) {

    return sizeof(vscr_ratchet_message_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_message_init(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_message_t));

    self->refcnt = 1;

    vscr_ratchet_message_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_message_cleanup(vscr_ratchet_message_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_message_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_message_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_new(void) {

    vscr_ratchet_message_t *self = (vscr_ratchet_message_t *) vscr_alloc(sizeof (vscr_ratchet_message_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_message_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_message_delete(vscr_ratchet_message_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_message_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_message_destroy(vscr_ratchet_message_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_message_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_message_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_shallow_copy(vscr_ratchet_message_t *self) {

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
//  Note, this method is called automatically when method vscr_ratchet_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    Message msg = Message_init_zero;

    self->message_pb = msg;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    RegularMessage *msg = NULL;

    if (self->message_pb.has_prekey_message) {
        msg = &self->message_pb.prekey_message.regular_message;
    } else if (self->message_pb.has_regular_message) {
        msg = &self->message_pb.regular_message;
    }

    if (msg && msg->cipher_text.arg) {
        vsc_buffer_destroy((vsc_buffer_t **)&msg->cipher_text.arg);
    }
}

//
//  Returns message type.
//
VSCR_PUBLIC vscr_msg_type_t
vscr_ratchet_message_get_type(const vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->message_pb.has_prekey_message) {
        return vscr_msg_type_PREKEY;
    } else if (self->message_pb.has_regular_message) {
        return vscr_msg_type_REGULAR;
    } else {
        VSCR_ASSERT(false);
    }

    return 0;
}

//
//  Returns long-term public key, if message is prekey message.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_long_term_public_key(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (!self->message_pb.has_prekey_message)
        return vsc_data_empty();

    return vsc_data(self->message_pb.prekey_message.receiver_long_term_key,
            sizeof(self->message_pb.prekey_message.receiver_long_term_key));
}

//
//  Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_one_time_public_key(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);

    if (!self->message_pb.has_prekey_message)
        return vsc_data_empty();

    if (!self->message_pb.prekey_message.has_receiver_one_time_key)
        return vsc_data_empty();

    return vsc_data(self->message_pb.prekey_message.receiver_one_time_key,
            sizeof(self->message_pb.prekey_message.receiver_one_time_key));
}

//
//  Buffer len to serialize this class.
//
VSCR_PUBLIC size_t
vscr_ratchet_message_serialize_len(vscr_ratchet_message_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->message_pb.has_prekey_message != self->message_pb.has_regular_message);

    if (self->message_pb.has_prekey_message) {
        VSCR_ASSERT(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN >=
                    vsc_buffer_len(self->message_pb.prekey_message.regular_message.cipher_text.arg));
        return vscr_ratchet_common_hidden_MAX_PREKEY_MESSAGE_LEN - vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN +
               vsc_buffer_len(self->message_pb.prekey_message.regular_message.cipher_text.arg);
    } else if (self->message_pb.has_regular_message) {
        VSCR_ASSERT(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN >=
                    vsc_buffer_len(self->message_pb.regular_message.cipher_text.arg));
        return vscr_ratchet_common_hidden_MAX_REGULAR_MESSAGE_LEN - vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN +
               vsc_buffer_len(self->message_pb.regular_message.cipher_text.arg);
    }

    VSCR_ASSERT(false);

    return 0;
}

//
//  Serializes instance.
//
VSCR_PUBLIC void
vscr_ratchet_message_serialize(vscr_ratchet_message_t *self, vsc_buffer_t *output) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(output);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_message_serialize_len(self));
    VSCR_ASSERT(self->message_pb.has_prekey_message != self->message_pb.has_regular_message);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    vscr_ratchet_message_set_pb_encode_callback(self);

    VSCR_ASSERT(pb_encode(&ostream, Message_fields, &self->message_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);
}

//
//  Deserializes instance.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_deserialize(vsc_data_t input, vscr_error_t *error) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > vscr_ratchet_common_MAX_MESSAGE_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        return NULL;
    }

    vscr_ratchet_message_t *message = vscr_ratchet_message_new();

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    vscr_ratchet_message_set_pb_decode_callback(message);

    bool status = pb_decode(&istream, Message_fields, &message->message_pb);

    if (!status || message->message_pb.has_prekey_message == message->message_pb.has_regular_message) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);
        vscr_ratchet_message_destroy(&message);

        return NULL;
    }

    return message;
}

static bool
vscr_ratchet_message_buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void **arg) {

    return vscr_ratchet_common_hidden_buffer_decode_callback(
            stream, field, arg, vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);
}

static void
vscr_ratchet_message_set_pb_encode_callback(vscr_ratchet_message_t *self) {

    self->message_pb.prekey_message.regular_message.cipher_text.funcs.encode =
            vscr_ratchet_common_hidden_buffer_encode_callback;
    self->message_pb.regular_message.cipher_text.funcs.encode = vscr_ratchet_common_hidden_buffer_encode_callback;
}

static void
vscr_ratchet_message_set_pb_decode_callback(vscr_ratchet_message_t *self) {

    self->message_pb.prekey_message.regular_message.cipher_text.funcs.decode =
            vscr_ratchet_message_buffer_decode_callback;
    self->message_pb.regular_message.cipher_text.funcs.decode = vscr_ratchet_message_buffer_decode_callback;
}
