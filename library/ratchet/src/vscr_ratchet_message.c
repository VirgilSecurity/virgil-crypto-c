//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "vscr_ratchet_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_message_defs.h"

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
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
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *ratchet_message);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *ratchet_message);

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
vscr_ratchet_message_init(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);

    vscr_zeroize(ratchet_message, sizeof(vscr_ratchet_message_t));

    ratchet_message->refcnt = 1;

    vscr_ratchet_message_init_ctx(ratchet_message);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_message_cleanup(vscr_ratchet_message_t *ratchet_message) {

    if (ratchet_message == NULL) {
        return;
    }

    if (ratchet_message->refcnt == 0) {
        return;
    }

    if (--ratchet_message->refcnt == 0) {
        vscr_ratchet_message_cleanup_ctx(ratchet_message);

        vscr_zeroize(ratchet_message, sizeof(vscr_ratchet_message_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_new(void) {

    vscr_ratchet_message_t *ratchet_message = (vscr_ratchet_message_t *) vscr_alloc(sizeof (vscr_ratchet_message_t));
    VSCR_ASSERT_ALLOC(ratchet_message);

    vscr_ratchet_message_init(ratchet_message);

    ratchet_message->self_dealloc_cb = vscr_dealloc;

    return ratchet_message;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_message_delete(vscr_ratchet_message_t *ratchet_message) {

    if (ratchet_message == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_message->self_dealloc_cb;

    vscr_ratchet_message_cleanup(ratchet_message);

    if (ratchet_message->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_message);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_message_destroy(vscr_ratchet_message_t **ratchet_message_ref) {

    VSCR_ASSERT_PTR(ratchet_message_ref);

    vscr_ratchet_message_t *ratchet_message = *ratchet_message_ref;
    *ratchet_message_ref = NULL;

    vscr_ratchet_message_delete(ratchet_message);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_shallow_copy(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);

    ++ratchet_message->refcnt;

    return ratchet_message;
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
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);

    ratchet_message->message = vscr_alloc(sizeof(Message));
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);

    vscr_dealloc(ratchet_message->message);
}

//
//  FIXME
//
VSCR_PUBLIC size_t
vscr_ratchet_message_get_type(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);

    if (ratchet_message->message->which_message == Message_prekey_message_tag) {
        return vscr_ratchet_message_RATCHET_MESSAGE_TYPE_PREKEY;
    } else if (ratchet_message->message->which_message == Message_regular_message_tag) {
        return vscr_ratchet_message_RATCHET_MESSAGE_TYPE_REGULAR;
    } else {
        VSCR_ASSERT(false);
    }

    return 0;
}

//
//  FIXME
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_long_term_public_key(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);
    VSCR_ASSERT(ratchet_message->message->which_message == Message_prekey_message_tag);

    return vsc_data(ratchet_message->message->message.prekey_message.receiver_longterm_key,
            sizeof(ratchet_message->message->message.prekey_message.receiver_longterm_key));
}

//
//  FIXME
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_compute_long_term_public_key_id(vscr_ratchet_message_t *ratchet_message) {

    //  TODO: This is STUB. Implement me.

    VSCR_ASSERT_PTR(ratchet_message);
    VSCR_ASSERT(ratchet_message->message->which_message == Message_prekey_message_tag);

    return vsc_data(ratchet_message->message->message.prekey_message.receiver_longterm_key,
            sizeof(ratchet_message->message->message.prekey_message.receiver_longterm_key));
}

//
//  FIXME
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_one_time_public_key(vscr_ratchet_message_t *ratchet_message) {

    VSCR_ASSERT_PTR(ratchet_message);
    VSCR_ASSERT(ratchet_message->message->which_message == Message_prekey_message_tag);

    return vsc_data(ratchet_message->message->message.prekey_message.receiver_onetime_key,
            sizeof(ratchet_message->message->message.prekey_message.receiver_onetime_key));
}

//
//  FIXME
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_compute_one_time_public_key_id(vscr_ratchet_message_t *ratchet_message) {

    //  TODO: This is STUB. Implement me.

    VSCR_ASSERT_PTR(ratchet_message);
    VSCR_ASSERT(ratchet_message->message->which_message == Message_prekey_message_tag);

    return vsc_data(ratchet_message->message->message.prekey_message.receiver_onetime_key,
            sizeof(ratchet_message->message->message.prekey_message.receiver_onetime_key));
}

VSCR_PUBLIC size_t
vscr_ratchet_message_serialize_len(vscr_ratchet_message_t *ratchet_message) {

    VSCR_UNUSED(ratchet_message);

    //  TODO: This is STUB. Implement me.

    return 500;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_message_serialize(vscr_ratchet_message_t *ratchet_message, vsc_buffer_t *output) {

    VSCR_UNUSED(ratchet_message);
    VSCR_UNUSED(output);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= 0); // FIXME

    //  TODO: This is STUB. Implement me.

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    bool status = pb_encode(&ostream, Message_fields, ratchet_message->message);
    VSCR_ASSERT(status); // FIXME

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_UNUSED(input);
    VSCR_UNUSED(err_ctx);

    vscr_ratchet_message_t *message = vscr_ratchet_message_new();

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool status = pb_decode(&istream, Message_fields, message->message);
    VSCR_ASSERT(status);

    return message;
}
