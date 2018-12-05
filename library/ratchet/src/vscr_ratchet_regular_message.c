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

#include "vscr_ratchet_regular_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <virgil/crypto/foundation/vscf_asn1wr.h>
#include <virgil/crypto/foundation/vscf_asn1rd.h>

// clang-format on
//  @end

#include <pb_encode.h>
#include <pb_decode.h>
#include <Message.pb.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_regular_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_regular_message_init_ctx(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_regular_message_cleanup_ctx(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx);

//
//  Return size of 'vscr_ratchet_regular_message_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_regular_message_ctx_size(void) {

    return sizeof(vscr_ratchet_regular_message_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_init(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);

    vscr_zeroize(ratchet_regular_message_ctx, sizeof(vscr_ratchet_regular_message_t));

    ratchet_regular_message_ctx->refcnt = 1;

    vscr_ratchet_regular_message_init_ctx(ratchet_regular_message_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_cleanup(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    if (ratchet_regular_message_ctx == NULL) {
        return;
    }

    if (ratchet_regular_message_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_regular_message_ctx->refcnt == 0) {
        vscr_ratchet_regular_message_cleanup_ctx(ratchet_regular_message_ctx);

        vscr_zeroize(ratchet_regular_message_ctx, sizeof(vscr_ratchet_regular_message_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_new(void) {

    vscr_ratchet_regular_message_t *ratchet_regular_message_ctx = (vscr_ratchet_regular_message_t *) vscr_alloc(sizeof (vscr_ratchet_regular_message_t));
    VSCR_ASSERT_ALLOC(ratchet_regular_message_ctx);

    vscr_ratchet_regular_message_init(ratchet_regular_message_ctx);

    ratchet_regular_message_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_regular_message_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_delete(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    if (ratchet_regular_message_ctx == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_regular_message_ctx->self_dealloc_cb;

    vscr_ratchet_regular_message_cleanup(ratchet_regular_message_ctx);

    if (ratchet_regular_message_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_regular_message_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_regular_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_regular_message_destroy(vscr_ratchet_regular_message_t **ratchet_regular_message_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx_ref);

    vscr_ratchet_regular_message_t *ratchet_regular_message_ctx = *ratchet_regular_message_ctx_ref;
    *ratchet_regular_message_ctx_ref = NULL;

    vscr_ratchet_regular_message_delete(ratchet_regular_message_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_copy(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);

    ++ratchet_regular_message_ctx->refcnt;

    return ratchet_regular_message_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_regular_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_regular_message_init_ctx(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_regular_message_cleanup_ctx(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);

    vsc_buffer_destroy(&ratchet_regular_message_ctx->public_key);
    vsc_buffer_destroy(&ratchet_regular_message_ctx->cipher_text);
}

VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_new_with_members(uint8_t version, uint32_t counter, vsc_buffer_t *public_key,
        vsc_buffer_t *cipher_text) {

    VSCR_ASSERT(vsc_buffer_is_valid(cipher_text));

    if (vsc_buffer_len(public_key) != vscr_ratchet_regular_message_PUBLIC_KEY_LENGTH) {

        return NULL;
    }

    vscr_ratchet_regular_message_t *ratchet_regular_message_ctx = vscr_ratchet_regular_message_new();

    ratchet_regular_message_ctx->version = version;
    ratchet_regular_message_ctx->counter = counter;
    ratchet_regular_message_ctx->public_key = vsc_buffer_copy(public_key);
    ratchet_regular_message_ctx->cipher_text = vsc_buffer_copy(cipher_text);

    return ratchet_regular_message_ctx;
}

VSCR_PUBLIC size_t
vscr_ratchet_regular_message_serialize_len(size_t cipher_text_len) {

    //  RATCHETRegularMessage ::= SEQUENCE {
    //       version INTEGER,
    //       counter INTEGER,
    //       public_key OCTET_STRING,
    //       cipher_text OCTET_STRING }

    size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                              + 1 + 1 + 2 /* INTEGER */
                              + 1 + 1 + 5 /* INTEGER */
                              + 1 + 1 + vscr_ratchet_regular_message_PUBLIC_KEY_LENGTH /* public_key */
                              + 1 + 3 + cipher_text_len; /* cipher_text */

    return top_sequence_len;
}

VSCR_PUBLIC size_t
vscr_ratchet_regular_message_serialize_len_ext(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);

    // TODO: Optimize
    size_t size = 0;
    RegularMessage regular_message = RegularMessage_init_zero;
    bool pb_status;

    memcpy(regular_message.cipher_text.bytes, ratchet_regular_message_ctx->cipher_text->bytes,
           ratchet_regular_message_ctx->cipher_text->len);

    regular_message.cipher_text.size += ratchet_regular_message_ctx->cipher_text->len;

    memcpy(regular_message.public_key, ratchet_regular_message_ctx->public_key->bytes,
           ratchet_regular_message_ctx->public_key->len);

    regular_message.counter = ratchet_regular_message_ctx->counter;

    regular_message.version = ratchet_regular_message_ctx->version;

    pb_status = pb_get_encoded_size(&size, RegularMessage_fields, &regular_message);
    VSCR_ASSERT(pb_status);

    return size;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_regular_message_serialize(vscr_ratchet_regular_message_t *ratchet_regular_message_ctx,
        vsc_buffer_t *output) {

    VSCR_ASSERT_PTR(ratchet_regular_message_ctx);
    VSCR_ASSERT(vsc_buffer_left(output) >= vscr_ratchet_regular_message_serialize_len_ext(ratchet_regular_message_ctx));

    RegularMessage regular_message = RegularMessage_init_zero;
    bool status;

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(output), vsc_buffer_capacity(output));

    memcpy(regular_message.cipher_text.bytes, ratchet_regular_message_ctx->cipher_text->bytes,
           ratchet_regular_message_ctx->cipher_text->len);

    regular_message.cipher_text.size += ratchet_regular_message_ctx->cipher_text->len;

    memcpy(regular_message.public_key, ratchet_regular_message_ctx->public_key->bytes,
           ratchet_regular_message_ctx->public_key->len);

    regular_message.counter = ratchet_regular_message_ctx->counter;

    regular_message.version = ratchet_regular_message_ctx->version;

    status = pb_encode(&ostream, RegularMessage_fields, &regular_message);

    if (!status) {
        // FIXME
        return vscr_ASN1_WRITE_ERROR;
    }

    vsc_buffer_reserve(output, ostream.bytes_written);

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_ratchet_regular_message_t *
vscr_ratchet_regular_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    RegularMessage regular_message = RegularMessage_init_zero;
    bool status;

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    status = pb_decode(&istream, RegularMessage_fields, &regular_message);

    if (!status) {
        // FIXME
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_ASN1_READ_ERROR);

        return NULL;
    }

    uint8_t version = regular_message.version;

    uint32_t counter = regular_message.counter;

    vsc_data_t public_key = vsc_data(regular_message.public_key, vscr_ratchet_regular_message_PUBLIC_KEY_LENGTH);

    vsc_data_t cipher_text = vsc_data(regular_message.cipher_text.bytes, regular_message.cipher_text.size);

    vsc_buffer_t *public_key_buf = vsc_buffer_new_with_data(public_key);
    vsc_buffer_t *cipher_text_buf = vsc_buffer_new_with_data(cipher_text);
    vscr_ratchet_regular_message_t *msg =
            vscr_ratchet_regular_message_new_with_members(version, counter, public_key_buf, cipher_text_buf);

    return msg;
}
