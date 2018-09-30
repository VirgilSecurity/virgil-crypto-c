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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <virgil/foundation/vscf_asn1wr.h>
#include <virgil/foundation/vscf_asn1rd.h>
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
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *ratchet_message_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *ratchet_message_ctx);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_message_init(vscr_ratchet_message_t *ratchet_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_message_ctx);

    vscr_zeroize(ratchet_message_ctx, sizeof(vscr_ratchet_message_t));

    ratchet_message_ctx->refcnt = 1;

    vscr_ratchet_message_init_ctx(ratchet_message_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_message_cleanup(vscr_ratchet_message_t *ratchet_message_ctx) {

    if (ratchet_message_ctx == NULL) {
        return;
    }

    if (ratchet_message_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_message_ctx->refcnt == 0) {
        vscr_ratchet_message_cleanup_ctx(ratchet_message_ctx);

        vscr_zeroize(ratchet_message_ctx, sizeof(vscr_ratchet_message_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_new(void) {

    vscr_ratchet_message_t *ratchet_message_ctx = (vscr_ratchet_message_t *) vscr_alloc(sizeof (vscr_ratchet_message_t));
    VSCR_ASSERT_ALLOC(ratchet_message_ctx);

    vscr_ratchet_message_init(ratchet_message_ctx);

    ratchet_message_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_message_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_message_delete(vscr_ratchet_message_t *ratchet_message_ctx) {

    if (ratchet_message_ctx == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_message_ctx->self_dealloc_cb;

    vscr_ratchet_message_cleanup(ratchet_message_ctx);

    if (ratchet_message_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_message_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_message_destroy(vscr_ratchet_message_t **ratchet_message_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_message_ctx_ref);

    vscr_ratchet_message_t *ratchet_message_ctx = *ratchet_message_ctx_ref;
    *ratchet_message_ctx_ref = NULL;

    vscr_ratchet_message_delete(ratchet_message_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_copy(vscr_ratchet_message_t *ratchet_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_message_ctx);

    ++ratchet_message_ctx->refcnt;

    return ratchet_message_ctx;
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
vscr_ratchet_message_init_ctx(vscr_ratchet_message_t *ratchet_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_message_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_message_cleanup_ctx(vscr_ratchet_message_t *ratchet_message_ctx) {

    vsc_buffer_destroy(&ratchet_message_ctx->public_key);
    vsc_buffer_destroy(&ratchet_message_ctx->cipher_text);
}

VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_new_with_members(uint8_t version, uint32_t counter, vsc_buffer_t *public_key,
        vsc_buffer_t *cipher_text) {

    VSCR_ASSERT(vsc_buffer_len(public_key) == vscr_ratchet_message_PUBLIC_KEY_LENGTH);
    VSCR_ASSERT(vsc_buffer_is_valid(cipher_text));

    vscr_ratchet_message_t *ratchet_message = vscr_ratchet_message_new();

    ratchet_message->version = version;
    ratchet_message->counter = counter;
    ratchet_message->public_key = vsc_buffer_copy(public_key);
    ratchet_message->cipher_text = vsc_buffer_copy(cipher_text);

    return ratchet_message;
}

VSCR_PUBLIC size_t
vscr_ratchet_message_serialize_len(size_t cipher_text_len) {

    //  RATCHETMessage ::= SEQUENCE {
    //       version INTEGER,
    //       counter INTEGER,
    //       public_key OCTET_STRING,
    //       cipher_text OCTET_STRING }

    size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                              + 1 + 1 + 2 /* INTEGER */
                              + 1 + 1 + 5 /* INTEGER */
                              + 1 + 1 + vscr_ratchet_message_PUBLIC_KEY_LENGTH
                              + 1 + 3 + cipher_text_len;

    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_message_serialize(vscr_ratchet_message_t *ratchet_message_ctx, vsc_buffer_t *output) {

    //  RATCHETMessage ::= SEQUENCE {
    //       version INTEGER,
    //       counter INTEGER,
    //       public_key OCTET_STRING,
    //       cipher_text OCTET_STRING }

    VSCR_ASSERT_PTR(ratchet_message_ctx);

    VSCR_ASSERT(vsc_buffer_left(output) >= vscr_ratchet_message_serialize_len(vsc_buffer_len(ratchet_message_ctx->cipher_text)));

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();

    vscf_asn1wr_reset(asn1wr, output);

    size_t top_sequence_len = 0;

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr,
                                                    vsc_buffer_data(ratchet_message_ctx->cipher_text));

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr,
                                                    vsc_buffer_data(ratchet_message_ctx->public_key));

    top_sequence_len += vscf_asn1wr_write_uint32(asn1wr, ratchet_message_ctx->counter);

    top_sequence_len += vscf_asn1wr_write_uint8(asn1wr, ratchet_message_ctx->version);

    vscf_asn1wr_write_sequence(asn1wr, top_sequence_len);

    if (vscf_asn1wr_error(asn1wr) != vscf_SUCCESS) {
        vscf_asn1wr_destroy(&asn1wr);

        // FIXME
        return vscr_ASN1_WRITE_ERROR;
    }

    vscf_asn1wr_seal(asn1wr);

    vscf_asn1wr_destroy(&asn1wr);

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();

    vscf_asn1rd_reset(asn1rd, input);
    vscf_asn1rd_read_sequence(asn1rd);

    uint8_t version = vscf_asn1rd_read_uint8(asn1rd);

    uint32_t counter = vscf_asn1rd_read_uint32(asn1rd);

    size_t public_key_len = vscf_asn1rd_get_len(asn1rd);
    // FIXME: Should not crash
    VSCR_ASSERT(public_key_len == vscr_ratchet_message_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *public_key = vsc_buffer_new_with_capacity(public_key_len);
    vscf_asn1rd_read_octet_str(asn1rd, public_key);

    size_t cipher_text_len = vscf_asn1rd_get_len(asn1rd);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(cipher_text_len);
    vscf_asn1rd_read_octet_str(asn1rd, cipher_text);

    if (vscf_asn1rd_error(asn1rd) != vscf_SUCCESS) {
        vsc_buffer_destroy(&public_key);
        vsc_buffer_destroy(&cipher_text);
        vscf_asn1rd_destroy(&asn1rd);

        // FIXME
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_ASN1_READ_ERROR);

        return NULL;
    }

    vscr_ratchet_message_t *msg = vscr_ratchet_message_new_with_members(version, counter, public_key, cipher_text);

    vsc_buffer_destroy(&public_key);
    vsc_buffer_destroy(&cipher_text);
    vscf_asn1rd_destroy(&asn1rd);

    return msg;
}
