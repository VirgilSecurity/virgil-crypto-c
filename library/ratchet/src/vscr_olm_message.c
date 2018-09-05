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

#include "vscr_olm_message.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <virgil/foundation/vscf_asn1wr.h>
#include <virgil/foundation/vscf_asn1rd.h>
#include <virgil/foundation/vscf_error_ctx.h>
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_olm_message_t *
vscr_olm_message_new(void) {

    vscr_olm_message_t *olm_message_ctx = (vscr_olm_message_t *) vscr_alloc(sizeof (vscr_olm_message_t));
    VSCR_ASSERT_ALLOC(olm_message_ctx);

    vscr_olm_message_init(olm_message_ctx);

    olm_message_ctx->self_dealloc_cb = vscr_dealloc;

    return olm_message_ctx;
}

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_olm_message_delete(vscr_olm_message_t *olm_message_ctx) {

    if (NULL == olm_message_ctx) {
        return;
    }

    vscr_olm_message_cleanup(olm_message_ctx);

    if (olm_message_ctx->self_dealloc_cb != NULL) {
         olm_message_ctx->self_dealloc_cb(olm_message_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_olm_message_new ()'.
//
VSCR_PUBLIC void
vscr_olm_message_destroy(vscr_olm_message_t **olm_message_ctx_ref) {

    VSCR_ASSERT_PTR(olm_message_ctx_ref);

    vscr_olm_message_t *olm_message_ctx = *olm_message_ctx_ref;
    *olm_message_ctx_ref = NULL;

    vscr_olm_message_delete(olm_message_ctx);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_olm_message_init(vscr_olm_message_t *olm_message_ctx) {

    VSCR_ASSERT_PTR(olm_message_ctx);

    //  TODO: This is STUB. Implement me.
}

//
//  Release all inner resources.
//
VSCR_PUBLIC void
vscr_olm_message_cleanup(vscr_olm_message_t *olm_message_ctx) {

    //  TODO: This is STUB. Implement me.

    VSCR_UNUSED(olm_message_ctx);
}

VSCR_PUBLIC vscr_olm_message_t *
vscr_olm_message_new_with_members(uint8_t version, uint32_t counter, vsc_buffer_t **public_key_ref,
        vsc_buffer_t **cipher_text_ref) {

    VSCR_ASSERT_PTR(public_key_ref);
    VSCR_ASSERT(vsc_buffer_is_valid(*public_key_ref));

    VSCR_ASSERT_PTR(cipher_text_ref);
    VSCR_ASSERT(vsc_buffer_is_valid(*cipher_text_ref));

    vscr_olm_message_t *olm_message = vscr_olm_message_new();

    olm_message->version = version;
    olm_message->counter = counter;
    olm_message->public_key = *public_key_ref;
    *public_key_ref = NULL;
    olm_message->cipher_text = *cipher_text_ref;
    *cipher_text_ref = NULL;

    return olm_message;
}

VSCR_PUBLIC vscr_error_t
vscr_olm_message_serialize(vscr_olm_message_t *olm_message_ctx, vsc_buffer_t *output) {

    //  OLMMessage ::= SEQUENCE {
            //       version INTEGER,
            //       counter INTEGER,
            //       public_key OCTET_STRING,
            //       cipher_text OCTET_STRING }

    VSCR_ASSERT(vsc_buffer_is_valid(output));

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    vscf_impl_t *asn1wr_impl = vscf_asn1wr_impl(asn1wr);

    vscf_asn1_writer_reset(asn1wr_impl, output);

    size_t top_sequence_len = 0;

    top_sequence_len += vscf_asn1_writer_write_octet_str(asn1wr_impl, vsc_buffer_data(olm_message_ctx->cipher_text));

    top_sequence_len += vscf_asn1_writer_write_octet_str(asn1wr_impl, vsc_buffer_data(olm_message_ctx->public_key));

    top_sequence_len += vscf_asn1_writer_write_int(asn1wr_impl, (int)olm_message_ctx->counter);

    top_sequence_len += vscf_asn1_writer_write_int(asn1wr_impl, (int)olm_message_ctx->version);

    vscf_asn1_writer_write_sequence(asn1wr_impl, top_sequence_len);

    if (vscf_asn1_writer_error(asn1wr_impl) != vscf_SUCCESS) {
        vscf_asn1wr_destroy(&asn1wr);

        return vscr_ASN1_WRITE_ERROR;
    }

    vscf_asn1_writer_seal(asn1wr_impl);

    vscf_asn1wr_destroy(&asn1wr);

    return vscr_SUCCESS;
}

VSCR_PUBLIC const vscr_olm_message_t *
vscr_olm_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    vscf_impl_t *asn1rd_impl = vscf_asn1rd_impl(asn1rd);

    vscr_olm_message_t *olm_message = vscr_olm_message_new();

    uint8_t version = (uint8_t)vscf_asn1_reader_read_int(asn1rd_impl);

    uint32_t counter = (uint32_t)vscf_asn1_reader_read_int(asn1rd_impl);

    size_t public_key_len = vscf_asn1_reader_get_len(asn1rd_impl);
    vsc_buffer_t *public_key = vsc_buffer_new_with_capacity(public_key_len);
    vscf_asn1_reader_read_octet_str(asn1rd_impl, public_key);

    size_t cipher_text_len = vscf_asn1_reader_get_len(asn1rd_impl);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(cipher_text_len);
    vscf_asn1_reader_read_octet_str(asn1rd_impl, cipher_text);

    if (vscf_asn1_reader_error(asn1rd_impl) != vscf_SUCCESS) {
        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_ASN1_READ_ERROR);

        return NULL;
    }

    vscf_asn1rd_destroy(&asn1rd);

    olm_message = vscr_olm_message_new_with_members(version, counter, &public_key, &cipher_text);

    return olm_message;
}
