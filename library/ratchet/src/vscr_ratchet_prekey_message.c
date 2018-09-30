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

#include "vscr_ratchet_prekey_message.h"
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
//  Note, this method is called automatically when method vscr_ratchet_prekey_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_prekey_message_init_ctx(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_prekey_message_cleanup_ctx(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_prekey_message_init(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_prekey_message_ctx);

    vscr_zeroize(ratchet_prekey_message_ctx, sizeof(vscr_ratchet_prekey_message_t));

    ratchet_prekey_message_ctx->refcnt = 1;

    vscr_ratchet_prekey_message_init_ctx(ratchet_prekey_message_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_prekey_message_cleanup(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    if (ratchet_prekey_message_ctx == NULL) {
        return;
    }

    if (ratchet_prekey_message_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_prekey_message_ctx->refcnt == 0) {
        vscr_ratchet_prekey_message_cleanup_ctx(ratchet_prekey_message_ctx);

        vscr_zeroize(ratchet_prekey_message_ctx, sizeof(vscr_ratchet_prekey_message_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_prekey_message_t *
vscr_ratchet_prekey_message_new(void) {

    vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx = (vscr_ratchet_prekey_message_t *) vscr_alloc(sizeof (vscr_ratchet_prekey_message_t));
    VSCR_ASSERT_ALLOC(ratchet_prekey_message_ctx);

    vscr_ratchet_prekey_message_init(ratchet_prekey_message_ctx);

    ratchet_prekey_message_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_prekey_message_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_prekey_message_delete(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    if (ratchet_prekey_message_ctx == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_prekey_message_ctx->self_dealloc_cb;

    vscr_ratchet_prekey_message_cleanup(ratchet_prekey_message_ctx);

    if (ratchet_prekey_message_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_prekey_message_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_prekey_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_prekey_message_destroy(vscr_ratchet_prekey_message_t **ratchet_prekey_message_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_prekey_message_ctx_ref);

    vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx = *ratchet_prekey_message_ctx_ref;
    *ratchet_prekey_message_ctx_ref = NULL;

    vscr_ratchet_prekey_message_delete(ratchet_prekey_message_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_prekey_message_t *
vscr_ratchet_prekey_message_copy(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_prekey_message_ctx);

    ++ratchet_prekey_message_ctx->refcnt;

    return ratchet_prekey_message_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_prekey_message_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_prekey_message_init_ctx(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_prekey_message_ctx);

    //  TODO: Perform additional context initialization.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_prekey_message_cleanup_ctx(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx) {

    VSCR_ASSERT_PTR(ratchet_prekey_message_ctx);

    //  TODO: Release all inner resources.
}

VSCR_PUBLIC vscr_ratchet_prekey_message_t *
vscr_ratchet_prekey_message_new_with_members(uint8_t protocol_version, vsc_buffer_t *identity_key,
        vsc_buffer_t *long_term_key, vsc_buffer_t *one_time_key, vsc_buffer_t *message) {

    vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx = (vscr_ratchet_prekey_message_t *) vscr_alloc(sizeof (vscr_ratchet_prekey_message_t));
    VSCR_ASSERT_ALLOC(ratchet_prekey_message_ctx);

    vscr_ratchet_prekey_message_init(ratchet_prekey_message_ctx);

    VSCR_UNUSED(protocol_version);
    VSCR_UNUSED(identity_key);
    VSCR_UNUSED(long_term_key);
    VSCR_UNUSED(one_time_key);
    VSCR_UNUSED(message);

    //   TODO: Perform additional initialization.

    ratchet_prekey_message_ctx->refcnt = 1;
    ratchet_prekey_message_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_prekey_message_ctx;
}

VSCR_PUBLIC size_t
vscr_ratchet_prekey_message_serialize_len(size_t cipher_text_len) {

    VSCR_UNUSED(cipher_text_len);

    return 0;
    //  TODO: This is STUB. Implement me.
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_prekey_message_serialize(vscr_ratchet_prekey_message_t *ratchet_prekey_message_ctx, vsc_buffer_t *output) {

    VSCR_UNUSED(ratchet_prekey_message_ctx);
    VSCR_UNUSED(output);

    return vscr_WRONG_MESSAGE_FORMAT;
    //  TODO: This is STUB. Implement me.
}

VSCR_PUBLIC vscr_ratchet_prekey_message_t *
vscr_ratchet_prekey_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_UNUSED(input);
    VSCR_UNUSED(err_ctx);

    VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

    return vscr_ratchet_prekey_message_new();
    //  TODO: This is STUB. Implement me.
}
