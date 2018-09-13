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

#include "vscr_olm_cipher.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <virgil/foundation/vscf_error_ctx.h>
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_olm_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_olm_cipher_init_ctx(vscr_olm_cipher_t *olm_cipher_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_olm_cipher_cleanup_ctx(vscr_olm_cipher_t *olm_cipher_ctx);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_olm_cipher_init(vscr_olm_cipher_t *olm_cipher_ctx) {

    VSCR_ASSERT_PTR(olm_cipher_ctx);

    vscr_zeroize(olm_cipher_ctx, sizeof(vscr_olm_cipher_t));

    olm_cipher_ctx->refcnt = 1;

    vscr_olm_cipher_init_ctx(olm_cipher_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_olm_cipher_cleanup(vscr_olm_cipher_t *olm_cipher_ctx) {

    VSCR_ASSERT_PTR(olm_cipher_ctx);

    if (olm_cipher_ctx->refcnt == 0) {
        return;
    }

    if (--olm_cipher_ctx->refcnt == 0) {
        vscr_olm_cipher_cleanup_ctx(olm_cipher_ctx);

        vscr_zeroize(olm_cipher_ctx, sizeof(vscr_olm_cipher_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_olm_cipher_t *
vscr_olm_cipher_new(void) {

    vscr_olm_cipher_t *olm_cipher_ctx = (vscr_olm_cipher_t *) vscr_alloc(sizeof (vscr_olm_cipher_t));
    VSCR_ASSERT_ALLOC(olm_cipher_ctx);

    vscr_olm_cipher_init(olm_cipher_ctx);

    olm_cipher_ctx->self_dealloc_cb = vscr_dealloc;

    return olm_cipher_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_olm_cipher_delete(vscr_olm_cipher_t *olm_cipher_ctx) {

    vscr_olm_cipher_cleanup(olm_cipher_ctx);

    vscr_dealloc_fn self_dealloc_cb = olm_cipher_ctx->self_dealloc_cb;

    if (olm_cipher_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(olm_cipher_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_olm_cipher_new ()'.
//
VSCR_PUBLIC void
vscr_olm_cipher_destroy(vscr_olm_cipher_t **olm_cipher_ctx_ref) {

    VSCR_ASSERT_PTR(olm_cipher_ctx_ref);

    vscr_olm_cipher_t *olm_cipher_ctx = *olm_cipher_ctx_ref;
    *olm_cipher_ctx_ref = NULL;

    vscr_olm_cipher_delete(olm_cipher_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_olm_cipher_t *
vscr_olm_cipher_copy(vscr_olm_cipher_t *olm_cipher_ctx) {

    VSCR_ASSERT_PTR(olm_cipher_ctx);

    ++olm_cipher_ctx->refcnt;

    return olm_cipher_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_olm_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_olm_cipher_init_ctx(vscr_olm_cipher_t *olm_cipher_ctx) {

    VSCR_UNUSED(olm_cipher_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_olm_cipher_cleanup_ctx(vscr_olm_cipher_t *olm_cipher_ctx) {

    VSCR_UNUSED(olm_cipher_ctx);
}

VSCR_PUBLIC vsc_buffer_t *
vscr_olm_cipher_encrypt(vscr_olm_cipher_t *olm_cipher_ctx, vsc_data_t key, vsc_data_t plain_text) {

    VSCR_UNUSED(olm_cipher_ctx);
    VSCR_UNUSED(key);
    VSCR_UNUSED(plain_text);

    return vsc_buffer_new();
    //  TODO: This is STUB. Implement me.
}
