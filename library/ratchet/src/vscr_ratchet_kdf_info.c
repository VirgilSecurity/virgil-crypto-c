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

#include "vscr_ratchet_kdf_info.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_kdf_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_kdf_info_init_ctx(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_kdf_info_cleanup_ctx(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_kdf_info_init(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    VSCR_ASSERT_PTR(ratchet_kdf_info_ctx);

    vscr_zeroize(ratchet_kdf_info_ctx, sizeof(vscr_ratchet_kdf_info_t));

    ratchet_kdf_info_ctx->refcnt = 1;

    vscr_ratchet_kdf_info_init_ctx(ratchet_kdf_info_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_kdf_info_cleanup(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    if (ratchet_kdf_info_ctx == NULL) {
        return;
    }

    if (ratchet_kdf_info_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_kdf_info_ctx->refcnt == 0) {
        vscr_ratchet_kdf_info_cleanup_ctx(ratchet_kdf_info_ctx);

        vscr_zeroize(ratchet_kdf_info_ctx, sizeof(vscr_ratchet_kdf_info_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_kdf_info_t *
vscr_ratchet_kdf_info_new(void) {

    vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx = (vscr_ratchet_kdf_info_t *) vscr_alloc(sizeof (vscr_ratchet_kdf_info_t));
    VSCR_ASSERT_ALLOC(ratchet_kdf_info_ctx);

    vscr_ratchet_kdf_info_init(ratchet_kdf_info_ctx);

    ratchet_kdf_info_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_kdf_info_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_kdf_info_delete(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    if (ratchet_kdf_info_ctx == NULL) {
        return;
    }

    vscr_ratchet_kdf_info_cleanup(ratchet_kdf_info_ctx);

    vscr_dealloc_fn self_dealloc_cb = ratchet_kdf_info_ctx->self_dealloc_cb;

    if (ratchet_kdf_info_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_kdf_info_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_kdf_info_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_kdf_info_destroy(vscr_ratchet_kdf_info_t **ratchet_kdf_info_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_kdf_info_ctx_ref);

    vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx = *ratchet_kdf_info_ctx_ref;
    *ratchet_kdf_info_ctx_ref = NULL;

    vscr_ratchet_kdf_info_delete(ratchet_kdf_info_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_kdf_info_t *
vscr_ratchet_kdf_info_copy(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    VSCR_ASSERT_PTR(ratchet_kdf_info_ctx);

    ++ratchet_kdf_info_ctx->refcnt;

    return ratchet_kdf_info_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_kdf_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_kdf_info_init_ctx(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    ratchet_kdf_info_ctx->root_info = NULL;
    ratchet_kdf_info_ctx->ratchet_info = NULL;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_kdf_info_cleanup_ctx(vscr_ratchet_kdf_info_t *ratchet_kdf_info_ctx) {

    vsc_buffer_destroy(&ratchet_kdf_info_ctx->root_info);
    vsc_buffer_destroy(&ratchet_kdf_info_ctx->ratchet_info);
}
