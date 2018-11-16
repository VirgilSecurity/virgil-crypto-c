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

#include "vsce_phe_server.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_server_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *phe_server_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *phe_server_ctx);

//
//  Return size of 'vsce_phe_server_t'.
//
VSCE_PUBLIC size_t
vsce_phe_server_ctx_size(void) {

    return sizeof(vsce_phe_server_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_server_init(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    vsce_zeroize(phe_server_ctx, sizeof(vsce_phe_server_t));

    phe_server_ctx->refcnt = 1;

    vsce_phe_server_init_ctx(phe_server_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_server_cleanup(vsce_phe_server_t *phe_server_ctx) {

    if (phe_server_ctx == NULL) {
        return;
    }

    if (phe_server_ctx->refcnt == 0) {
        return;
    }

    if (--phe_server_ctx->refcnt == 0) {
        vsce_phe_server_cleanup_ctx(phe_server_ctx);

        vsce_zeroize(phe_server_ctx, sizeof(vsce_phe_server_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_new(void) {

    vsce_phe_server_t *phe_server_ctx = (vsce_phe_server_t *) vsce_alloc(sizeof (vsce_phe_server_t));
    VSCE_ASSERT_ALLOC(phe_server_ctx);

    vsce_phe_server_init(phe_server_ctx);

    phe_server_ctx->self_dealloc_cb = vsce_dealloc;

    return phe_server_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_server_delete(vsce_phe_server_t *phe_server_ctx) {

    if (phe_server_ctx == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_server_ctx->self_dealloc_cb;

    vsce_phe_server_cleanup(phe_server_ctx);

    if (phe_server_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_server_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_server_new ()'.
//
VSCE_PUBLIC void
vsce_phe_server_destroy(vsce_phe_server_t **phe_server_ctx_ref) {

    VSCE_ASSERT_PTR(phe_server_ctx_ref);

    vsce_phe_server_t *phe_server_ctx = *phe_server_ctx_ref;
    *phe_server_ctx_ref = NULL;

    vsce_phe_server_delete(phe_server_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_copy(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    ++phe_server_ctx->refcnt;

    return phe_server_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    //  TODO: Perform additional context initialization.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    //  TODO: Release all inner resources.
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_encrypt(vsce_phe_server_t *phe_server_ctx, const vsc_buffer_t *nc, const vsc_buffer_t *ns,
        vsc_buffer_t *c0, vsc_buffer_t *c1, vsc_buffer_t *proof) {

    VSCE_UNUSED(phe_server_ctx);
    VSCE_UNUSED(nc);
    VSCE_UNUSED(ns);
    VSCE_UNUSED(c0);
    VSCE_UNUSED(c1);
    VSCE_UNUSED(proof);
    //  TODO: This is STUB. Implement me.

    //    HR0 = HR(nl, 0)
    //    HR1 = HR(nl, 1)
    //    c0 = HR0 ^ x
    //    c1 = HR1 ^ x

    return vsce_SUCCESS;
}
