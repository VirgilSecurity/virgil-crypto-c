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

#include "vsce_phe_client.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_client_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_client_init_ctx(vsce_phe_client_t *phe_client_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *phe_client_ctx);

//
//  Return size of 'vsce_phe_client_t'.
//
VSCE_PUBLIC size_t
vsce_phe_client_ctx_size(void) {

    return sizeof(vsce_phe_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_client_init(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vsce_zeroize(phe_client_ctx, sizeof(vsce_phe_client_t));

    phe_client_ctx->refcnt = 1;

    vsce_phe_client_init_ctx(phe_client_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_client_cleanup(vsce_phe_client_t *phe_client_ctx) {

    if (phe_client_ctx == NULL) {
        return;
    }

    if (phe_client_ctx->refcnt == 0) {
        return;
    }

    if (--phe_client_ctx->refcnt == 0) {
        vsce_phe_client_cleanup_ctx(phe_client_ctx);

        vsce_phe_client_release_random(phe_client_ctx);

        vsce_zeroize(phe_client_ctx, sizeof(vsce_phe_client_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_new(void) {

    vsce_phe_client_t *phe_client_ctx = (vsce_phe_client_t *) vsce_alloc(sizeof (vsce_phe_client_t));
    VSCE_ASSERT_ALLOC(phe_client_ctx);

    vsce_phe_client_init(phe_client_ctx);

    phe_client_ctx->self_dealloc_cb = vsce_dealloc;

    return phe_client_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_client_delete(vsce_phe_client_t *phe_client_ctx) {

    if (phe_client_ctx == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_client_ctx->self_dealloc_cb;

    vsce_phe_client_cleanup(phe_client_ctx);

    if (phe_client_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_client_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_client_new ()'.
//
VSCE_PUBLIC void
vsce_phe_client_destroy(vsce_phe_client_t **phe_client_ctx_ref) {

    VSCE_ASSERT_PTR(phe_client_ctx_ref);

    vsce_phe_client_t *phe_client_ctx = *phe_client_ctx_ref;
    *phe_client_ctx_ref = NULL;

    vsce_phe_client_delete(phe_client_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_copy(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    ++phe_client_ctx->refcnt;

    return phe_client_ctx;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_client_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_client_ctx->random = vscf_impl_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_client_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_client_ctx->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_random(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vscf_impl_destroy(&phe_client_ctx->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_client_init_ctx(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    //  TODO: Perform additional context initialization.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    //  TODO: Release all inner resources.
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_encrypt(vsce_phe_client_t *phe_client_ctx, const vsc_buffer_t *nc, const vsc_buffer_t *ns,
        const vsc_buffer_t *password, const vsc_buffer_t *message, const vsc_buffer_t *c0, const vsc_buffer_t *c1,
        const vsc_buffer_t *proof) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(password);
    VSCE_ASSERT_PTR(message);

    VSCE_ASSERT(vsc_buffer_len(ns) == vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(nc) == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    //  TODO: This is STUB. Implement me.

    //    HS0 = HS(password, ns, 0)
    //    HS1 = HS(password, ns ,1)
    //    HR0 = HR(nr, 0)
    //    HR1 = HR(nr, 1)
    //    stmt ← “∃x s.t. (C0,C1,X) = (H
    //    x
    //    R,0
    //            ,H
    //    x
    //    R,1
    //            ,G
    //    x
    //)”

    VSCE_UNUSED(c0);
    VSCE_UNUSED(c1);
    VSCE_UNUSED(proof);

    return vsce_SUCCESS;
}
