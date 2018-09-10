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

#include "vscr_olm_receiver_chain.h"
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
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_olm_receiver_chain_t *
vscr_olm_receiver_chain_new(void) {

    vscr_olm_receiver_chain_t *olm_receiver_chain_ctx = (vscr_olm_receiver_chain_t *) vscr_alloc(sizeof (vscr_olm_receiver_chain_t));
    VSCR_ASSERT_ALLOC(olm_receiver_chain_ctx);

    vscr_olm_receiver_chain_init(olm_receiver_chain_ctx);

    olm_receiver_chain_ctx->self_dealloc_cb = vscr_dealloc;

    return olm_receiver_chain_ctx;
}

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_olm_receiver_chain_delete(vscr_olm_receiver_chain_t *olm_receiver_chain_ctx) {

    if (NULL == olm_receiver_chain_ctx) {
        return;
    }

    vscr_olm_receiver_chain_cleanup(olm_receiver_chain_ctx);

    if (olm_receiver_chain_ctx->self_dealloc_cb != NULL) {
         olm_receiver_chain_ctx->self_dealloc_cb(olm_receiver_chain_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_olm_receiver_chain_new ()'.
//
VSCR_PUBLIC void
vscr_olm_receiver_chain_destroy(vscr_olm_receiver_chain_t **olm_receiver_chain_ctx_ref) {

    VSCR_ASSERT_PTR(olm_receiver_chain_ctx_ref);

    vscr_olm_receiver_chain_t *olm_receiver_chain_ctx = *olm_receiver_chain_ctx_ref;
    *olm_receiver_chain_ctx_ref = NULL;

    vscr_olm_receiver_chain_delete(olm_receiver_chain_ctx);
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
vscr_olm_receiver_chain_init(vscr_olm_receiver_chain_t *olm_receiver_chain_ctx) {

    VSCR_ASSERT_PTR(olm_receiver_chain_ctx);

    VSCR_UNUSED(olm_receiver_chain_ctx);
}

//
//  Release all inner resources.
//
VSCR_PUBLIC void
vscr_olm_receiver_chain_cleanup(vscr_olm_receiver_chain_t *olm_receiver_chain_ctx) {

    VSCR_UNUSED(olm_receiver_chain_ctx);
}
