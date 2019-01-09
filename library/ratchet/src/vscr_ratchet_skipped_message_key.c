//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#include "vscr_ratchet_skipped_message_key.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_skipped_message_key_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_message_key_init_ctx(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_message_key_cleanup_ctx(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key);

//
//  Return size of 'vscr_ratchet_skipped_message_key_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_skipped_message_key_ctx_size(void) {

    return sizeof(vscr_ratchet_skipped_message_key_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_message_key_init(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_skipped_message_key);

    vscr_zeroize(ratchet_skipped_message_key, sizeof(vscr_ratchet_skipped_message_key_t));

    ratchet_skipped_message_key->refcnt = 1;

    vscr_ratchet_skipped_message_key_init_ctx(ratchet_skipped_message_key);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_message_key_cleanup(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    if (ratchet_skipped_message_key == NULL) {
        return;
    }

    if (ratchet_skipped_message_key->refcnt == 0) {
        return;
    }

    if (--ratchet_skipped_message_key->refcnt == 0) {
        vscr_ratchet_skipped_message_key_cleanup_ctx(ratchet_skipped_message_key);

        vscr_zeroize(ratchet_skipped_message_key, sizeof(vscr_ratchet_skipped_message_key_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_skipped_message_key_t *
vscr_ratchet_skipped_message_key_new(void) {

    vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key = (vscr_ratchet_skipped_message_key_t *) vscr_alloc(sizeof (vscr_ratchet_skipped_message_key_t));
    VSCR_ASSERT_ALLOC(ratchet_skipped_message_key);

    vscr_ratchet_skipped_message_key_init(ratchet_skipped_message_key);

    ratchet_skipped_message_key->self_dealloc_cb = vscr_dealloc;

    return ratchet_skipped_message_key;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_message_key_delete(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    if (ratchet_skipped_message_key == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_skipped_message_key->self_dealloc_cb;

    vscr_ratchet_skipped_message_key_cleanup(ratchet_skipped_message_key);

    if (ratchet_skipped_message_key->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_skipped_message_key);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_skipped_message_key_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_message_key_destroy(vscr_ratchet_skipped_message_key_t **ratchet_skipped_message_key_ref) {

    VSCR_ASSERT_PTR(ratchet_skipped_message_key_ref);

    vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key = *ratchet_skipped_message_key_ref;
    *ratchet_skipped_message_key_ref = NULL;

    vscr_ratchet_skipped_message_key_delete(ratchet_skipped_message_key);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_skipped_message_key_t *
vscr_ratchet_skipped_message_key_shallow_copy(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_skipped_message_key);

    ++ratchet_skipped_message_key->refcnt;

    return ratchet_skipped_message_key;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_skipped_message_key_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_message_key_init_ctx(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_skipped_message_key);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_message_key_cleanup_ctx(vscr_ratchet_skipped_message_key_t *ratchet_skipped_message_key) {

    VSCR_ASSERT_PTR(ratchet_skipped_message_key);

    vscr_ratchet_message_key_destroy(&ratchet_skipped_message_key->message_key);
    vsc_buffer_destroy(&ratchet_skipped_message_key->public_key);
}
