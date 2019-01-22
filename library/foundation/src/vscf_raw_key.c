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


//  @description
// --------------------------------------------------------------------------
//  Provide implementation agnostic representation of the asymmetric key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_raw_key.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_raw_key_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_raw_key_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_raw_key_init_ctx(vscf_raw_key_t *raw_key);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_raw_key_cleanup_ctx(vscf_raw_key_t *raw_key);

//
//  Return size of 'vscf_raw_key_t'.
//
VSCF_PUBLIC size_t
vscf_raw_key_ctx_size(void) {

    return sizeof(vscf_raw_key_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_raw_key_init(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);

    vscf_zeroize(raw_key, sizeof(vscf_raw_key_t));

    raw_key->refcnt = 1;

    vscf_raw_key_init_ctx(raw_key);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_raw_key_cleanup(vscf_raw_key_t *raw_key) {

    if (raw_key == NULL) {
        return;
    }

    if (raw_key->refcnt == 0) {
        return;
    }

    if (--raw_key->refcnt == 0) {
        vscf_raw_key_cleanup_ctx(raw_key);

        vscf_zeroize(raw_key, sizeof(vscf_raw_key_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_new(void) {

    vscf_raw_key_t *raw_key = (vscf_raw_key_t *) vscf_alloc(sizeof (vscf_raw_key_t));
    VSCF_ASSERT_ALLOC(raw_key);

    vscf_raw_key_init(raw_key);

    raw_key->self_dealloc_cb = vscf_dealloc;

    return raw_key;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_raw_key_delete(vscf_raw_key_t *raw_key) {

    if (raw_key == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = raw_key->self_dealloc_cb;

    vscf_raw_key_cleanup(raw_key);

    if (raw_key->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(raw_key);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_raw_key_new ()'.
//
VSCF_PUBLIC void
vscf_raw_key_destroy(vscf_raw_key_t **raw_key_ref) {

    VSCF_ASSERT_PTR(raw_key_ref);

    vscf_raw_key_t *raw_key = *raw_key_ref;
    *raw_key_ref = NULL;

    vscf_raw_key_delete(raw_key);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_shallow_copy(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);

    ++raw_key->refcnt;

    return raw_key;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_raw_key_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_raw_key_init_ctx(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_raw_key_cleanup_ctx(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);
    vsc_buffer_destroy(&raw_key->bytes);
}

//
//  Creates raw key defined with algorithm and data.
//  Note, data is copied.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_raw_key_new_with_data(vscf_alg_id_t alg_id, vsc_data_t raw_key_data) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(raw_key_data));

    vscf_raw_key_t *raw_key = vscf_raw_key_new();

    raw_key->alg_id = alg_id;
    raw_key->bytes = vsc_buffer_new_with_data(raw_key_data);

    vsc_buffer_make_secure(raw_key->bytes);

    return raw_key;
}

//
//  Creates raw key defined with algorithm and buffer.
//
VSCF_PRIVATE vscf_raw_key_t *
vscf_raw_key_new_with_buffer(vscf_alg_id_t alg_id, vsc_buffer_t *buffer) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(buffer);
    VSCF_ASSERT(vsc_buffer_is_valid(buffer));

    vscf_raw_key_t *raw_key = vscf_raw_key_new();

    raw_key->alg_id = alg_id;
    raw_key->bytes = vsc_buffer_shallow_copy(buffer);

    vsc_buffer_make_secure(raw_key->bytes);

    return raw_key;
}

//
//  Returns asymmetric algorithm type that raw key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_raw_key_alg_id(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);
    return raw_key->alg_id;
}

//
//  Return raw key data.
//
VSCF_PUBLIC vsc_data_t
vscf_raw_key_data(vscf_raw_key_t *raw_key) {

    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(raw_key->alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(raw_key->bytes != NULL);
    VSCF_ASSERT(vsc_buffer_is_valid(raw_key->bytes));

    return vsc_buffer_data(raw_key->bytes);
}
