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
//  Handle information about recipient that is defined by a Public Key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_recipient_info.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_key_recipient_info_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_recipient_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_recipient_info_init_ctx(vscf_key_recipient_info_t *key_recipient_info);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_recipient_info_cleanup_ctx(vscf_key_recipient_info_t *key_recipient_info);

//
//  Return size of 'vscf_key_recipient_info_t'.
//
VSCF_PUBLIC size_t
vscf_key_recipient_info_ctx_size(void) {

    return sizeof(vscf_key_recipient_info_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_recipient_info_init(vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(key_recipient_info);

    vscf_zeroize(key_recipient_info, sizeof(vscf_key_recipient_info_t));

    key_recipient_info->refcnt = 1;

    vscf_key_recipient_info_init_ctx(key_recipient_info);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_recipient_info_cleanup(vscf_key_recipient_info_t *key_recipient_info) {

    if (key_recipient_info == NULL) {
        return;
    }

    if (key_recipient_info->refcnt == 0) {
        return;
    }

    if (--key_recipient_info->refcnt == 0) {
        vscf_key_recipient_info_cleanup_ctx(key_recipient_info);

        vscf_zeroize(key_recipient_info, sizeof(vscf_key_recipient_info_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new(void) {

    vscf_key_recipient_info_t *key_recipient_info = (vscf_key_recipient_info_t *) vscf_alloc(sizeof (vscf_key_recipient_info_t));
    VSCF_ASSERT_ALLOC(key_recipient_info);

    vscf_key_recipient_info_init(key_recipient_info);

    key_recipient_info->self_dealloc_cb = vscf_dealloc;

    return key_recipient_info;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_key_recipient_info_delete(vscf_key_recipient_info_t *key_recipient_info) {

    if (key_recipient_info == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = key_recipient_info->self_dealloc_cb;

    vscf_key_recipient_info_cleanup(key_recipient_info);

    if (key_recipient_info->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(key_recipient_info);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_recipient_info_new ()'.
//
VSCF_PUBLIC void
vscf_key_recipient_info_destroy(vscf_key_recipient_info_t **key_recipient_info_ref) {

    VSCF_ASSERT_PTR(key_recipient_info_ref);

    vscf_key_recipient_info_t *key_recipient_info = *key_recipient_info_ref;
    *key_recipient_info_ref = NULL;

    vscf_key_recipient_info_delete(key_recipient_info);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_shallow_copy(vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(key_recipient_info);

    ++key_recipient_info->refcnt;

    return key_recipient_info;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_key_recipient_info_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_key_recipient_info_init_ctx(vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(key_recipient_info);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_key_recipient_info_cleanup_ctx(vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(key_recipient_info);

    vsc_buffer_destroy(&key_recipient_info->recipient_id);
    vscf_impl_destroy(&key_recipient_info->key_encryption_algorithm);
    vsc_buffer_destroy(&key_recipient_info->encrypted_key);
}

//
//  Create object and define all properties.
//
VSCF_PUBLIC vscf_key_recipient_info_t *
vscf_key_recipient_info_new_with_members(
        vsc_data_t recipient_id, vscf_impl_t **key_encryption_algorithm_ref, vsc_data_t encrypted_key) {

    VSCF_ASSERT_PTR(key_encryption_algorithm_ref);
    VSCF_ASSERT_PTR(*key_encryption_algorithm_ref);

    vscf_impl_t *key_encryption_algorithm = *key_encryption_algorithm_ref;
    *key_encryption_algorithm_ref = NULL;

    vscf_key_recipient_info_t *key_recipient_info = vscf_key_recipient_info_new();

    key_recipient_info->recipient_id = vsc_buffer_new_with_data(recipient_id);
    key_recipient_info->key_encryption_algorithm = key_encryption_algorithm;
    key_recipient_info->encrypted_key = vsc_buffer_new_with_data(encrypted_key);

    return key_recipient_info;
}
