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
//  Handle list of the "password recipient info" class objects.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_password_recipient_info_list.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_password_recipient_info_list_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_password_recipient_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_password_recipient_info_list_init_ctx(vscf_password_recipient_info_list_t *password_recipient_info_list);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_password_recipient_info_list_cleanup_ctx(vscf_password_recipient_info_list_t *password_recipient_info_list);

//
//  Return size of 'vscf_password_recipient_info_list_t'.
//
VSCF_PUBLIC size_t
vscf_password_recipient_info_list_ctx_size(void) {

    return sizeof(vscf_password_recipient_info_list_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_init(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    VSCF_ASSERT_PTR(password_recipient_info_list);

    vscf_zeroize(password_recipient_info_list, sizeof(vscf_password_recipient_info_list_t));

    password_recipient_info_list->refcnt = 1;

    vscf_password_recipient_info_list_init_ctx(password_recipient_info_list);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_cleanup(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    if (password_recipient_info_list == NULL) {
        return;
    }

    if (password_recipient_info_list->refcnt == 0) {
        return;
    }

    if (--password_recipient_info_list->refcnt == 0) {
        vscf_password_recipient_info_list_cleanup_ctx(password_recipient_info_list);

        vscf_zeroize(password_recipient_info_list, sizeof(vscf_password_recipient_info_list_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_new(void) {

    vscf_password_recipient_info_list_t *password_recipient_info_list = (vscf_password_recipient_info_list_t *) vscf_alloc(sizeof (vscf_password_recipient_info_list_t));
    VSCF_ASSERT_ALLOC(password_recipient_info_list);

    vscf_password_recipient_info_list_init(password_recipient_info_list);

    password_recipient_info_list->self_dealloc_cb = vscf_dealloc;

    return password_recipient_info_list;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_delete(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    if (password_recipient_info_list == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = password_recipient_info_list->self_dealloc_cb;

    vscf_password_recipient_info_list_cleanup(password_recipient_info_list);

    if (password_recipient_info_list->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(password_recipient_info_list);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_password_recipient_info_list_new ()'.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_destroy(vscf_password_recipient_info_list_t **password_recipient_info_list_ref) {

    VSCF_ASSERT_PTR(password_recipient_info_list_ref);

    vscf_password_recipient_info_list_t *password_recipient_info_list = *password_recipient_info_list_ref;
    *password_recipient_info_list_ref = NULL;

    vscf_password_recipient_info_list_delete(password_recipient_info_list);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_shallow_copy(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    VSCF_ASSERT_PTR(password_recipient_info_list);

    ++password_recipient_info_list->refcnt;

    return password_recipient_info_list;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_password_recipient_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_password_recipient_info_list_init_ctx(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    VSCF_ASSERT_PTR(password_recipient_info_list);

    //  TODO: Perform additional context initialization.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_password_recipient_info_list_cleanup_ctx(vscf_password_recipient_info_list_t *password_recipient_info_list) {

    VSCF_ASSERT_PTR(password_recipient_info_list);

    //  TODO: Release all inner resources.
}
