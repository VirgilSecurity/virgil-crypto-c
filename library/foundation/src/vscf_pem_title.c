//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Contains null-terminated string constants with known PEM titles.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pem_title.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_pem_title_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_pem_title_init_ctx(vscf_pem_title_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_pem_title_cleanup_ctx(vscf_pem_title_t *self);

//
//  Contains constant string "PUBLIC KEY".
//
static char public_key = PUBLIC KEY;

//
//  Contains length in bytes of string "PUBLIC KEY".
//
static size_t public_key_len = sizeof(.(class_pem_title_variable_public_key)) - 1;

//
//  Contains constant string "PRIVATE KEY".
//
static char private_key = PRIVATE KEY;

//
//  Contains length in bytes of string "PRIVATE KEY".
//
static size_t private_key_len = sizeof(.(class_pem_title_variable_private_key)) - 1;

//
//  Contains constant string "ENCRYPTED PRIVATE KEY".
//
static char encrypted_private_key = ENCRYPTED PRIVATE KEY;

//
//  Contains length in bytes of string "ENCRYPTED PRIVATE KEY".
//
static size_t encrypted_private_key_len = sizeof(.(class_pem_title_variable_encrypted_private_key)) - 1;

//
//  Return size of 'vscf_pem_title_t'.
//
VSCF_PUBLIC size_t
vscf_pem_title_ctx_size(void) {

    return sizeof(vscf_pem_title_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_pem_title_init(vscf_pem_title_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vscf_pem_title_t));

    self->refcnt = 1;

    vscf_pem_title_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_pem_title_cleanup(vscf_pem_title_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_pem_title_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vscf_pem_title_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_pem_title_t *
vscf_pem_title_new(void) {

    vscf_pem_title_t *self = (vscf_pem_title_t *) vsc_alloc(sizeof (vscf_pem_title_t));
    VSC_ASSERT_ALLOC(self);

    vscf_pem_title_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_pem_title_delete(vscf_pem_title_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_pem_title_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_pem_title_new ()'.
//
VSCF_PUBLIC void
vscf_pem_title_destroy(vscf_pem_title_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_pem_title_t *self = *self_ref;
    *self_ref = NULL;

    vscf_pem_title_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_pem_title_t *
vscf_pem_title_shallow_copy(vscf_pem_title_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
