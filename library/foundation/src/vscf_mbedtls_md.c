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
//  Bridge between MbedTLS MD module and virgil foundation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_md.h"
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
//  Note, this method is called automatically when method vscf_mbedtls_md_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_mbedtls_md_init_ctx(vscf_mbedtls_md_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_mbedtls_md_cleanup_ctx(vscf_mbedtls_md_t *self);

//
//  Return size of 'vscf_mbedtls_md_t'.
//
VSCF_PUBLIC size_t
vscf_mbedtls_md_ctx_size(void) {

    return sizeof(vscf_mbedtls_md_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_mbedtls_md_init(vscf_mbedtls_md_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_md_t));

    self->refcnt = 1;

    vscf_mbedtls_md_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_mbedtls_md_cleanup(vscf_mbedtls_md_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_mbedtls_md_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_md_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_mbedtls_md_t *
vscf_mbedtls_md_new(void) {

    vscf_mbedtls_md_t *self = (vscf_mbedtls_md_t *) vsc_alloc(sizeof (vscf_mbedtls_md_t));
    VSC_ASSERT_ALLOC(self);

    vscf_mbedtls_md_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_mbedtls_md_delete(vscf_mbedtls_md_t *self) {

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

    vscf_mbedtls_md_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_mbedtls_md_new ()'.
//
VSCF_PUBLIC void
vscf_mbedtls_md_destroy(vscf_mbedtls_md_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_mbedtls_md_t *self = *self_ref;
    *self_ref = NULL;

    vscf_mbedtls_md_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_mbedtls_md_t *
vscf_mbedtls_md_shallow_copy(vscf_mbedtls_md_t *self) {

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


//
//  Map alg id to correspond 'mbedtls_md_type_t'.
//
VSCF_PUBLIC mbedtls_md_type_t
vscf_mbedtls_md_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SHA224:
        return MBEDTLS_MD_SHA224;

    case vscf_alg_id_SHA256:
        return MBEDTLS_MD_SHA256;

    case vscf_alg_id_SHA384:
        return MBEDTLS_MD_SHA384;

    case vscf_alg_id_SHA512:
        return MBEDTLS_MD_SHA512;

    default:
        VSCF_ASSERT_OPT(0 && "Can not map alg id to mbedtls_md_type_t.");
        return MBEDTLS_MD_NONE;
    }
}
