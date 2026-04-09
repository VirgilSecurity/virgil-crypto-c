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
//  Bridge between MbedTLS ECP module and virgil foundation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_ecp.h"
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
//  Note, this method is called automatically when method vscf_mbedtls_ecp_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_mbedtls_ecp_init_ctx(vscf_mbedtls_ecp_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_mbedtls_ecp_cleanup_ctx(vscf_mbedtls_ecp_t *self);

//
//  Return size of 'vscf_mbedtls_ecp_t'.
//
VSCF_PUBLIC size_t
vscf_mbedtls_ecp_ctx_size(void) {

    return sizeof(vscf_mbedtls_ecp_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_mbedtls_ecp_init(vscf_mbedtls_ecp_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_ecp_t));

    self->refcnt = 1;

    vscf_mbedtls_ecp_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_mbedtls_ecp_cleanup(vscf_mbedtls_ecp_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_mbedtls_ecp_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_ecp_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_mbedtls_ecp_t *
vscf_mbedtls_ecp_new(void) {

    vscf_mbedtls_ecp_t *self = (vscf_mbedtls_ecp_t *) vsc_alloc(sizeof (vscf_mbedtls_ecp_t));
    VSC_ASSERT_ALLOC(self);

    vscf_mbedtls_ecp_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_mbedtls_ecp_delete(vscf_mbedtls_ecp_t *self) {

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

    vscf_mbedtls_ecp_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_mbedtls_ecp_new ()'.
//
VSCF_PUBLIC void
vscf_mbedtls_ecp_destroy(vscf_mbedtls_ecp_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_mbedtls_ecp_t *self = *self_ref;
    *self_ref = NULL;

    vscf_mbedtls_ecp_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_mbedtls_ecp_t *
vscf_mbedtls_ecp_shallow_copy(vscf_mbedtls_ecp_t *self) {

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
//  Map "alg id" to correspond "mbedtls_ecp_group_id".
//
VSCF_PUBLIC mbedtls_ecp_group_id
vscf_mbedtls_ecp_group_id_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return MBEDTLS_ECP_DP_SECP256R1;
    default:
        return MBEDTLS_ECP_DP_NONE;
    }
}

//
//  Map "mbedtls_ecp_group_id" to correspond "alg id".
//
VSCF_PUBLIC vscf_alg_id_t
vscf_mbedtls_ecp_group_id_to_alg_id(mbedtls_ecp_group_id grp_id) {

    VSCF_ASSERT(grp_id != MBEDTLS_ECP_DP_NONE);

    switch (grp_id) {
    case MBEDTLS_ECP_DP_SECP256R1:
        return vscf_alg_id_SECP256R1;
    default:
        return vscf_alg_id_NONE;
    }
}

//
//  Validate if "alg id" belongs to ECC.
//
VSCF_PUBLIC vscf_status_t
vscf_mbedtls_ecp_group_load(vscf_alg_id_t alg_id, mbedtls_ecp_group *ecc_grp) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(ecc_grp);

    const mbedtls_ecp_group_id grp_id = vscf_mbedtls_ecp_group_id_from_alg_id(alg_id);
    const int mbed_status = mbedtls_ecp_group_load(ecc_grp, grp_id);

    if (grp_id == MBEDTLS_ECP_DP_NONE || mbed_status != 0) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    return vscf_status_SUCCESS;
}
