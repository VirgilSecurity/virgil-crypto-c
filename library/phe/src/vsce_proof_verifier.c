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

#include "vsce_proof_verifier.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_proof_verifier_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/private/vscf_mbedtls_bridge_random.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_proof_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_proof_verifier_init_ctx(vsce_proof_verifier_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_proof_verifier_cleanup_ctx(vsce_proof_verifier_t *self);

//
//  Return size of 'vsce_proof_verifier_t'.
//
VSCE_PUBLIC size_t
vsce_proof_verifier_ctx_size(void) {

    return sizeof(vsce_proof_verifier_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_proof_verifier_init(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_proof_verifier_t));

    self->refcnt = 1;

    vsce_proof_verifier_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_proof_verifier_cleanup(vsce_proof_verifier_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_proof_verifier_cleanup_ctx(self);

    vsce_proof_verifier_release_random(self);
    vsce_proof_verifier_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_proof_verifier_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_proof_verifier_t *
vsce_proof_verifier_new(void) {

    vsce_proof_verifier_t *self = (vsce_proof_verifier_t *) vsce_alloc(sizeof (vsce_proof_verifier_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_proof_verifier_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_proof_verifier_delete(vsce_proof_verifier_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCE_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCE_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsce_proof_verifier_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_proof_verifier_new ()'.
//
VSCE_PUBLIC void
vsce_proof_verifier_destroy(vsce_proof_verifier_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_proof_verifier_t *self = *self_ref;
    *self_ref = NULL;

    vsce_proof_verifier_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_proof_verifier_t *
vsce_proof_verifier_shallow_copy(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_proof_verifier_use_random(vsce_proof_verifier_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_proof_verifier_take_random(vsce_proof_verifier_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_proof_verifier_release_random(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_proof_verifier_use_operation_random(vsce_proof_verifier_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_proof_verifier_take_operation_random(vsce_proof_verifier_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_proof_verifier_release_operation_random(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->operation_random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_proof_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_proof_verifier_init_ctx(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    self->phe_hash = vsce_phe_hash_new();

    mbedtls_mpi_init(&self->one);

    int mbedtls_status = mbedtls_mpi_lset(&self->one, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_proof_verifier_cleanup_ctx(vsce_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_phe_hash_destroy(&self->phe_hash);

    mbedtls_mpi_free(&self->one);
}

VSCE_PUBLIC vsce_status_t
vsce_proof_verifier_check_success_proof(vsce_proof_verifier_t *self, mbedtls_ecp_group *op_group,
        const mbedtls_ecp_point *pub, const mbedtls_mpi *blind_x, const mbedtls_ecp_point *term1,
        const mbedtls_ecp_point *term2, const mbedtls_ecp_point *term3, const mbedtls_ecp_point *p1,
        const mbedtls_ecp_point *p2, const mbedtls_ecp_point *q1, const mbedtls_ecp_point *q2) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(op_group);
    VSCE_ASSERT_PTR(pub);
    VSCE_ASSERT_PTR(blind_x);
    VSCE_ASSERT_PTR(term1);
    VSCE_ASSERT_PTR(term2);
    VSCE_ASSERT_PTR(p1);
    VSCE_ASSERT_PTR(p2);
    VSCE_ASSERT((term3 == NULL && q1 == NULL && q2 == NULL) || (term3 != NULL && q1 != NULL && q2 != NULL));

    vsce_status_t status = vsce_status_SUCCESS;

    bool tp_mode = false;

    if (term3 != NULL) {
        tp_mode = true;
    }

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_phe_hash_hash_z_success(self->phe_hash, pub, p2, q2, term1, term2, term3, &challenge);

    mbedtls_ecp_point t1, t2;
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&t2);

    // if term1 * (self.X ** challenge) != self.G ** blind_x:
    // return False

    int mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, term1, &challenge, pub);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status =
            mbedtls_ecp_mul(op_group, &t2, blind_x, &op_group->G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto err;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    // if term2 * (c0 ** challenge) != hs0 ** blind_x:
    // return False

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, term2, &challenge, p2);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_mul(op_group, &t2, blind_x, p1, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto err;
    }

    if (tp_mode) {
        mbedtls_ecp_point_free(&t1);
        mbedtls_ecp_point_free(&t2);

        // if term3 * (c1 ** challenge) != hs1 ** blind_x:
        // return False

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, term3, &challenge, q2);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status =
                mbedtls_ecp_mul(op_group, &t2, blind_x, q1, vscf_mbedtls_bridge_random, self->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
            goto err;
        }
    }

err:
    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    mbedtls_mpi_free(&challenge);

    return status;
}
