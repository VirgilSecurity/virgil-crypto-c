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

#include "vsce_uokms_proof_verifier.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_uokms_proof_verifier_defs.h"

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
//  Note, this method is called automatically when method vsce_uokms_proof_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_proof_verifier_init_ctx(vsce_uokms_proof_verifier_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_proof_verifier_cleanup_ctx(vsce_uokms_proof_verifier_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_verifier_did_setup_random(vsce_uokms_proof_verifier_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_verifier_did_release_random(vsce_uokms_proof_verifier_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_verifier_did_setup_operation_random(vsce_uokms_proof_verifier_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_verifier_did_release_operation_random(vsce_uokms_proof_verifier_t *self);

//
//  Return size of 'vsce_uokms_proof_verifier_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_proof_verifier_ctx_size(void) {

    return sizeof(vsce_uokms_proof_verifier_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_init(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_uokms_proof_verifier_t));

    self->refcnt = 1;

    vsce_uokms_proof_verifier_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_cleanup(vsce_uokms_proof_verifier_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_uokms_proof_verifier_cleanup_ctx(self);

    vsce_uokms_proof_verifier_release_random(self);
    vsce_uokms_proof_verifier_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_uokms_proof_verifier_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_proof_verifier_t *
vsce_uokms_proof_verifier_new(void) {

    vsce_uokms_proof_verifier_t *self = (vsce_uokms_proof_verifier_t *) vsce_alloc(sizeof (vsce_uokms_proof_verifier_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_uokms_proof_verifier_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_delete(vsce_uokms_proof_verifier_t *self) {

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

    vsce_uokms_proof_verifier_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_proof_verifier_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_destroy(vsce_uokms_proof_verifier_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_uokms_proof_verifier_t *self = *self_ref;
    *self_ref = NULL;

    vsce_uokms_proof_verifier_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_proof_verifier_t *
vsce_uokms_proof_verifier_shallow_copy(vsce_uokms_proof_verifier_t *self) {

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
vsce_uokms_proof_verifier_use_random(vsce_uokms_proof_verifier_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vsce_uokms_proof_verifier_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_take_random(vsce_uokms_proof_verifier_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vsce_uokms_proof_verifier_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_release_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vsce_uokms_proof_verifier_did_release_random(self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_use_operation_random(vsce_uokms_proof_verifier_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);

    vsce_uokms_proof_verifier_did_setup_operation_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_take_operation_random(vsce_uokms_proof_verifier_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;

    vsce_uokms_proof_verifier_did_setup_operation_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_proof_verifier_release_operation_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->operation_random);

    vsce_uokms_proof_verifier_did_release_operation_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_uokms_proof_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_proof_verifier_init_ctx(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    self->proof_verifier = vsce_proof_verifier_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_proof_verifier_cleanup_ctx(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_proof_verifier_destroy(&self->proof_verifier);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_verifier_did_setup_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->random) {
        vsce_proof_verifier_release_random(self->proof_verifier);
        vsce_proof_verifier_use_random(self->proof_verifier, self->random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_verifier_did_release_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_verifier_did_setup_operation_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->operation_random) {
        vsce_proof_verifier_release_operation_random(self->proof_verifier);
        vsce_proof_verifier_use_operation_random(self->proof_verifier, self->operation_random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_verifier_did_release_operation_random(vsce_uokms_proof_verifier_t *self) {

    VSCE_ASSERT_PTR(self);
}

VSCE_PUBLIC vsce_status_t
vsce_uokms_proof_verifier_check_success_proof(vsce_uokms_proof_verifier_t *self, mbedtls_ecp_group *op_group,
        const ProofOfSuccess *success_proof, const mbedtls_ecp_point *pub, const mbedtls_ecp_point *u,
        const mbedtls_ecp_point *v) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(op_group);
    VSCE_ASSERT_PTR(success_proof);
    VSCE_ASSERT_PTR(pub);
    VSCE_ASSERT_PTR(u);
    VSCE_ASSERT_PTR(v);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point term1, term2;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);

    int mbedtls_status = 0;
    mbedtls_status =
            mbedtls_ecp_point_read_binary(op_group, &term1, success_proof->term1, sizeof(success_proof->term1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(op_group, &term1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status =
            mbedtls_ecp_point_read_binary(op_group, &term2, success_proof->term2, sizeof(success_proof->term2));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(op_group, &term2) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(op_group, &blind_x);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    status = vsce_proof_verifier_check_success_proof(
            self->proof_verifier, op_group, pub, &blind_x, &term1, &term2, NULL, u, v, NULL, NULL);

priv_err:
    mbedtls_mpi_free(&blind_x);

ecp_err:
    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);

    return status;
}
