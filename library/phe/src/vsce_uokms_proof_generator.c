//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "vsce_uokms_proof_generator.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_uokms_proof_generator_defs.h"

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
//  Note, this method is called automatically when method vsce_uokms_proof_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_proof_generator_init_ctx(vsce_uokms_proof_generator_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_proof_generator_cleanup_ctx(vsce_uokms_proof_generator_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_generator_did_setup_random(vsce_uokms_proof_generator_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_generator_did_release_random(vsce_uokms_proof_generator_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_generator_did_setup_operation_random(vsce_uokms_proof_generator_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_generator_did_release_operation_random(vsce_uokms_proof_generator_t *self);

//
//  Return size of 'vsce_uokms_proof_generator_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_proof_generator_ctx_size(void) {

    return sizeof(vsce_uokms_proof_generator_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_init(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_uokms_proof_generator_t));

    self->refcnt = 1;

    vsce_uokms_proof_generator_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_cleanup(vsce_uokms_proof_generator_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_uokms_proof_generator_cleanup_ctx(self);

    vsce_uokms_proof_generator_release_random(self);
    vsce_uokms_proof_generator_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_uokms_proof_generator_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_proof_generator_t *
vsce_uokms_proof_generator_new(void) {

    vsce_uokms_proof_generator_t *self = (vsce_uokms_proof_generator_t *) vsce_alloc(sizeof (vsce_uokms_proof_generator_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_uokms_proof_generator_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_delete(vsce_uokms_proof_generator_t *self) {

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

    vsce_uokms_proof_generator_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_proof_generator_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_destroy(vsce_uokms_proof_generator_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_uokms_proof_generator_t *self = *self_ref;
    *self_ref = NULL;

    vsce_uokms_proof_generator_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_proof_generator_t *
vsce_uokms_proof_generator_shallow_copy(vsce_uokms_proof_generator_t *self) {

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
vsce_uokms_proof_generator_use_random(vsce_uokms_proof_generator_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vsce_uokms_proof_generator_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_take_random(vsce_uokms_proof_generator_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vsce_uokms_proof_generator_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_release_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vsce_uokms_proof_generator_did_release_random(self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_use_operation_random(vsce_uokms_proof_generator_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);

    vsce_uokms_proof_generator_did_setup_operation_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_take_operation_random(vsce_uokms_proof_generator_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;

    vsce_uokms_proof_generator_did_setup_operation_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_proof_generator_release_operation_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->operation_random);

    vsce_uokms_proof_generator_did_release_operation_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_uokms_proof_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_proof_generator_init_ctx(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    self->proof_generator = vsce_proof_generator_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_proof_generator_cleanup_ctx(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_proof_generator_destroy(&self->proof_generator);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_generator_did_setup_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->random) {
        vsce_proof_generator_release_random(self->proof_generator);
        vsce_proof_generator_use_random(self->proof_generator, self->random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_generator_did_release_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_proof_generator_did_setup_operation_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->operation_random) {
        vsce_proof_generator_release_operation_random(self->proof_generator);
        vsce_proof_generator_use_operation_random(self->proof_generator, self->operation_random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_proof_generator_did_release_operation_random(vsce_uokms_proof_generator_t *self) {

    VSCE_ASSERT_PTR(self);
}

VSCE_PUBLIC vsce_status_t
vsce_uokms_proof_generator_prove_success(vsce_uokms_proof_generator_t *self, mbedtls_ecp_group *op_group,
        const mbedtls_mpi *priv, const mbedtls_ecp_point *pub, const mbedtls_ecp_point *u, const mbedtls_ecp_point *v,
        UOKMSProofOfSuccess *success_proof) {

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point term1, term2;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    status = vsce_proof_generator_prove_success(
            self->proof_generator, op_group, priv, pub, u, v, NULL, NULL, &blind_x, &term1, &term2, NULL);

    if (status != vsce_status_SUCCESS) {
        goto err;
    }
    size_t olen = 0;
    int mbedtls_status = mbedtls_ecp_point_write_binary(
            op_group, &term1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, success_proof->term1, sizeof(success_proof->term1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(success_proof->term1));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            op_group, &term2, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, success_proof->term2, sizeof(success_proof->term2));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(success_proof->term2));

    mbedtls_status = mbedtls_mpi_write_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

err:
    mbedtls_mpi_free(&blind_x);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);

    return status;
}
