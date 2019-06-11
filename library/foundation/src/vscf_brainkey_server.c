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

#include "vscf_brainkey_server.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_random.h"
#include "vscf_brainkey_server_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_mbedtls_bridge_random.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_brainkey_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_brainkey_server_init_ctx(vscf_brainkey_server_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_brainkey_server_cleanup_ctx(vscf_brainkey_server_t *self);

static mbedtls_ecp_group *
vscf_brainkey_server_get_op_group(vscf_brainkey_server_t *self);

static void
vscf_brainkey_server_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vscf_brainkey_server_t'.
//
VSCF_PUBLIC size_t
vscf_brainkey_server_ctx_size(void) {

    return sizeof(vscf_brainkey_server_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_brainkey_server_init(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_brainkey_server_t));

    self->refcnt = 1;

    vscf_brainkey_server_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_brainkey_server_cleanup(vscf_brainkey_server_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_brainkey_server_cleanup_ctx(self);

        vscf_brainkey_server_release_random(self);
        vscf_brainkey_server_release_operation_random(self);

        vscf_zeroize(self, sizeof(vscf_brainkey_server_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_brainkey_server_t *
vscf_brainkey_server_new(void) {

    vscf_brainkey_server_t *self = (vscf_brainkey_server_t *) vscf_alloc(sizeof (vscf_brainkey_server_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_brainkey_server_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_brainkey_server_delete(vscf_brainkey_server_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_brainkey_server_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_brainkey_server_new ()'.
//
VSCF_PUBLIC void
vscf_brainkey_server_destroy(vscf_brainkey_server_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_brainkey_server_t *self = *self_ref;
    *self_ref = NULL;

    vscf_brainkey_server_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_brainkey_server_t *
vscf_brainkey_server_shallow_copy(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_brainkey_server_use_random(vscf_brainkey_server_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_brainkey_server_take_random(vscf_brainkey_server_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT_PTR(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_brainkey_server_release_random(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_brainkey_server_use_operation_random(vscf_brainkey_server_t *self, vscf_impl_t *operation_random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(operation_random);
    VSCF_ASSERT(self->operation_random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_brainkey_server_take_operation_random(vscf_brainkey_server_t *self, vscf_impl_t *operation_random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(operation_random);
    VSCF_ASSERT_PTR(self->operation_random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_brainkey_server_release_operation_random(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->operation_random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_brainkey_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_brainkey_server_init_ctx(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->group);
    int mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_brainkey_server_cleanup_ctx(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_group_free(&self->group);
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_server_setup_defaults(vscf_brainkey_server_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng1 = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng1);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng1);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_brainkey_server_take_random(self, vscf_ctr_drbg_impl(rng1));

    vscf_ctr_drbg_t *rng2 = vscf_ctr_drbg_new();
    status = vscf_ctr_drbg_setup_defaults(rng2);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng2);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_brainkey_server_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_server_generate_identity_secret(vscf_brainkey_server_t *self, vsc_buffer_t *identity_secret) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(identity_secret);

    vscf_status_t status = vscf_status_SUCCESS;

    if (vsc_buffer_unused_len(identity_secret) < vscf_brainkey_server_MPI_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN;
        goto input_err;
    }

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &x, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_RANDOM_FAILED;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_write_binary(
            &x, vsc_buffer_unused_bytes(identity_secret), vsc_buffer_unused_len(identity_secret));
    vsc_buffer_inc_used(identity_secret, vscf_brainkey_server_MPI_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

err:
    mbedtls_mpi_free(&x);

input_err:
    return status;
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_server_harden(vscf_brainkey_server_t *self, vsc_data_t identity_secret, vsc_data_t blinded_point,
        vsc_buffer_t *hardened_point) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hardened_point);
    VSCF_ASSERT(vsc_data_is_valid(identity_secret));
    VSCF_ASSERT(vsc_data_is_valid(blinded_point));

    vscf_status_t status = vscf_status_SUCCESS;

    if (identity_secret.len != vscf_brainkey_server_MPI_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN;
        goto input_err;
    }

    if (blinded_point.len != vscf_brainkey_server_POINT_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN;
        goto input_err;
    }

    if (vsc_buffer_unused_len(hardened_point) < vscf_brainkey_server_POINT_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN;
        goto input_err;
    }

    mbedtls_ecp_point A;
    mbedtls_ecp_point_init(&A);

    mbedtls_ecp_point Y;
    mbedtls_ecp_point_init(&Y);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    int mbedtls_status = mbedtls_mpi_read_binary(&x, identity_secret.bytes, identity_secret.len);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_INVALID_IDENTITY_SECRET;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &A, blinded_point.bytes, blinded_point.len);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INVALID_POINT;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_check_pubkey(&self->group, &A);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INVALID_POINT;
        goto err;
    }

    mbedtls_ecp_group *op_group = vscf_brainkey_server_get_op_group(self);

    mbedtls_status = mbedtls_ecp_mul(op_group, &Y, &x, &A, vscf_mbedtls_bridge_random, self->operation_random);

    vscf_brainkey_server_free_op_group(op_group);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &Y, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(hardened_point), vscf_brainkey_server_POINT_LEN);
    vsc_buffer_inc_used(hardened_point, vscf_brainkey_server_POINT_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCF_ASSERT(olen == vscf_brainkey_server_POINT_LEN);

err:
    mbedtls_mpi_free(&x);
    mbedtls_ecp_point_free(&Y);
    mbedtls_ecp_point_free(&A);

input_err:
    return status;
}

static mbedtls_ecp_group *
vscf_brainkey_server_get_op_group(vscf_brainkey_server_t *self) {

#if VSCF_MULTI_THREAD
    VSCF_UNUSED(self);

    mbedtls_ecp_group *new_group = (mbedtls_ecp_group *)vscf_alloc(sizeof(mbedtls_ecp_group));
    mbedtls_ecp_group_init(new_group);

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_ecp_group_load(new_group, MBEDTLS_ECP_DP_SECP256R1));

    return new_group;
#else
    return &self->group;
#endif
}

static void
vscf_brainkey_server_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCF_MULTI_THREAD
    mbedtls_ecp_group_free(op_group);
    vscf_dealloc(op_group);
#endif
}
