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

#include "vscf_brainkey_client.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_random.h"
#include "vscf_brainkey_client_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_hkdf.h"
#include "vscf_sha512.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_brainkey_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_brainkey_client_init_ctx(vscf_brainkey_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_brainkey_client_cleanup_ctx(vscf_brainkey_client_t *self);

static mbedtls_ecp_group *
vscf_brainkey_client_get_op_group(vscf_brainkey_client_t *self);

static void
vscf_brainkey_client_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vscf_brainkey_client_t'.
//
VSCF_PUBLIC size_t
vscf_brainkey_client_ctx_size(void) {

    return sizeof(vscf_brainkey_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_brainkey_client_init(vscf_brainkey_client_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_brainkey_client_t));

    self->refcnt = 1;

    vscf_brainkey_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_brainkey_client_cleanup(vscf_brainkey_client_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_brainkey_client_cleanup_ctx(self);

    vscf_brainkey_client_release_random(self);
    vscf_brainkey_client_release_operation_random(self);

    vscf_zeroize(self, sizeof(vscf_brainkey_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_brainkey_client_t *
vscf_brainkey_client_new(void) {

    vscf_brainkey_client_t *self = (vscf_brainkey_client_t *) vscf_alloc(sizeof (vscf_brainkey_client_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_brainkey_client_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_brainkey_client_delete(vscf_brainkey_client_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    VSCF_ASSERT(old_counter != 0);

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_brainkey_client_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_brainkey_client_new ()'.
//
VSCF_PUBLIC void
vscf_brainkey_client_destroy(vscf_brainkey_client_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_brainkey_client_t *self = *self_ref;
    *self_ref = NULL;

    vscf_brainkey_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_brainkey_client_t *
vscf_brainkey_client_shallow_copy(vscf_brainkey_client_t *self) {

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

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_brainkey_client_use_random(vscf_brainkey_client_t *self, vscf_impl_t *random) {

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
vscf_brainkey_client_take_random(vscf_brainkey_client_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_brainkey_client_release_random(vscf_brainkey_client_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_brainkey_client_use_operation_random(vscf_brainkey_client_t *self, vscf_impl_t *operation_random) {

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
vscf_brainkey_client_take_operation_random(vscf_brainkey_client_t *self, vscf_impl_t *operation_random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(operation_random);
    VSCF_ASSERT(self->operation_random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_brainkey_client_release_operation_random(vscf_brainkey_client_t *self) {

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
//  Note, this method is called automatically when method vscf_brainkey_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_brainkey_client_init_ctx(vscf_brainkey_client_t *self) {

    VSCF_ASSERT_PTR(self);

    self->simple_swu = vscf_simple_swu_new();

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
vscf_brainkey_client_cleanup_ctx(vscf_brainkey_client_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_simple_swu_destroy(&self->simple_swu);

    mbedtls_ecp_group_free(&self->group);
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_client_setup_defaults(vscf_brainkey_client_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng1 = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng1);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng1);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_brainkey_client_take_random(self, vscf_ctr_drbg_impl(rng1));

    vscf_ctr_drbg_t *rng2 = vscf_ctr_drbg_new();
    status = vscf_ctr_drbg_setup_defaults(rng2);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng2);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_brainkey_client_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_client_blind(
        vscf_brainkey_client_t *self, vsc_data_t password, vsc_buffer_t *deblind_factor, vsc_buffer_t *blinded_point) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(deblind_factor);
    VSCF_ASSERT_PTR(blinded_point);
    VSCF_ASSERT(vsc_data_is_valid(password));

    vscf_status_t status = vscf_status_SUCCESS;

    if (password.len == 0 || password.len > vscf_brainkey_client_MAX_PASSWORD_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN;
        goto input_err;
    }

    if (vsc_buffer_unused_len(deblind_factor) < vscf_brainkey_client_MPI_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN;
        goto input_err;
    }

    if (vsc_buffer_unused_len(blinded_point) < vscf_brainkey_client_POINT_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN;
        goto input_err;
    }

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_ecp_point A;
    mbedtls_ecp_point_init(&A);

    mbedtls_mpi rInv;
    mbedtls_mpi_init(&rInv);

    vscf_simple_swu_data_to_point(self->simple_swu, password, &P);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &r, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_RANDOM_FAILED;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_inv_mod(&rInv, &r, &self->group.N);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    mbedtls_ecp_group *op_group = vscf_brainkey_client_get_op_group(self);

    mbedtls_status = mbedtls_ecp_mul(op_group, &A, &r, &P, vscf_mbedtls_bridge_random, self->operation_random);

    vscf_brainkey_client_free_op_group(op_group);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &A, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(blinded_point), vscf_brainkey_client_POINT_LEN);
    vsc_buffer_inc_used(blinded_point, vscf_brainkey_client_POINT_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCF_ASSERT(olen == vscf_brainkey_client_POINT_LEN);

    mbedtls_status = mbedtls_mpi_write_binary(
            &rInv, vsc_buffer_unused_bytes(deblind_factor), vsc_buffer_unused_len(deblind_factor));
    vsc_buffer_inc_used(deblind_factor, vscf_brainkey_client_MPI_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

err:
    mbedtls_ecp_point_free(&A);
    mbedtls_mpi_free(&rInv);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&P);

input_err:
    return status;
}

VSCF_PUBLIC vscf_status_t
vscf_brainkey_client_deblind(vscf_brainkey_client_t *self, vsc_data_t password, vsc_data_t hardened_point,
        vsc_data_t deblind_factor, vsc_data_t key_name, vsc_buffer_t *seed) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(seed);
    VSCF_ASSERT(vsc_data_is_valid(deblind_factor));
    VSCF_ASSERT(vsc_data_is_valid(hardened_point));
    VSCF_ASSERT(vsc_data_is_valid(key_name));

    vscf_status_t status = vscf_status_SUCCESS;

    if (password.len == 0 || password.len > vscf_brainkey_client_MAX_PASSWORD_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN;
        goto input_err;
    }

    if (key_name.len > vscf_brainkey_client_MAX_KEY_NAME_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN;
        goto input_err;
    }

    if (deblind_factor.len != vscf_brainkey_client_MPI_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN;
        goto input_err;
    }

    if (hardened_point.len != vscf_brainkey_client_POINT_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN;
        goto input_err;
    }

    if (vsc_buffer_unused_len(seed) < vscf_brainkey_client_SEED_LEN) {
        status = vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN;
        goto input_err;
    }

    mbedtls_ecp_point Y;
    mbedtls_ecp_point_init(&Y);

    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);

    mbedtls_mpi rInv;
    mbedtls_mpi_init(&rInv);

    int mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &Y, hardened_point.bytes, hardened_point.len);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INVALID_POINT;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_check_pubkey(&self->group, &Y);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INVALID_POINT;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_read_binary(&rInv, deblind_factor.bytes, deblind_factor.len);
    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    mbedtls_ecp_group *op_group = vscf_brainkey_client_get_op_group(self);

    mbedtls_status = mbedtls_ecp_mul(op_group, &S, &rInv, &Y, vscf_mbedtls_bridge_random, self->operation_random);

    vscf_brainkey_client_free_op_group(op_group);

    if (mbedtls_status != 0) {
        status = vscf_status_ERROR_BRAINKEY_INTERNAL;
        goto err;
    }

    byte point[vscf_brainkey_client_POINT_LEN];

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, point, vscf_brainkey_client_POINT_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCF_ASSERT(olen == vscf_brainkey_client_POINT_LEN);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscf_hkdf_reset(hkdf, password, 0);
    vscf_hkdf_set_info(hkdf, key_name);
    vscf_hkdf_derive(hkdf, vsc_data(point, sizeof(point)), vscf_brainkey_client_SEED_LEN, seed);

    vscf_hkdf_destroy(&hkdf);

    vscf_zeroize(point, sizeof(point));

err:
    mbedtls_mpi_free(&rInv);
    mbedtls_ecp_point_free(&S);
    mbedtls_ecp_point_free(&Y);

input_err:
    return status;
}

static mbedtls_ecp_group *
vscf_brainkey_client_get_op_group(vscf_brainkey_client_t *self) {

#if VSCF_MULTI_THREADING
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
vscf_brainkey_client_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCF_MULTI_THREADING
    mbedtls_ecp_group_free(op_group);
    vscf_dealloc(op_group);
#else
    VSCF_UNUSED(op_group);
#endif
}
