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
//  Implements wrap rotation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_uokms_wrap_rotation.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_uokms_wrap_rotation_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
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
//  Note, this method is called automatically when method vsce_uokms_wrap_rotation_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_wrap_rotation_init_ctx(vsce_uokms_wrap_rotation_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_wrap_rotation_cleanup_ctx(vsce_uokms_wrap_rotation_t *self);

static mbedtls_ecp_group *
vsce_uokms_wrap_rotation_get_op_group(vsce_uokms_wrap_rotation_t *self);

static void
vsce_uokms_wrap_rotation_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vsce_uokms_wrap_rotation_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_wrap_rotation_ctx_size(void) {

    return sizeof(vsce_uokms_wrap_rotation_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_init(vsce_uokms_wrap_rotation_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_uokms_wrap_rotation_t));

    self->refcnt = 1;

    vsce_uokms_wrap_rotation_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_cleanup(vsce_uokms_wrap_rotation_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_uokms_wrap_rotation_cleanup_ctx(self);

    vsce_uokms_wrap_rotation_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_uokms_wrap_rotation_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_wrap_rotation_t *
vsce_uokms_wrap_rotation_new(void) {

    vsce_uokms_wrap_rotation_t *self = (vsce_uokms_wrap_rotation_t *) vsce_alloc(sizeof (vsce_uokms_wrap_rotation_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_uokms_wrap_rotation_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_delete(vsce_uokms_wrap_rotation_t *self) {

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

    vsce_uokms_wrap_rotation_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_wrap_rotation_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_destroy(vsce_uokms_wrap_rotation_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_uokms_wrap_rotation_t *self = *self_ref;
    *self_ref = NULL;

    vsce_uokms_wrap_rotation_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_wrap_rotation_t *
vsce_uokms_wrap_rotation_shallow_copy(vsce_uokms_wrap_rotation_t *self) {

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
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_use_operation_random(vsce_uokms_wrap_rotation_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_wrap_rotation_take_operation_random(vsce_uokms_wrap_rotation_t *self, vscf_impl_t *operation_random) {

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
vsce_uokms_wrap_rotation_release_operation_random(vsce_uokms_wrap_rotation_t *self) {

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
//  Note, this method is called automatically when method vsce_uokms_wrap_rotation_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_wrap_rotation_init_ctx(vsce_uokms_wrap_rotation_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->group);
    int status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT(status == 0);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_wrap_rotation_cleanup_ctx(vsce_uokms_wrap_rotation_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_free(&self->group);
    mbedtls_mpi_free(&self->a);
}

//
//  Setups dependencies with default values.
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_setup_defaults(vsce_uokms_wrap_rotation_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_uokms_wrap_rotation_take_operation_random(self, vscf_ctr_drbg_impl(rng));

    return vsce_status_SUCCESS;
}

//
//  Sets update token. Should be called only once and before any other function
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_set_update_token(vsce_uokms_wrap_rotation_t *self, vsc_data_t update_token) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_data_is_valid(update_token) && update_token.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    mbedtls_mpi_init(&self->a);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&self->a, update_token.bytes, update_token.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &self->a);
    if (mbedtls_status != 0) {
        return vsce_status_ERROR_INVALID_PRIVATE_KEY;
    }

    return vsce_status_SUCCESS;
}

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_wrap_rotation_update_wrap(vsce_uokms_wrap_rotation_t *self, vsc_data_t wrap, vsc_buffer_t *new_wrap) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_data_is_valid(wrap));
    VSCE_ASSERT(vsc_buffer_len(new_wrap) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_wrap) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_status_SUCCESS;

    if (wrap.len != vsce_phe_common_PHE_PUBLIC_KEY_LENGTH) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err1;
    }

    mbedtls_ecp_point W;
    mbedtls_ecp_point_init(&W);

    int mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &W, wrap.bytes, wrap.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &W) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err;
    }

    mbedtls_ecp_point new_W;
    mbedtls_ecp_point_init(&new_W);

    mbedtls_ecp_group *op_group = vsce_uokms_wrap_rotation_get_op_group(self);

    mbedtls_status =
            mbedtls_ecp_mul(op_group, &new_W, &self->a, &W, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_uokms_wrap_rotation_free_op_group(op_group);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &new_W, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(new_wrap), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(new_wrap, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&new_W);

err:
    mbedtls_ecp_point_free(&W);

err1:

    return status;
}

static mbedtls_ecp_group *
vsce_uokms_wrap_rotation_get_op_group(vsce_uokms_wrap_rotation_t *self) {

#if VSCE_MULTI_THREADING
    VSCE_UNUSED(self);

    mbedtls_ecp_group *new_group = (mbedtls_ecp_group *)vsce_alloc(sizeof(mbedtls_ecp_group));
    mbedtls_ecp_group_init(new_group);

    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_ecp_group_load(new_group, MBEDTLS_ECP_DP_SECP256R1));

    return new_group;
#else
    return &self->group;
#endif
}

static void
vsce_uokms_wrap_rotation_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCE_MULTI_THREADING
    mbedtls_ecp_group_free(op_group);
    vsce_dealloc(op_group);
#else
    VSCE_UNUSED(op_group);
#endif
}
