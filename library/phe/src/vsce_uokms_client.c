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

#include "vsce_uokms_client.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_uokms_client_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <UOKMSModels.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
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
//  Note, this method is called automatically when method vsce_uokms_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_client_init_ctx(vsce_uokms_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_client_cleanup_ctx(vsce_uokms_client_t *self);

static mbedtls_ecp_group *
vsce_uokms_client_get_op_group(vsce_uokms_client_t *self);

static void
vsce_uokms_client_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vsce_uokms_client_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_client_ctx_size(void) {

    return sizeof(vsce_uokms_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_client_init(vsce_uokms_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_uokms_client_t));

    self->refcnt = 1;

    vsce_uokms_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_client_cleanup(vsce_uokms_client_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_uokms_client_cleanup_ctx(self);

    vsce_uokms_client_release_random(self);
    vsce_uokms_client_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_uokms_client_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_client_t *
vsce_uokms_client_new(void) {

    vsce_uokms_client_t *self = (vsce_uokms_client_t *) vsce_alloc(sizeof (vsce_uokms_client_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_uokms_client_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_client_delete(vsce_uokms_client_t *self) {

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

    vsce_uokms_client_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_client_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_client_destroy(vsce_uokms_client_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_uokms_client_t *self = *self_ref;
    *self_ref = NULL;

    vsce_uokms_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_client_t *
vsce_uokms_client_shallow_copy(vsce_uokms_client_t *self) {

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
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_client_use_random(vsce_uokms_client_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_client_take_random(vsce_uokms_client_t *self, vscf_impl_t *random) {

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
vsce_uokms_client_release_random(vsce_uokms_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_client_use_operation_random(vsce_uokms_client_t *self, vscf_impl_t *operation_random) {

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
vsce_uokms_client_take_operation_random(vsce_uokms_client_t *self, vscf_impl_t *operation_random) {

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
vsce_uokms_client_release_operation_random(vsce_uokms_client_t *self) {

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
//  Note, this method is called automatically when method vsce_uokms_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_client_init_ctx(vsce_uokms_client_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->group);
    int mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    self->keys_are_set = false;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_client_cleanup_ctx(vsce_uokms_client_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_free(&self->group);
}

VSCE_PUBLIC vsce_status_t
vsce_uokms_client_setup_defaults(vsce_uokms_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng1 = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng1);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng1);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_uokms_client_take_random(self, vscf_ctr_drbg_impl(rng1));

    vscf_ctr_drbg_t *rng2 = vscf_ctr_drbg_new();
    status = vscf_ctr_drbg_setup_defaults(rng2);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng2);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_uokms_client_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

    return vsce_status_SUCCESS;
}

//
//  Sets client private and server public key
//  Call this method before any other methods except `update enrollment record` and `generate client private key`
//  This function should be called only once
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_set_keys(vsce_uokms_client_t *self, vsc_data_t client_private_key, vsc_data_t server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(!self->keys_are_set);
    VSCE_ASSERT(
            vsc_data_is_valid(client_private_key) && client_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_data_is_valid(server_public_key) && server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_status_SUCCESS;

    self->keys_are_set = true;

    int mbedtls_status = 0;

    mbedtls_status = mbedtls_mpi_read_binary(&self->kc_private, client_private_key.bytes, client_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &self->kc_private);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(
            &self->group, &self->ks_public, server_public_key.bytes, server_public_key.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &self->ks_public) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err;
    }

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_status = mbedtls_mpi_lset(&one, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_group *op_group = vsce_uokms_client_get_op_group(self);

    mbedtls_status =
            mbedtls_ecp_muladd(op_group, &self->k_public, &self->kc_private, &self->group.G, &one, &self->ks_public);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_uokms_client_free_op_group(op_group);
    mbedtls_mpi_free(&one);

err:
    return status;
}

//
//  Generates client private key
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_client_private_key(vsce_uokms_client_t *self, vsc_buffer_t *client_private_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(client_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_make_secure(client_private_key);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &priv, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_write_binary(
            &priv, vsc_buffer_unused_bytes(client_private_key), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

err:
    mbedtls_mpi_free(&priv);

    return status;
}

//
//  Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
//  a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
//  Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_encrypt_wrap(
        vsce_uokms_client_t *self, vsc_buffer_t *wrap, size_t encryption_key_len, vsc_buffer_t *encryption_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT_PTR(wrap);
    VSCE_ASSERT(vsc_buffer_len(wrap) == 0 && vsc_buffer_capacity(wrap) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT(encryption_key_len > 0);
    VSCE_ASSERT_PTR(encryption_key);
    VSCE_ASSERT(vsc_buffer_len(encryption_key) == 0 && vsc_buffer_capacity(encryption_key) >= encryption_key_len);

    vsc_buffer_make_secure(encryption_key);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &r, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto err;
    }

    mbedtls_ecp_point W;
    mbedtls_ecp_point_init(&W);

    mbedtls_ecp_group *op_group = vsce_uokms_client_get_op_group(self);

    mbedtls_status = mbedtls_ecp_mul(op_group, &W, &r, &self->group.G, vscf_mbedtls_bridge_random, self->random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &W, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(wrap), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(wrap, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&W);

    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);

    mbedtls_status = mbedtls_ecp_mul(op_group, &S, &r, &self->k_public, vscf_mbedtls_bridge_random, self->random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_uokms_client_free_op_group(op_group);

    byte seed[vsce_phe_common_PHE_POINT_LENGTH];

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, seed, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&S);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));
    // TODO: Add some hkdf info
    vscf_hkdf_derive(hkdf, vsc_data(seed, sizeof(seed)), encryption_key_len, encryption_key);

    vscf_hkdf_destroy(&hkdf);

    vsce_zeroize(seed, sizeof(seed));

err:
    mbedtls_mpi_free(&r);

    return status;
}

//
//  Decrypts data (and verifies additional data) using account key
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_decrypt_request(
        vsce_uokms_client_t *self, vsc_data_t wrap, vsc_buffer_t *deblind_factor, vsc_buffer_t *decrypt_request) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_data_is_valid(wrap) && wrap.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_PTR(deblind_factor);
    VSCE_ASSERT(vsc_buffer_len(deblind_factor) == 0 &&
                vsc_buffer_capacity(deblind_factor) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_PTR(decrypt_request);
    VSCE_ASSERT(vsc_buffer_len(decrypt_request) == 0 &&
                vsc_buffer_capacity(decrypt_request) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_make_secure(deblind_factor);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point W;
    mbedtls_ecp_point_init(&W);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &W, wrap.bytes, wrap.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &W) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err1;
    }

    mbedtls_mpi b;
    mbedtls_mpi_init(&b);

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &b, vscf_mbedtls_bridge_random, self->random);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto err2;
    }

    mbedtls_mpi bInv;
    mbedtls_mpi_init(&bInv);

    mbedtls_status = mbedtls_mpi_inv_mod(&bInv, &b, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_write_binary(
            &bInv, vsc_buffer_unused_bytes(deblind_factor), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(deblind_factor, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_free(&bInv);

    mbedtls_ecp_point U;
    mbedtls_ecp_point_init(&U);

    mbedtls_ecp_group *op_group = vsce_uokms_client_get_op_group(self);

    mbedtls_status = mbedtls_ecp_mul(op_group, &U, &b, &W, vscf_mbedtls_bridge_random, self->random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_uokms_client_free_op_group(op_group);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &U, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(decrypt_request), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(decrypt_request, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&U);

err2:
    mbedtls_mpi_free(&b);

err1:
    mbedtls_ecp_point_free(&W);

    return status;
}

//
//  Decrypts data (and verifies additional data) using account key
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_process_decrypt_response(vsce_uokms_client_t *self, vsc_data_t wrap, vsc_data_t decrypt_response,
        vsc_data_t deblind_factor, size_t encryption_key_len, vsc_buffer_t *encryption_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_data_is_valid(wrap) && wrap.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT(vsc_data_is_valid(decrypt_response) && decrypt_response.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT(vsc_data_is_valid(deblind_factor) && deblind_factor.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(encryption_key_len > 0);
    VSCE_ASSERT_PTR(encryption_key);
    VSCE_ASSERT(vsc_buffer_len(encryption_key) == 0 && vsc_buffer_capacity(encryption_key) >= encryption_key_len);

    vsc_buffer_make_secure(encryption_key);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point W;
    mbedtls_ecp_point_init(&W);

    int mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &W, wrap.bytes, wrap.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &W) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err1;
    }

    mbedtls_ecp_point V;
    mbedtls_ecp_point_init(&V);

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &V, decrypt_response.bytes, decrypt_response.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &V) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err2;
    }

    mbedtls_mpi bInv;
    mbedtls_mpi_init(&bInv);

    mbedtls_status = mbedtls_mpi_read_binary(&bInv, deblind_factor.bytes, deblind_factor.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);

    mbedtls_ecp_group *op_group = vsce_uokms_client_get_op_group(self);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &S, &bInv, &V, &self->kc_private, &W);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_uokms_client_free_op_group(op_group);

    byte seed[vsce_phe_common_PHE_POINT_LENGTH];

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, seed, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));
    // TODO: Add some hkdf info
    vscf_hkdf_derive(hkdf, vsc_data(seed, sizeof(seed)), encryption_key_len, encryption_key);

    vsce_zeroize(seed, sizeof(seed));

    vscf_hkdf_destroy(&hkdf);

    mbedtls_ecp_point_free(&S);

    mbedtls_mpi_free(&bInv);

err2:
    mbedtls_ecp_point_free(&V);

err1:
    mbedtls_ecp_point_free(&W);

    return status;
}

//
//  Updates client's private key and server's public key using server's update token
//  Use output values to instantiate new client instance with new keys
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_rotate_keys(vsce_uokms_client_t *self, vsc_data_t update_token, vsc_buffer_t *new_client_private_key,
        vsc_buffer_t *new_server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(update_token.len == vsce_phe_common_PHE_POINT_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(new_client_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_client_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_uokms_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_mpi a;
    mbedtls_mpi_init(&a);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&a, update_token.bytes, update_token.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &a);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_mpi aInv;
    mbedtls_mpi_init(&aInv);

    mbedtls_status = mbedtls_mpi_inv_mod(&aInv, &a, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi new_kc;
    mbedtls_mpi_init(&new_kc);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_kc, &self->kc_private, &aInv);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_kc, &new_kc, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_write_binary(
            &new_kc, vsc_buffer_unused_bytes(new_client_private_key), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(new_client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point new_Ks;
    mbedtls_ecp_point_init(&new_Ks);

    mbedtls_status = mbedtls_ecp_mul(
            op_group, &new_Ks, &aInv, &self->ks_public, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &new_Ks, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(new_server_public_key), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(new_server_public_key, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&new_Ks);

    mbedtls_mpi_free(&new_kc);

    mbedtls_mpi_free(&aInv);
priv_err:
    mbedtls_mpi_free(&a);

    vsce_uokms_client_free_op_group(op_group);

    return status;
}

static mbedtls_ecp_group *
vsce_uokms_client_get_op_group(vsce_uokms_client_t *self) {

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
vsce_uokms_client_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCE_MULTI_THREADING
    mbedtls_ecp_group_free(op_group);
    vsce_dealloc(op_group);
#else
    VSCE_UNUSED(op_group);
#endif
}
