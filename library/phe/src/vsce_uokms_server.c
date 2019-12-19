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

#include "vsce_uokms_server.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_uokms_server_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <UOKMSModels.pb.h>
#include <pb_encode.h>
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
//  Note, this method is called automatically when method vsce_uokms_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_server_init_ctx(vsce_uokms_server_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_server_cleanup_ctx(vsce_uokms_server_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_server_did_setup_random(vsce_uokms_server_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_server_did_release_random(vsce_uokms_server_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_server_did_setup_operation_random(vsce_uokms_server_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_server_did_release_operation_random(vsce_uokms_server_t *self);

static mbedtls_ecp_group *
vsce_uokms_server_get_op_group(vsce_uokms_server_t *self);

static void
vsce_uokms_server_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vsce_uokms_server_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_server_ctx_size(void) {

    return sizeof(vsce_uokms_server_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_server_init(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_uokms_server_t));

    self->refcnt = 1;

    vsce_uokms_server_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_server_cleanup(vsce_uokms_server_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_uokms_server_cleanup_ctx(self);

    vsce_uokms_server_release_random(self);
    vsce_uokms_server_release_operation_random(self);

    vsce_zeroize(self, sizeof(vsce_uokms_server_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_server_t *
vsce_uokms_server_new(void) {

    vsce_uokms_server_t *self = (vsce_uokms_server_t *) vsce_alloc(sizeof (vsce_uokms_server_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_uokms_server_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_server_delete(vsce_uokms_server_t *self) {

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

    vsce_uokms_server_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_server_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_server_destroy(vsce_uokms_server_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_uokms_server_t *self = *self_ref;
    *self_ref = NULL;

    vsce_uokms_server_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_server_t *
vsce_uokms_server_shallow_copy(vsce_uokms_server_t *self) {

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
vsce_uokms_server_use_random(vsce_uokms_server_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vsce_uokms_server_did_setup_random(self);
}

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_server_take_random(vsce_uokms_server_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vsce_uokms_server_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_server_release_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vsce_uokms_server_did_release_random(self);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_server_use_operation_random(vsce_uokms_server_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);

    vsce_uokms_server_did_setup_operation_random(self);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_server_take_operation_random(vsce_uokms_server_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;

    vsce_uokms_server_did_setup_operation_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_server_release_operation_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->operation_random);

    vsce_uokms_server_did_release_operation_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_uokms_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_uokms_server_init_ctx(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->group);
    int mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    self->proof_generator = vsce_uokms_proof_generator_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_uokms_server_cleanup_ctx(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    mbedtls_ecp_group_free(&self->group);
    vsce_uokms_proof_generator_destroy(&self->proof_generator);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_server_did_setup_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->random) {
        vsce_uokms_proof_generator_release_random(self->proof_generator);
        vsce_uokms_proof_generator_use_random(self->proof_generator, self->random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_server_did_release_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vsce_uokms_server_did_setup_operation_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    if (self->operation_random) {
        vsce_uokms_proof_generator_release_operation_random(self->proof_generator);
        vsce_uokms_proof_generator_use_operation_random(self->proof_generator, self->operation_random);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vsce_uokms_server_did_release_operation_random(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);
}

VSCE_PUBLIC vsce_status_t
vsce_uokms_server_setup_defaults(vsce_uokms_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng1 = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng1);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng1);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_uokms_server_take_random(self, vscf_ctr_drbg_impl(rng1));

    vscf_ctr_drbg_t *rng2 = vscf_ctr_drbg_new();
    status = vscf_ctr_drbg_setup_defaults(rng2);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng2);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_uokms_server_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

    return vsce_status_SUCCESS;
}

//
//  Generates new NIST P-256 server key pair for some client
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_server_generate_server_key_pair(
        vsce_uokms_server_t *self, vsc_buffer_t *server_private_key, vsc_buffer_t *server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(server_private_key);
    VSCE_ASSERT(vsc_buffer_len(server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_uokms_server_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;
    int mbedtls_status = 0;

    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);

    mbedtls_ecp_point pub;
    mbedtls_ecp_point_init(&pub);

    mbedtls_status = mbedtls_ecp_gen_keypair(op_group, &priv, &pub, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_write_binary(
            &priv, vsc_buffer_unused_bytes(server_private_key), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(server_public_key), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(server_public_key, olen);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

err:
    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&priv);

    vsce_uokms_server_free_op_group(op_group);

    return status;
}

//
//  Buffer size needed to fit VerifyPasswordResponse
//
VSCE_PUBLIC size_t
vsce_uokms_server_decrypt_response_len(vsce_uokms_server_t *self) {

    VSCE_UNUSED(self);

    return DecryptResponse_size;
}

//
//  Generates a new random enrollment and proof for a new user
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_server_process_decrypt_request(vsce_uokms_server_t *self, vsc_data_t server_private_key,
        vsc_data_t decrypt_request, vsc_buffer_t *decrypt_response) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(
            vsc_data_is_valid(server_private_key) && server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_data_is_valid(decrypt_request) && decrypt_request.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_PTR(decrypt_response);
    VSCE_ASSERT(vsc_buffer_len(decrypt_response) == 0 &&
                vsc_buffer_capacity(decrypt_response) >= vsce_uokms_server_decrypt_response_len(self));

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point U;
    mbedtls_ecp_point_init(&U);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &U, decrypt_request.bytes, decrypt_request.len);
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &U) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err1;
    }

    mbedtls_mpi ks;
    mbedtls_mpi_init(&ks);

    mbedtls_status = mbedtls_mpi_read_binary(&ks, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &ks);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_ecp_group *op_group = vsce_uokms_server_get_op_group(self);

    mbedtls_ecp_point Ks;
    mbedtls_ecp_point_init(&Ks);

    mbedtls_status =
            mbedtls_ecp_mul(op_group, &Ks, &ks, &op_group->G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point V;
    mbedtls_ecp_point_init(&V);

    mbedtls_status = mbedtls_ecp_mul(op_group, &V, &ks, &U, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    DecryptResponse response = DecryptResponse_init_zero;

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &V, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.v, sizeof(response.v));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    status = vsce_uokms_proof_generator_prove_success(
            self->proof_generator, op_group, &ks, &Ks, &U, &V, &response.proof);

    vsce_uokms_server_free_op_group(op_group);

    if (status != vsce_status_SUCCESS) {
        goto err;
    }

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &V, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.v, sizeof(response.v));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    pb_ostream_t ostream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(decrypt_response), vsc_buffer_capacity(decrypt_response));
    VSCE_ASSERT(pb_encode(&ostream, DecryptResponse_fields, &response));
    vsc_buffer_inc_used(decrypt_response, ostream.bytes_written);
    vsce_zeroize(&response, sizeof(response));

err:
    mbedtls_ecp_point_free(&V);
    mbedtls_ecp_point_free(&Ks);

priv_err:
    mbedtls_mpi_free(&ks);

err1:
    mbedtls_ecp_point_free(&U);

    return status;
}

//
//  Updates server's private and public keys and issues an update token for use on client's side
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_server_rotate_keys(vsce_uokms_server_t *self, vsc_data_t server_private_key,
        vsc_buffer_t *new_server_private_key, vsc_buffer_t *new_server_public_key, vsc_buffer_t *update_token) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(
            vsc_data_is_valid(server_private_key) && server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(update_token) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(update_token) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(new_server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_server_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_uokms_server_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_mpi ks;
    mbedtls_mpi_init(&ks);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&ks, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &ks);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_mpi a;
    mbedtls_mpi_init(&a);

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &a, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto err;
    }

    mbedtls_status =
            mbedtls_mpi_write_binary(&a, vsc_buffer_unused_bytes(update_token), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(update_token, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi aInv;
    mbedtls_mpi_init(&aInv);

    mbedtls_status = mbedtls_mpi_inv_mod(&aInv, &a, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi new_ks;
    mbedtls_mpi_init(&new_ks);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_ks, &ks, &aInv);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_ks, &new_ks, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_write_binary(
            &new_ks, vsc_buffer_unused_bytes(new_server_private_key), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(new_server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point new_Ks;
    mbedtls_ecp_point_init(&new_Ks);

    mbedtls_status = mbedtls_ecp_mul(
            op_group, &new_Ks, &new_ks, &self->group.G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &new_Ks, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(new_server_public_key), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(new_server_public_key, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&new_Ks);

    mbedtls_mpi_free(&new_ks);

    mbedtls_mpi_free(&aInv);
err:
    mbedtls_mpi_free(&a);

priv_err:
    mbedtls_mpi_free(&ks);

    vsce_uokms_server_free_op_group(op_group);

    return status;
}

static mbedtls_ecp_group *
vsce_uokms_server_get_op_group(vsce_uokms_server_t *self) {

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
vsce_uokms_server_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCE_MULTI_THREADING
    mbedtls_ecp_group_free(op_group);
    vsce_dealloc(op_group);
#else
    VSCE_UNUSED(op_group);
#endif
}
