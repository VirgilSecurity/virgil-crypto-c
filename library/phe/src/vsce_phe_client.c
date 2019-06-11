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
//  Class for client-side PHE crypto operations.
//  This class is thread-safe in case if VSCE_MULTI_THREAD defined
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_phe_client.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_client_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <PHEModels.pb.h>
#include <pb_decode.h>
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
//  Note, this method is called automatically when method vsce_phe_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_client_init_ctx(vsce_phe_client_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *self);

static vsce_status_t
vsce_phe_client_check_success_proof(vsce_phe_client_t *self, mbedtls_ecp_group *op_group,
        const ProofOfSuccess *success_proof, vsc_data_t ns, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1) VSCE_NODISCARD;

static vsce_status_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *self, mbedtls_ecp_group *op_group, const ProofOfFail *fail_proof,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, const mbedtls_ecp_point *hs0) VSCE_NODISCARD;

static mbedtls_ecp_group *
vsce_phe_client_get_op_group(vsce_phe_client_t *self);

static void
vsce_phe_client_free_op_group(mbedtls_ecp_group *op_group);

//
//  Return size of 'vsce_phe_client_t'.
//
VSCE_PUBLIC size_t
vsce_phe_client_ctx_size(void) {

    return sizeof(vsce_phe_client_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_client_init(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_phe_client_t));

    self->refcnt = 1;

    vsce_phe_client_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_client_cleanup(vsce_phe_client_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vsce_phe_client_cleanup_ctx(self);

        vsce_phe_client_release_random(self);
        vsce_phe_client_release_operation_random(self);

        vsce_zeroize(self, sizeof(vsce_phe_client_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_new(void) {

    vsce_phe_client_t *self = (vsce_phe_client_t *) vsce_alloc(sizeof (vsce_phe_client_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_phe_client_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_client_delete(vsce_phe_client_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsce_phe_client_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_client_new ()'.
//
VSCE_PUBLIC void
vsce_phe_client_destroy(vsce_phe_client_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_phe_client_t *self = *self_ref;
    *self_ref = NULL;

    vsce_phe_client_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_shallow_copy(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_client_use_random(vsce_phe_client_t *self, vscf_impl_t *random) {

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
vsce_phe_client_take_random(vsce_phe_client_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_random(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_client_use_operation_random(vsce_phe_client_t *self, vscf_impl_t *operation_random) {

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
vsce_phe_client_take_operation_random(vsce_phe_client_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT_PTR(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = operation_random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_operation_random(vsce_phe_client_t *self) {

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
//  Note, this method is called automatically when method vsce_phe_client_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_client_init_ctx(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    self->simple_swu = vscf_simple_swu_new();
    self->phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_group_init(&self->group);
    int mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->one);
    mbedtls_mpi_init(&self->minus_one);

    mbedtls_status = mbedtls_mpi_lset(&self->one, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_lset(&self->minus_one, -1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->y);
    mbedtls_mpi_init(&self->minus_y);
    mbedtls_mpi_init(&self->y_inv);
    mbedtls_ecp_point_init(&self->x);

    self->keys_are_set = false;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_simple_swu_destroy(&self->simple_swu);
    mbedtls_ecp_group_free(&self->group);
    vsce_phe_hash_destroy(&self->phe_hash);

    mbedtls_mpi_free(&self->one);
    mbedtls_mpi_free(&self->minus_one);

    mbedtls_mpi_free(&self->y);
    mbedtls_mpi_free(&self->minus_y);
    mbedtls_mpi_free(&self->y_inv);
    mbedtls_ecp_point_free(&self->x);
}

VSCE_PUBLIC vsce_status_t
vsce_phe_client_setup_defaults(vsce_phe_client_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_ctr_drbg_t *rng1 = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng1);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng1);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_phe_client_take_random(self, vscf_ctr_drbg_impl(rng1));

    vscf_ctr_drbg_t *rng2 = vscf_ctr_drbg_new();
    status = vscf_ctr_drbg_setup_defaults(rng2);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng2);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_phe_client_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

    return vsce_status_SUCCESS;
}

//
//  Sets client private and server public key
//  Call this method before any other methods except `update enrollment record` and `generate client private key`
//  This function should be called only once
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_set_keys(vsce_phe_client_t *self, vsc_data_t client_private_key, vsc_data_t server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(!self->keys_are_set);

    self->keys_are_set = true;

    VSCE_ASSERT(client_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    memcpy(self->client_private_key, client_private_key.bytes, client_private_key.len);

    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    memcpy(self->server_public_key, server_public_key.bytes, server_public_key.len);

    int mbedtls_status = 0;

    mbedtls_status = mbedtls_mpi_read_binary(&self->y, self->client_private_key, sizeof(self->client_private_key));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &self->y);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_sub_mpi(&self->minus_y, &self->group.N, &self->y);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_inv_mod(&self->y_inv, &self->y, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_point_read_binary(
            &self->group, &self->x, self->server_public_key, sizeof(self->server_public_key));

    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &self->x) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto err;
    }

err:
    return status;
}

//
//  Generates client private key
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_generate_client_private_key(vsce_phe_client_t *self, vsc_buffer_t *client_private_key) {

    VSCE_ASSERT_PTR(self);

    VSCE_ASSERT(vsc_buffer_len(client_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

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
//  Buffer size needed to fit EnrollmentRecord
//
VSCE_PUBLIC size_t
vsce_phe_client_enrollment_record_len(vsce_phe_client_t *self) {

    VSCE_UNUSED(self);

    return EnrollmentRecord_size;
}

//
//  Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
//  a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
//  Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_enroll_account(vsce_phe_client_t *self, vsc_data_t enrollment_response, vsc_data_t password,
        vsc_buffer_t *enrollment_record, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_buffer_len(enrollment_record) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(enrollment_record) >= vsce_phe_client_enrollment_record_len(self));
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_make_secure(account_key);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    EnrollmentResponse response = EnrollmentResponse_init_zero;

    if (enrollment_response.len > EnrollmentResponse_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t stream = pb_istream_from_buffer(enrollment_response.bytes, enrollment_response.len);

    bool pb_status = pb_decode(&stream, EnrollmentResponse_fields, &response);
    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &c0, response.c0, sizeof(response.c0));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &c0) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto proof_err;
    }
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &c1, response.c1, sizeof(response.c1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &c1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto proof_err;
    }

    status = vsce_phe_client_check_success_proof(
            self, op_group, &response.proof, vsc_data(response.ns, sizeof(response.ns)), &c0, &c1);

    if (status != vsce_status_SUCCESS) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto proof_err;
    }

    EnrollmentRecord record = EnrollmentRecord_init_zero;

    vsc_buffer_t nc;
    vsc_buffer_init(&nc);
    vsc_buffer_use(&nc, record.nc, sizeof(record.nc));

    vscf_status_t f_status;
    f_status = vscf_random(self->random, vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH, &nc);

    if (f_status != vscf_status_SUCCESS) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto rng_err1;
    }

    byte rnd_m_buffer[vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH];

    vsc_buffer_t rnd_m;
    vsc_buffer_init(&rnd_m);
    vsc_buffer_use(&rnd_m, rnd_m_buffer, sizeof(rnd_m_buffer));

    f_status = vscf_random(self->random, vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, &rnd_m);
    if (f_status != vscf_status_SUCCESS) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto rng_err2;
    }

    mbedtls_ecp_point hc0, hc1;
    mbedtls_ecp_point_init(&hc0);
    mbedtls_ecp_point_init(&hc1);

    vsce_phe_hash_hc0(self->phe_hash, vsc_buffer_data(&nc), password, &hc0);
    vsce_phe_hash_hc1(self->phe_hash, vsc_buffer_data(&nc), password, &hc1);

    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);

    vscf_simple_swu_data_to_point(self->simple_swu, vsc_buffer_data(&rnd_m), &M);

    vsce_phe_hash_derive_account_key(self->phe_hash, &M, account_key);

    mbedtls_ecp_point t0, t1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t0, &self->one, &c0, &self->y, &hc0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &c1, &self->y, &hc1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &t1, &self->y, &M);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    memcpy(record.ns, response.ns, sizeof(response.ns));
    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t0, sizeof(record.t0));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t1, sizeof(record.t1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            vsc_buffer_unused_bytes(enrollment_record), vsc_buffer_unused_len(enrollment_record));
    VSCE_ASSERT(pb_encode(&ostream, EnrollmentRecord_fields, &record));
    vsc_buffer_inc_used(enrollment_record, ostream.bytes_written);
    vsce_zeroize(&record, sizeof(record));

    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);

    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&hc1);
    mbedtls_ecp_point_free(&M);

rng_err1:
    vsc_buffer_delete(&nc);

rng_err2:
    vsc_buffer_delete(&rnd_m);

    vsce_zeroize(rnd_m_buffer, sizeof(rnd_m_buffer));

proof_err:
    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

pb_err:
    vsce_zeroize(&response, sizeof(response));
    vsce_phe_client_free_op_group(op_group);

    return status;
}

//
//  Buffer size needed to fit VerifyPasswordRequest
//
VSCE_PUBLIC size_t
vsce_phe_client_verify_password_request_len(vsce_phe_client_t *self) {

    VSCE_UNUSED(self);

    return VerifyPasswordRequest_size;
}

//
//  Creates a request for further password verification at the PHE server side.
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_create_verify_password_request(vsce_phe_client_t *self, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_buffer_t *verify_password_request) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_buffer_len(verify_password_request) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(verify_password_request) >= vsce_phe_client_verify_password_request_len(self));
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    EnrollmentRecord record = EnrollmentRecord_init_zero;

    if (enrollment_record.len > EnrollmentRecord_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t istream = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
    bool pb_status = pb_decode(&istream, EnrollmentRecord_fields, &record);

    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    int mbedtls_status = 0;

    mbedtls_ecp_point t0;
    mbedtls_ecp_point_init(&t0);
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &t0, record.t0, sizeof(record.t0));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &t0) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_ecp_point hc0;
    mbedtls_ecp_point_init(&hc0);

    vsce_phe_hash_hc0(self->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &c0, &self->one, &t0, &self->minus_y, &hc0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    VerifyPasswordRequest request = VerifyPasswordRequest_init_zero;
    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, request.c0, sizeof(request.c0));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    memcpy(request.ns, record.ns, sizeof(record.ns));

    pb_ostream_t ostream = pb_ostream_from_buffer(
            vsc_buffer_unused_bytes(verify_password_request), vsc_buffer_unused_len(verify_password_request));
    VSCE_ASSERT(pb_encode(&ostream, VerifyPasswordRequest_fields, &request));
    vsc_buffer_inc_used(verify_password_request, ostream.bytes_written);
    vsce_zeroize(&request, sizeof(request));

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&hc0);

ecp_err:
    mbedtls_ecp_point_free(&t0);

pb_err:
    vsce_zeroize(&record, sizeof(&record));
    vsce_phe_client_free_op_group(op_group);

    return status;
}

//
//  Verifies PHE server's answer
//  If login succeeded, extracts account key
//  If login failed account key will be empty
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_check_response_and_decrypt(vsce_phe_client_t *self, vsc_data_t password, vsc_data_t enrollment_record,
        vsc_data_t verify_password_response, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_make_secure(account_key);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
    EnrollmentRecord record = EnrollmentRecord_init_zero;

    if (enrollment_record.len > EnrollmentRecord_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t istream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
    bool pb_status = pb_decode(&istream1, EnrollmentRecord_fields, &record);
    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    if (verify_password_response.len > VerifyPasswordResponse_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t istream2 = pb_istream_from_buffer(verify_password_response.bytes, verify_password_response.len);
    pb_status = pb_decode(&istream2, VerifyPasswordResponse_fields, &response);
    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    if ((response.res && response.which_proof != VerifyPasswordResponse_success_tag) ||
            (!response.res && response.which_proof != VerifyPasswordResponse_fail_tag)) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    mbedtls_ecp_point t0, t1, c1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&c1);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &t0, record.t0, sizeof(record.t0));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &t0) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &t1, record.t1, sizeof(record.t1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &t1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &c1, response.c1, sizeof(response.c1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &c1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_ecp_point hc0, hc1;
    mbedtls_ecp_point_init(&hc0);
    mbedtls_ecp_point_init(&hc1);

    vsce_phe_hash_hc0(self->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);
    vsce_phe_hash_hc1(self->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc1);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);
    mbedtls_status = mbedtls_ecp_muladd(op_group, &c0, &self->one, &t0, &self->minus_y, &hc0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (response.res) {
        status = vsce_phe_client_check_success_proof(
                self, op_group, &response.proof.success, vsc_data(record.ns, sizeof(record.ns)), &c0, &c1);

        if (status != vsce_status_SUCCESS) {
            goto err;
        }

        mbedtls_ecp_point M;
        mbedtls_ecp_point_init(&M);

        mbedtls_status = mbedtls_ecp_muladd(&self->group, &M, &self->minus_one, &c1, &self->minus_y, &hc1);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_ecp_muladd(op_group, &M, &self->one, &t1, &self->one, &M);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status =
                mbedtls_ecp_mul(op_group, &M, &self->y_inv, &M, vscf_mbedtls_bridge_random, self->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        vsce_phe_hash_derive_account_key(self->phe_hash, &M, account_key);

        mbedtls_ecp_point_free(&M);
    } else {
        mbedtls_ecp_point hs0;
        mbedtls_ecp_point_init(&hs0);

        vsce_phe_hash_hs0(self->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);

        status = vsce_phe_client_check_fail_proof(self, op_group, &response.proof.fail, &c0, &c1, &hs0);
        if (status != vsce_status_SUCCESS) {
            mbedtls_ecp_point_free(&hs0);
            goto err;
        }

        mbedtls_ecp_point_free(&hs0);
    }

err:
    mbedtls_ecp_point_free(&c0);

    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&hc1);

ecp_err:
    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&c1);

pb_err:
    vsce_zeroize(&record, sizeof(record));
    vsce_zeroize(&response, sizeof(response));
    vsce_phe_client_free_op_group(op_group);

    return status;
}

static vsce_status_t
vsce_phe_client_check_success_proof(vsce_phe_client_t *self, mbedtls_ecp_group *op_group,
        const ProofOfSuccess *success_proof, vsc_data_t ns, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT_PTR(success_proof);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);

    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point term1, term2, term3;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);

    int mbedtls_status = 0;
    mbedtls_status =
            mbedtls_ecp_point_read_binary(&self->group, &term1, success_proof->term1, sizeof(success_proof->term1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status =
            mbedtls_ecp_point_read_binary(&self->group, &term2, success_proof->term2, sizeof(success_proof->term2));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term2) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status =
            mbedtls_ecp_point_read_binary(&self->group, &term3, success_proof->term3, sizeof(success_proof->term3));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term3) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &blind_x);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(self->phe_hash, ns, &hs0);
    vsce_phe_hash_hs1(self->phe_hash, ns, &hs1);

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_phe_hash_hash_z_success(self->phe_hash, vsc_data(self->server_public_key, sizeof(self->server_public_key)), c0,
            c1, &term1, &term2, &term3, &challenge);

    // if term1 * (c0 ** challenge) != hs0 ** blind_x:
    // return False

    mbedtls_ecp_point t1, t2;
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&t2);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &term1, &challenge, c0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status =
            mbedtls_ecp_mul(&self->group, &t2, &blind_x, &hs0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto err;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    // if term2 * (c1 ** challenge) != hs1 ** blind_x:
    // return False

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &term2, &challenge, c1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status =
            mbedtls_ecp_mul(&self->group, &t2, &blind_x, &hs1, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto err;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    // if term3 * (self.X ** challenge) != self.G ** blind_x:
    // return False

    mbedtls_status = mbedtls_ecp_muladd(&self->group, &t1, &self->one, &term3, &challenge, &self->x);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_mul(
            op_group, &t2, &blind_x, &self->group.G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_SUCCESS_PROOF;
        goto err;
    }

err:
    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    mbedtls_mpi_free(&challenge);

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);

priv_err:
    mbedtls_mpi_free(&blind_x);

ecp_err:
    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);

    return status;
}

static vsce_status_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *self, mbedtls_ecp_group *op_group, const ProofOfFail *fail_proof,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, const mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT_PTR(fail_proof);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(hs0);

    vsce_status_t status = vsce_status_SUCCESS;

    mbedtls_ecp_point term1, term2, term3, term4;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);
    mbedtls_ecp_point_init(&term4);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &term1, fail_proof->term1, sizeof(fail_proof->term1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &term2, fail_proof->term2, sizeof(fail_proof->term2));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term2) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &term3, fail_proof->term3, sizeof(fail_proof->term3));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term3) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &term4, fail_proof->term4, sizeof(fail_proof->term4));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &term4) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_mpi blind_A, blind_B;
    mbedtls_mpi_init(&blind_A);
    mbedtls_mpi_init(&blind_B);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_A, fail_proof->blind_a, sizeof(fail_proof->blind_a));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &blind_A);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_status = mbedtls_mpi_read_binary(&blind_B, fail_proof->blind_b, sizeof(fail_proof->blind_b));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &blind_B);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_phe_hash_hash_z_failure(self->phe_hash, vsc_data(self->server_public_key, sizeof(self->server_public_key)), c0,
            c1, &term1, &term2, &term3, &term4, &challenge);

    mbedtls_ecp_point t1, t2;
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&t2);

    // if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
    // return False

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &term1, &self->one, &term2);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &t1, &challenge, c1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t2, &blind_A, c0, &blind_B, hs0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_FAIL_PROOF;
        goto err;
    }

    // if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
    // return False

    mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &self->one, &term3, &self->one, &term4);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_muladd(&self->group, &t2, &blind_A, &self->x, &blind_B, &self->group.G);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        status = vsce_status_ERROR_INVALID_FAIL_PROOF;
        goto err;
    }

err:
    mbedtls_mpi_free(&challenge);

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

priv_err:
    mbedtls_mpi_free(&blind_A);
    mbedtls_mpi_free(&blind_B);

ecp_err:
    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);
    mbedtls_ecp_point_free(&term4);

    return status;
}

//
//  Updates client's private key and server's public key using server's update token
//  Use output values to instantiate new client instance with new keys
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_rotate_keys(vsce_phe_client_t *self, vsc_data_t update_token, vsc_buffer_t *new_client_private_key,
        vsc_buffer_t *new_server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->keys_are_set);
    VSCE_ASSERT(vsc_buffer_len(new_client_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_client_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    UpdateToken token = UpdateToken_init_zero;

    if (update_token.len > UpdateToken_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t stream = pb_istream_from_buffer(update_token.bytes, update_token.len);

    bool pb_status = pb_decode(&stream, UpdateToken_fields, &token);

    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &a);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &b);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_mpi new_y;
    mbedtls_mpi_init(&new_y);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_y, &self->y, &a);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_y, &new_y, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_write_binary(
            &new_y, vsc_buffer_unused_bytes(new_client_private_key), vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_inc_used(new_client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point new_X;
    mbedtls_ecp_point_init(&new_X);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &new_X, &a, &self->x, &b, &self->group.G);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &new_X, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(new_server_public_key), vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_inc_used(new_server_public_key, olen);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_free(&new_y);

    mbedtls_ecp_point_free(&new_X);

priv_err:
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

pb_err:
    vsce_zeroize(&token, sizeof(token));
    vsce_phe_client_free_op_group(op_group);

    return status;
}

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_status_t
vsce_phe_client_update_enrollment_record(vsce_phe_client_t *self, vsc_data_t enrollment_record, vsc_data_t update_token,
        vsc_buffer_t *new_enrollment_record) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(new_enrollment_record) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_enrollment_record) >= vsce_phe_client_enrollment_record_len(self));

    mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(self);

    vsce_status_t status = vsce_status_SUCCESS;

    UpdateToken token = UpdateToken_init_zero;
    EnrollmentRecord record = EnrollmentRecord_init_zero;

    if (enrollment_record.len > EnrollmentRecord_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t stream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);

    bool pb_status = pb_decode(&stream1, EnrollmentRecord_fields, &record);
    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    if (update_token.len > UpdateToken_size) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    pb_istream_t stream2 = pb_istream_from_buffer(update_token.bytes, update_token.len);

    pb_status = pb_decode(&stream2, UpdateToken_fields, &token);
    if (!pb_status) {
        status = vsce_status_ERROR_PROTOBUF_DECODE_FAILED;
        goto pb_err;
    }

    int mbedtls_status = 0;

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &a);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &b);
    if (mbedtls_status != 0) {
        status = vsce_status_ERROR_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_ecp_point t0, t1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &t0, record.t0, sizeof(record.t0));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &t0) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &t1, record.t1, sizeof(record.t1));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &t1) != 0) {
        status = vsce_status_ERROR_INVALID_PUBLIC_KEY;
        goto ecp_err;
    }

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(self->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);
    vsce_phe_hash_hs1(self->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs1);

    mbedtls_ecp_point new_t0, new_t1;
    mbedtls_ecp_point_init(&new_t0);
    mbedtls_ecp_point_init(&new_t1);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &new_t0, &a, &t0, &b, &hs0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_muladd(op_group, &new_t1, &a, &t1, &b, &hs1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    EnrollmentRecord new_record = EnrollmentRecord_init_zero;

    memcpy(new_record.ns, record.ns, sizeof(new_record.ns));
    memcpy(new_record.nc, record.nc, sizeof(new_record.nc));

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &new_t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, new_record.t0, sizeof(new_record.t0));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &new_t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, new_record.t1, sizeof(new_record.t1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            vsc_buffer_unused_bytes(new_enrollment_record), vsc_buffer_unused_len(new_enrollment_record));

    VSCE_ASSERT(pb_encode(&ostream, EnrollmentRecord_fields, &new_record));
    vsc_buffer_inc_used(new_enrollment_record, ostream.bytes_written);
    vsce_zeroize(&new_record, sizeof(new_record));

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);

    mbedtls_ecp_point_free(&new_t0);
    mbedtls_ecp_point_free(&new_t1);

ecp_err:
    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);

priv_err:
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

pb_err:
    vsce_zeroize(&token, sizeof(token));
    vsce_zeroize(&record, sizeof(record));
    vsce_phe_client_free_op_group(op_group);

    return status;
}

static mbedtls_ecp_group *
vsce_phe_client_get_op_group(vsce_phe_client_t *self) {

#if VSCE_MULTI_THREAD
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
vsce_phe_client_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCE_MULTI_THREAD
    mbedtls_ecp_group_free(op_group);
    vsce_dealloc(op_group);
#endif
}
