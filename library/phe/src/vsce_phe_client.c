//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
vsce_phe_client_init_ctx(vsce_phe_client_t *phe_client_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *phe_client_ctx);

static vsce_error_t
vsce_phe_client_check_success_proof(vsce_phe_client_t *phe_client_ctx, mbedtls_ecp_group *op_group,
        const ProofOfSuccess *success_proof, vsc_data_t ns, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1);

static vsce_error_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *phe_client_ctx, mbedtls_ecp_group *op_group,
        const ProofOfFail *fail_proof, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1,
        const mbedtls_ecp_point *hs0);

static mbedtls_ecp_group *
vsce_phe_client_get_op_group(vsce_phe_client_t *phe_client_ctx);

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
vsce_phe_client_init(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vsce_zeroize(phe_client_ctx, sizeof(vsce_phe_client_t));

    phe_client_ctx->refcnt = 1;

    vsce_phe_client_init_ctx(phe_client_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_client_cleanup(vsce_phe_client_t *phe_client_ctx) {

    if (phe_client_ctx == NULL) {
        return;
    }

    if (phe_client_ctx->refcnt == 0) {
        return;
    }

    if (--phe_client_ctx->refcnt == 0) {
        vsce_phe_client_cleanup_ctx(phe_client_ctx);

        vsce_phe_client_release_random(phe_client_ctx);
        vsce_phe_client_release_operation_random(phe_client_ctx);

        vsce_zeroize(phe_client_ctx, sizeof(vsce_phe_client_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_new(void) {

    vsce_phe_client_t *phe_client_ctx = (vsce_phe_client_t *) vsce_alloc(sizeof (vsce_phe_client_t));
    VSCE_ASSERT_ALLOC(phe_client_ctx);

    vsce_phe_client_init(phe_client_ctx);

    phe_client_ctx->self_dealloc_cb = vsce_dealloc;

    return phe_client_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_client_delete(vsce_phe_client_t *phe_client_ctx) {

    if (phe_client_ctx == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_client_ctx->self_dealloc_cb;

    vsce_phe_client_cleanup(phe_client_ctx);

    if (phe_client_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_client_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_client_new ()'.
//
VSCE_PUBLIC void
vsce_phe_client_destroy(vsce_phe_client_t **phe_client_ctx_ref) {

    VSCE_ASSERT_PTR(phe_client_ctx_ref);

    vsce_phe_client_t *phe_client_ctx = *phe_client_ctx_ref;
    *phe_client_ctx_ref = NULL;

    vsce_phe_client_delete(phe_client_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_copy(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    ++phe_client_ctx->refcnt;

    return phe_client_ctx;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_client_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_client_ctx->random = vscf_impl_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_client_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_client_ctx->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_random(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vscf_impl_destroy(&phe_client_ctx->random);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_operation_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT_PTR(phe_client_ctx->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    phe_client_ctx->operation_random = vscf_impl_copy(operation_random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_operation_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT_PTR(phe_client_ctx->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    phe_client_ctx->operation_random = operation_random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_operation_random(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vscf_impl_destroy(&phe_client_ctx->operation_random);
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
vsce_phe_client_init_ctx(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    phe_client_ctx->phe_hash = vsce_phe_hash_new();

    vscf_ctr_drbg_impl_t *rng1, *rng2;
    rng1 = vscf_ctr_drbg_new();
    rng2 = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng1);
    vscf_ctr_drbg_setup_defaults(rng2);

    vsce_phe_client_take_random(phe_client_ctx, vscf_ctr_drbg_impl(rng1));
    vsce_phe_client_take_operation_random(phe_client_ctx, vscf_ctr_drbg_impl(rng2));

    mbedtls_ecp_group_init(&phe_client_ctx->group);
    int mbedtls_status = mbedtls_ecp_group_load(&phe_client_ctx->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&phe_client_ctx->one);
    mbedtls_mpi_init(&phe_client_ctx->minus_one);

    mbedtls_status = mbedtls_mpi_lset(&phe_client_ctx->one, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_lset(&phe_client_ctx->minus_one, -1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&phe_client_ctx->y);
    mbedtls_mpi_init(&phe_client_ctx->minus_y);
    mbedtls_mpi_init(&phe_client_ctx->y_inv);
    mbedtls_ecp_point_init(&phe_client_ctx->x);

    phe_client_ctx->keys_are_set = false;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    mbedtls_ecp_group_free(&phe_client_ctx->group);
    vsce_phe_hash_destroy(&phe_client_ctx->phe_hash);

    mbedtls_mpi_free(&phe_client_ctx->one);
    mbedtls_mpi_free(&phe_client_ctx->minus_one);

    mbedtls_mpi_free(&phe_client_ctx->y);
    mbedtls_mpi_free(&phe_client_ctx->minus_y);
    mbedtls_mpi_free(&phe_client_ctx->y_inv);
    mbedtls_ecp_point_free(&phe_client_ctx->x);
}

//
//  Sets client private and server public key
//  Call this method before any other methods except `update enrollment record` and `generate client private key`
//  This function should be called only once
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_set_keys(vsce_phe_client_t *phe_client_ctx, vsc_data_t client_private_key,
        vsc_data_t server_public_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(!phe_client_ctx->keys_are_set);

        phe_client_ctx->keys_are_set = true;

        VSCE_ASSERT(client_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
        memcpy(phe_client_ctx->client_private_key, client_private_key.bytes, client_private_key.len);

        VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
        memcpy(phe_client_ctx->server_public_key, server_public_key.bytes, server_public_key.len);

        int mbedtls_status = 0;

        mbedtls_status = mbedtls_mpi_read_binary(
                &phe_client_ctx->y, phe_client_ctx->client_private_key, sizeof(phe_client_ctx->client_private_key));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        vsce_error_t status = vsce_SUCCESS;

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &phe_client_ctx->y);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto err;
        }

        mbedtls_status = mbedtls_mpi_sub_mpi(&phe_client_ctx->minus_y, &phe_client_ctx->group.N, &phe_client_ctx->y);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_mpi_inv_mod(&phe_client_ctx->y_inv, &phe_client_ctx->y, &phe_client_ctx->group.N);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &phe_client_ctx->x,
                phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key));

        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &phe_client_ctx->x) != 0) {
            status = vsce_INVALID_ECP;
            goto err;
        }

    err:
        return status;
}

//
//  Generates client private key
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_generate_client_private_key(vsce_phe_client_t *phe_client_ctx, vsc_buffer_t *client_private_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);

        VSCE_ASSERT(vsc_buffer_len(client_private_key) == 0);
        VSCE_ASSERT(vsc_buffer_left(client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

        vsce_error_t status = vsce_SUCCESS;

        mbedtls_mpi priv;
        mbedtls_mpi_init(&priv);

        int mbedtls_status = 0;
        mbedtls_status =
                mbedtls_ecp_gen_privkey(&phe_client_ctx->group, &priv, vscf_mbedtls_bridge_random, phe_client_ctx->random);

        if (mbedtls_status != 0) {
            status = vsce_RNG_ERROR;
            goto err;
        }

        mbedtls_status = mbedtls_mpi_write_binary(
                &priv, vsc_buffer_ptr(client_private_key), vsc_buffer_capacity(client_private_key));
        vsc_buffer_reserve(client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    err:
        mbedtls_mpi_free(&priv);

        return status;
}

//
//  Buffer size needed to fit EnrollmentRecord
//
VSCE_PUBLIC size_t
vsce_phe_client_enrollment_record_len(vsce_phe_client_t *phe_client_ctx) {

    VSCE_UNUSED(phe_client_ctx);

    return EnrollmentRecord_size;
}

//
//  Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
//  a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
//  Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_enroll_account(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_response, vsc_data_t password,
        vsc_buffer_t *enrollment_record, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT(vsc_buffer_len(enrollment_record) == 0);
        VSCE_ASSERT(vsc_buffer_left(enrollment_record) >= vsce_phe_client_enrollment_record_len(phe_client_ctx));
        VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
        VSCE_ASSERT(vsc_buffer_left(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
        vsc_buffer_make_secure(account_key);
        VSCE_ASSERT(password.len > 0);
        VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

        mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(phe_client_ctx);

        vsce_error_t status = vsce_SUCCESS;

        if (enrollment_response.len > EnrollmentResponse_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        EnrollmentResponse response = EnrollmentResponse_init_zero;

        pb_istream_t stream = pb_istream_from_buffer(enrollment_response.bytes, enrollment_response.len);

        bool pb_status = pb_decode(&stream, EnrollmentResponse_fields, &response);
        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        mbedtls_ecp_point c0, c1;
        mbedtls_ecp_point_init(&c0);
        mbedtls_ecp_point_init(&c1);

        int mbedtls_status = 0;
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c0, response.c0, sizeof(response.c0));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &c0) != 0) {
            status = vsce_INVALID_ECP;
            goto proof_err;
        }
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c1, response.c1, sizeof(response.c1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &c1) != 0) {
            status = vsce_INVALID_ECP;
            goto proof_err;
        }

        status = vsce_phe_client_check_success_proof(
                phe_client_ctx, op_group, &response.proof, vsc_data(response.ns, sizeof(response.ns)), &c0, &c1);

        if (status != vsce_SUCCESS) {
            status = vsce_INVALID_SUCCESS_PROOF;
            goto proof_err;
        }

        EnrollmentRecord record = EnrollmentRecord_init_zero;

        vsc_buffer_t nc;
        vsc_buffer_init(&nc);
        vsc_buffer_use(&nc, record.nc, sizeof(record.nc));

        vscf_error_t f_status;
        f_status = vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH, &nc);

        if (f_status != vscf_SUCCESS) {
            status = vsce_RNG_ERROR;
            goto rng_err1;
        }

        byte rnd_m_buffer[vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH];

        vsc_buffer_t rnd_m;
        vsc_buffer_init(&rnd_m);
        vsc_buffer_use(&rnd_m, rnd_m_buffer, sizeof(rnd_m_buffer));

        f_status = vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, &rnd_m);
        if (f_status != vscf_SUCCESS) {
            status = vsce_RNG_ERROR;
            goto rng_err2;
        }

        mbedtls_ecp_point hc0, hc1;
        mbedtls_ecp_point_init(&hc0);
        mbedtls_ecp_point_init(&hc1);

        vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_buffer_data(&nc), password, &hc0);
        vsce_phe_hash_hc1(phe_client_ctx->phe_hash, vsc_buffer_data(&nc), password, &hc1);

        mbedtls_ecp_point M;
        mbedtls_ecp_point_init(&M);

        vsce_phe_hash_data_to_point(phe_client_ctx->phe_hash, vsc_buffer_data(&rnd_m), &M);

        vsce_phe_hash_derive_account_key(phe_client_ctx->phe_hash, &M, account_key);

        mbedtls_ecp_point t0, t1;
        mbedtls_ecp_point_init(&t0);
        mbedtls_ecp_point_init(&t1);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t0, &phe_client_ctx->one, &c0, &phe_client_ctx->y, &hc0);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &c1, &phe_client_ctx->y, &hc1);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &t1, &phe_client_ctx->y, &M);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        memcpy(record.ns, response.ns, sizeof(response.ns));
        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_client_ctx->group, &t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t0, sizeof(record.t0));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
        olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_client_ctx->group, &t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t1, sizeof(record.t1));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream =
                pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_record), vsc_buffer_capacity(enrollment_record));
        VSCE_ASSERT(pb_encode(&ostream, EnrollmentRecord_fields, &record));
        vsc_buffer_reserve(enrollment_record, ostream.bytes_written);

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
        vsce_phe_client_free_op_group(op_group);

        return status;
}

//
//  Buffer size needed to fit VerifyPasswordRequest
//
VSCE_PUBLIC size_t
vsce_phe_client_verify_password_request_len(vsce_phe_client_t *phe_client_ctx) {

    VSCE_UNUSED(phe_client_ctx);

    return VerifyPasswordRequest_size;
}

//
//  Creates a request for further password verification at the PHE server side.
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_create_verify_password_request(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_buffer_t *verify_password_request) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT(vsc_buffer_len(verify_password_request) == 0);
        VSCE_ASSERT(
                vsc_buffer_left(verify_password_request) >= vsce_phe_client_verify_password_request_len(phe_client_ctx));
        VSCE_ASSERT(password.len > 0);
        VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

        mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(phe_client_ctx);

        vsce_error_t status = vsce_SUCCESS;

        if (enrollment_record.len > EnrollmentRecord_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        EnrollmentRecord record = EnrollmentRecord_init_zero;

        pb_istream_t istream = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
        bool pb_status = pb_decode(&istream, EnrollmentRecord_fields, &record);

        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        int mbedtls_status = 0;

        mbedtls_ecp_point t0;
        mbedtls_ecp_point_init(&t0);
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t0, sizeof(record.t0));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &t0) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_ecp_point hc0;
        mbedtls_ecp_point_init(&hc0);

        vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);

        mbedtls_ecp_point c0;
        mbedtls_ecp_point_init(&c0);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &c0, &phe_client_ctx->one, &t0, &phe_client_ctx->minus_y, &hc0);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        VerifyPasswordRequest request = VerifyPasswordRequest_init_zero;
        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_client_ctx->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, request.c0, sizeof(request.c0));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        memcpy(request.ns, record.ns, sizeof(record.ns));

        pb_ostream_t ostream = pb_ostream_from_buffer(
                vsc_buffer_ptr(verify_password_request), vsc_buffer_capacity(verify_password_request));
        VSCE_ASSERT(pb_encode(&ostream, VerifyPasswordRequest_fields, &request));
        vsc_buffer_reserve(verify_password_request, ostream.bytes_written);

        mbedtls_ecp_point_free(&c0);
        mbedtls_ecp_point_free(&hc0);

    ecp_err:
        mbedtls_ecp_point_free(&t0);

    pb_err:
        vsce_phe_client_free_op_group(op_group);

        return status;
}

//
//  Verifies PHE server's answer
//  If login succeeded, extracts account key
//  If login failed account key will be empty
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_check_response_and_decrypt(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_data_t verify_password_response, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
        VSCE_ASSERT(vsc_buffer_left(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
        vsc_buffer_make_secure(account_key);
        VSCE_ASSERT(password.len > 0);
        VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

        mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(phe_client_ctx);

        vsce_error_t status = vsce_SUCCESS;

        if (enrollment_record.len > EnrollmentRecord_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        EnrollmentRecord record = EnrollmentRecord_init_zero;

        pb_istream_t istream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
        bool pb_status = pb_decode(&istream1, EnrollmentRecord_fields, &record);
        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        if (verify_password_response.len > VerifyPasswordResponse_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;

        pb_istream_t istream2 = pb_istream_from_buffer(verify_password_response.bytes, verify_password_response.len);
        pb_status = pb_decode(&istream2, VerifyPasswordResponse_fields, &response);
        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        if ((response.res && response.which_proof != VerifyPasswordResponse_success_tag) ||
                (!response.res && response.which_proof != VerifyPasswordResponse_fail_tag)) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        mbedtls_ecp_point t0, t1, c1;
        mbedtls_ecp_point_init(&t0);
        mbedtls_ecp_point_init(&t1);
        mbedtls_ecp_point_init(&c1);

        int mbedtls_status = 0;
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t0, sizeof(record.t0));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &t0) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t1, record.t1, sizeof(record.t1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &t1) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }
        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c1, response.c1, sizeof(response.c1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &c1) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_ecp_point hc0, hc1;
        mbedtls_ecp_point_init(&hc0);
        mbedtls_ecp_point_init(&hc1);

        vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);
        vsce_phe_hash_hc1(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc1);

        mbedtls_ecp_point c0;
        mbedtls_ecp_point_init(&c0);
        mbedtls_status = mbedtls_ecp_muladd(op_group, &c0, &phe_client_ctx->one, &t0, &phe_client_ctx->minus_y, &hc0);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (response.res) {
            status = vsce_phe_client_check_success_proof(
                    phe_client_ctx, op_group, &response.proof.success, vsc_data(record.ns, sizeof(record.ns)), &c0, &c1);

            if (status != vsce_SUCCESS) {
                goto err;
            }

            mbedtls_ecp_point M;
            mbedtls_ecp_point_init(&M);

            mbedtls_status = mbedtls_ecp_muladd(
                    &phe_client_ctx->group, &M, &phe_client_ctx->minus_one, &c1, &phe_client_ctx->minus_y, &hc1);
            VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
            mbedtls_status = mbedtls_ecp_muladd(op_group, &M, &phe_client_ctx->one, &t1, &phe_client_ctx->one, &M);
            VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

            mbedtls_status = mbedtls_ecp_mul(
                    op_group, &M, &phe_client_ctx->y_inv, &M, vscf_mbedtls_bridge_random, phe_client_ctx->operation_random);
            VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

            vsce_phe_hash_derive_account_key(phe_client_ctx->phe_hash, &M, account_key);

            mbedtls_ecp_point_free(&M);
        } else {
            mbedtls_ecp_point hs0;
            mbedtls_ecp_point_init(&hs0);

            vsce_phe_hash_hs0(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);

            status = vsce_phe_client_check_fail_proof(phe_client_ctx, op_group, &response.proof.fail, &c0, &c1, &hs0);
            if (status != vsce_SUCCESS) {
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
        vsce_phe_client_free_op_group(op_group);

        return status;
}

static vsce_error_t
vsce_phe_client_check_success_proof(vsce_phe_client_t *phe_client_ctx, mbedtls_ecp_group *op_group,
        const ProofOfSuccess *success_proof, vsc_data_t ns, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT_PTR(success_proof);

        VSCE_ASSERT(ns.len == vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);

        VSCE_ASSERT_PTR(c0);
        VSCE_ASSERT_PTR(c1);

        vsce_error_t status = vsce_SUCCESS;

        mbedtls_ecp_point term1, term2, term3;
        mbedtls_ecp_point_init(&term1);
        mbedtls_ecp_point_init(&term2);
        mbedtls_ecp_point_init(&term3);

        int mbedtls_status = 0;
        mbedtls_status = mbedtls_ecp_point_read_binary(
                &phe_client_ctx->group, &term1, success_proof->term1, sizeof(success_proof->term1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term1) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status = mbedtls_ecp_point_read_binary(
                &phe_client_ctx->group, &term2, success_proof->term2, sizeof(success_proof->term2));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term2) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status = mbedtls_ecp_point_read_binary(
                &phe_client_ctx->group, &term3, success_proof->term3, sizeof(success_proof->term3));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term3) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_mpi blind_x;
        mbedtls_mpi_init(&blind_x);

        mbedtls_status = mbedtls_mpi_read_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &blind_x);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_ecp_point hs0, hs1;
        mbedtls_ecp_point_init(&hs0);
        mbedtls_ecp_point_init(&hs1);

        vsce_phe_hash_hs0(phe_client_ctx->phe_hash, ns, &hs0);
        vsce_phe_hash_hs1(phe_client_ctx->phe_hash, ns, &hs1);

        mbedtls_mpi challenge;
        mbedtls_mpi_init(&challenge);

        vsce_phe_hash_hash_z_success(phe_client_ctx->phe_hash,
                vsc_data(phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key)), c0, c1, &term1,
                &term2, &term3, &challenge);

        // if term1 * (c0 ** challenge) != hs0 ** blind_x:
        // return False

        mbedtls_ecp_point t1, t2;
        mbedtls_ecp_point_init(&t1);
        mbedtls_ecp_point_init(&t2);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &term1, &challenge, c0);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_mul(
                &phe_client_ctx->group, &t2, &blind_x, &hs0, vscf_mbedtls_bridge_random, phe_client_ctx->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_INVALID_SUCCESS_PROOF;
            goto err;
        }

        mbedtls_ecp_point_free(&t1);
        mbedtls_ecp_point_free(&t2);

        // if term2 * (c1 ** challenge) != hs1 ** blind_x:
        // return False

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &term2, &challenge, c1);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_mul(
                &phe_client_ctx->group, &t2, &blind_x, &hs1, vscf_mbedtls_bridge_random, phe_client_ctx->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_INVALID_SUCCESS_PROOF;
            goto err;
        }

        mbedtls_ecp_point_free(&t1);
        mbedtls_ecp_point_free(&t2);

        // if term3 * (self.X ** challenge) != self.G ** blind_x:
        // return False

        mbedtls_status = mbedtls_ecp_muladd(
                &phe_client_ctx->group, &t1, &phe_client_ctx->one, &term3, &challenge, &phe_client_ctx->x);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_mul(op_group, &t2, &blind_x, &phe_client_ctx->group.G, vscf_mbedtls_bridge_random,
                phe_client_ctx->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_INVALID_SUCCESS_PROOF;
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

static vsce_error_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *phe_client_ctx, mbedtls_ecp_group *op_group,
        const ProofOfFail *fail_proof, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1,
        const mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT_PTR(fail_proof);
        VSCE_ASSERT_PTR(c0);
        VSCE_ASSERT_PTR(c1);
        VSCE_ASSERT_PTR(hs0);

        vsce_error_t status = vsce_SUCCESS;

        mbedtls_ecp_point term1, term2, term3, term4;
        mbedtls_ecp_point_init(&term1);
        mbedtls_ecp_point_init(&term2);
        mbedtls_ecp_point_init(&term3);
        mbedtls_ecp_point_init(&term4);

        int mbedtls_status = 0;
        mbedtls_status =
                mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term1, fail_proof->term1, sizeof(fail_proof->term1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term1) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status =
                mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term2, fail_proof->term2, sizeof(fail_proof->term2));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term2) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status =
                mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term3, fail_proof->term3, sizeof(fail_proof->term3));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term3) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status =
                mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term4, fail_proof->term4, sizeof(fail_proof->term4));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &term4) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_mpi blind_A, blind_B;
        mbedtls_mpi_init(&blind_A);
        mbedtls_mpi_init(&blind_B);

        mbedtls_status = mbedtls_mpi_read_binary(&blind_A, fail_proof->blind_a, sizeof(fail_proof->blind_a));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &blind_A);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_status = mbedtls_mpi_read_binary(&blind_B, fail_proof->blind_b, sizeof(fail_proof->blind_b));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &blind_B);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_mpi challenge;
        mbedtls_mpi_init(&challenge);

        vsce_phe_hash_hash_z_failure(phe_client_ctx->phe_hash,
                vsc_data(phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key)), c0, c1, &term1,
                &term2, &term3, &term4, &challenge);

        mbedtls_ecp_point t1, t2;
        mbedtls_ecp_point_init(&t1);
        mbedtls_ecp_point_init(&t2);

        // if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
        // return False

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &term1, &phe_client_ctx->one, &term2);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &t1, &challenge, c1);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t2, &blind_A, c0, &blind_B, hs0);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_INVALID_FAIL_PROOF;
            goto err;
        }

        // if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
        // return False

        mbedtls_status = mbedtls_ecp_muladd(op_group, &t1, &phe_client_ctx->one, &term3, &phe_client_ctx->one, &term4);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_muladd(
                &phe_client_ctx->group, &t2, &blind_A, &phe_client_ctx->x, &blind_B, &phe_client_ctx->group.G);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
            status = vsce_INVALID_FAIL_PROOF;
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
VSCE_PUBLIC vsce_error_t
vsce_phe_client_rotate_keys(vsce_phe_client_t *phe_client_ctx, vsc_data_t update_token,
        vsc_buffer_t *new_client_private_key, vsc_buffer_t *new_server_public_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(phe_client_ctx->keys_are_set);
        VSCE_ASSERT(vsc_buffer_len(new_client_private_key) == 0);
        VSCE_ASSERT(vsc_buffer_left(new_client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
        vsc_buffer_make_secure(new_client_private_key);
        VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
        VSCE_ASSERT(vsc_buffer_left(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

        mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(phe_client_ctx);

        vsce_error_t status = vsce_SUCCESS;

        if (update_token.len > UpdateToken_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        UpdateToken token = UpdateToken_init_zero;

        pb_istream_t stream = pb_istream_from_buffer(update_token.bytes, update_token.len);

        bool pb_status = pb_decode(&stream, UpdateToken_fields, &token);

        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        mbedtls_mpi a, b;
        mbedtls_mpi_init(&a);
        mbedtls_mpi_init(&b);

        int mbedtls_status = 0;
        mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &a);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &b);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_mpi new_y;
        mbedtls_mpi_init(&new_y);

        mbedtls_status = mbedtls_mpi_mul_mpi(&new_y, &phe_client_ctx->y, &a);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_mod_mpi(&new_y, &new_y, &phe_client_ctx->group.N);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_mpi_write_binary(
                &new_y, vsc_buffer_ptr(new_client_private_key), vsc_buffer_capacity(new_client_private_key));
        vsc_buffer_reserve(new_client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_ecp_point new_X;
        mbedtls_ecp_point_init(&new_X);

        mbedtls_status = mbedtls_ecp_muladd(op_group, &new_X, &a, &phe_client_ctx->x, &b, &phe_client_ctx->group.G);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &new_X, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                vsc_buffer_ptr(new_server_public_key), vsc_buffer_capacity(new_server_public_key));
        vsc_buffer_reserve(new_server_public_key, olen);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_mpi_free(&new_y);

        mbedtls_ecp_point_free(&new_X);

    priv_err:
        mbedtls_mpi_free(&a);
        mbedtls_mpi_free(&b);

    pb_err:
        vsce_phe_client_free_op_group(op_group);

        return status;
}

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_update_enrollment_record(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_record,
        vsc_data_t update_token, vsc_buffer_t *new_enrollment_record) {

    VSCE_ASSERT_PTR(phe_client_ctx);
        VSCE_ASSERT(vsc_buffer_len(new_enrollment_record) == 0);
        VSCE_ASSERT(vsc_buffer_left(new_enrollment_record) >= vsce_phe_client_enrollment_record_len(phe_client_ctx));

        mbedtls_ecp_group *op_group = vsce_phe_client_get_op_group(phe_client_ctx);

        vsce_error_t status = vsce_SUCCESS;

        if (enrollment_record.len > EnrollmentRecord_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        EnrollmentRecord record = EnrollmentRecord_init_zero;

        pb_istream_t stream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);

        bool pb_status = pb_decode(&stream1, EnrollmentRecord_fields, &record);
        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        if (update_token.len > UpdateToken_size) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        UpdateToken token = UpdateToken_init_zero;

        pb_istream_t stream2 = pb_istream_from_buffer(update_token.bytes, update_token.len);

        pb_status = pb_decode(&stream2, UpdateToken_fields, &token);
        if (!pb_status) {
            status = vsce_PROTOBUF_DECODE_ERROR;
            goto pb_err;
        }

        int mbedtls_status = 0;

        mbedtls_mpi a, b;
        mbedtls_mpi_init(&a);
        mbedtls_mpi_init(&b);

        mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &a);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        mbedtls_status = mbedtls_ecp_check_privkey(&phe_client_ctx->group, &b);
        if (mbedtls_status != 0) {
            status = vsce_INVALID_PRIVATE_KEY;
            goto priv_err;
        }

        mbedtls_ecp_point t0, t1;
        mbedtls_ecp_point_init(&t0);
        mbedtls_ecp_point_init(&t1);

        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t0, sizeof(record.t0));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &t0) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t1, record.t1, sizeof(record.t1));
        if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&phe_client_ctx->group, &t1) != 0) {
            status = vsce_INVALID_ECP;
            goto ecp_err;
        }

        mbedtls_ecp_point hs0, hs1;
        mbedtls_ecp_point_init(&hs0);
        mbedtls_ecp_point_init(&hs1);

        vsce_phe_hash_hs0(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);
        vsce_phe_hash_hs1(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs1);

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
                &phe_client_ctx->group, &new_t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, new_record.t0, sizeof(new_record.t0));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_client_ctx->group, &new_t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, new_record.t1, sizeof(new_record.t1));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        pb_ostream_t ostream =
                pb_ostream_from_buffer(vsc_buffer_ptr(new_enrollment_record), vsc_buffer_capacity(new_enrollment_record));

        VSCE_ASSERT(pb_encode(&ostream, EnrollmentRecord_fields, &new_record));
        vsc_buffer_reserve(new_enrollment_record, ostream.bytes_written);

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
        vsce_phe_client_free_op_group(op_group);

        return status;
}

static mbedtls_ecp_group *
vsce_phe_client_get_op_group(vsce_phe_client_t *phe_client_ctx) {

    #if VSCE_MULTI_THREAD
        VSCE_UNUSED(phe_client_ctx);

        mbedtls_ecp_group *new_group = (mbedtls_ecp_group *)vsce_alloc(sizeof(mbedtls_ecp_group));
        mbedtls_ecp_group_init(new_group);

        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_ecp_group_load(new_group, MBEDTLS_ECP_DP_SECP256R1));

        return new_group;
    #else
        return &phe_client_ctx->group;
    #endif
}

static void
vsce_phe_client_free_op_group(mbedtls_ecp_group *op_group) {

    #if VSCE_MULTI_THREAD
        mbedtls_ecp_group_free(op_group);
        vsce_dealloc(op_group);
    #endif
}
