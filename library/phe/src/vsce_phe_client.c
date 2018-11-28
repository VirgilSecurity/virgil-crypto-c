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
#include "vsce_phe_utils.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <PHEModels.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>

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
vsce_phe_client_check_success_proof(vsce_phe_client_t *phe_client_ctx, const ProofOfSuccess *success_proof,
        vsc_data_t ns, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1);

static vsce_error_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *phe_client_ctx, const ProofOfFail *fail_proof,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, const mbedtls_ecp_point *hs0);

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

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    vsce_phe_client_take_random(phe_client_ctx, vscf_ctr_drbg_impl(rng));

    phe_client_ctx->utils = vsce_phe_utils_new();
    vsce_phe_utils_use_random(phe_client_ctx->utils, phe_client_ctx->random);

    mbedtls_ecp_group_init(&phe_client_ctx->group);
    int status = mbedtls_ecp_group_load(&phe_client_ctx->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT(status == 0);
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
    vsce_phe_utils_destroy(&phe_client_ctx->utils);
    vsce_phe_hash_destroy(&phe_client_ctx->phe_hash);
}

VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_new_with_keys(vsc_data_t client_private_key, vsc_data_t server_public_key) {

    vsce_phe_client_t *phe_client_ctx = vsce_phe_client_new();

    VSCE_ASSERT(client_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    memcpy(phe_client_ctx->client_private_key, client_private_key.bytes, client_private_key.len);

    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    memcpy(phe_client_ctx->server_public_key, server_public_key.bytes, server_public_key.len);

    return phe_client_ctx;
}

VSCE_PUBLIC size_t
vsce_phe_client_enrollment_record_len(vsce_phe_client_t *phe_client_ctx) {

    VSCE_UNUSED(phe_client_ctx);
    size_t size = 0;
    // TODO: Optimize
    EnrollmentRecord record = EnrollmentRecord_init_zero;
    bool pb_status = true;
    pb_status = pb_get_encoded_size(&size, EnrollmentRecord_fields, &record);
    VSCE_ASSERT(pb_status);

    return size;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_enroll_account(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_response, vsc_data_t password,
        vsc_buffer_t *enrollment_record, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT(vsc_buffer_len(enrollment_record) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(enrollment_record) >= 0); // TODO: Check length
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(account_key) == vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_make_secure(account_key);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    EnrollmentResponse response = EnrollmentResponse_init_zero;

    pb_istream_t stream = pb_istream_from_buffer(enrollment_response.bytes, enrollment_response.len);

    bool pb_status = pb_decode(&stream, EnrollmentResponse_fields, &response);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c0, response.c_0, sizeof(response.c_0));
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c1, response.c_1, sizeof(response.c_1));
    VSCE_ASSERT(mbedtls_status == 0);

    vsce_error_t status = vsce_phe_client_check_success_proof(phe_client_ctx, &response.proof,
            vsc_data(response.ns, sizeof(response.ns)), &c0, &c1);

    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_t *nc = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    status = vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH, nc);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_ecp_point hc0, hc1;
    mbedtls_ecp_point_init(&hc0);
    mbedtls_ecp_point_init(&hc1);

    status = vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_buffer_data(nc), password, &hc0);
    VSCE_ASSERT(status == vsce_SUCCESS);
    status = vsce_phe_hash_hc1(phe_client_ctx->phe_hash, vsc_buffer_data(nc), password, &hc1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_t *rnd_m = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    vsc_buffer_make_secure(rnd_m);
    status = vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, rnd_m);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);

    status = vsce_phe_hash_data_to_point(phe_client_ctx->phe_hash, vsc_buffer_data(rnd_m), &M);
    VSCE_ASSERT(status == vsce_SUCCESS);
    vsc_buffer_destroy(&rnd_m);

    vsc_buffer_t *M_buf = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_POINT_LENGTH);
    vsc_buffer_make_secure(M_buf);
    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &M, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(M_buf), vsce_phe_common_PHE_POINT_LENGTH);
    vsc_buffer_reserve(M_buf, vsce_phe_common_PHE_POINT_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    // FIXME: Duplicate
    char hkdf_info[] = "Secret";

    vscf_hkdf_derive(hkdf, vsc_buffer_data(M_buf), vsc_data_empty(),
            vsc_data((byte *)hkdf_info, sizeof(hkdf_info)), account_key, vsc_buffer_capacity(account_key));
    vsc_buffer_destroy(&M_buf);
    vscf_hkdf_destroy(&hkdf);

    mbedtls_ecp_point t0, t1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);

    mbedtls_mpi y;
    mbedtls_mpi_init(&y);
    mbedtls_status = mbedtls_mpi_read_binary(&y, phe_client_ctx->client_private_key, sizeof(phe_client_ctx->client_private_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t0, &one, &c0, &y, &hc0);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &c1, &y, &hc1);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &t1, &y, &M);
    VSCE_ASSERT(mbedtls_status == 0);

    EnrollmentRecord record = EnrollmentRecord_init_zero;
    memcpy(record.ns, response.ns, sizeof(response.ns));
    memcpy(record.nc, vsc_buffer_bytes(nc), vsc_buffer_len(nc));
    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t_0, sizeof(record.t_0));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t_1, sizeof(record.t_1));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_record), vsc_buffer_capacity(enrollment_record));
    pb_status = pb_encode(&ostream, EnrollmentRecord_fields, &record);
    VSCE_ASSERT(pb_status);
    vsc_buffer_reserve(enrollment_record, ostream.bytes_written);

    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);

    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&hc1);
    mbedtls_ecp_point_free(&M);

    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&y);

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

    vsc_buffer_destroy(&nc);

    return vsce_SUCCESS;
}

VSCE_PUBLIC size_t
vsce_phe_client_verify_password_request_len(vsce_phe_client_t *phe_client_ctx) {

    VSCE_UNUSED(phe_client_ctx);
    size_t size = 0;
    // TODO: Optimize
    VerifyPasswordRequest record = VerifyPasswordRequest_init_zero;
    bool pb_status = true;
    pb_status = pb_get_encoded_size(&size, VerifyPasswordRequest_fields, &record);
    VSCE_ASSERT(pb_status);

    return size;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_create_verify_password_request(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_buffer_t *verify_password_request) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT(vsc_buffer_len(verify_password_request) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(verify_password_request) >= 0); // TODO: Check length
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    EnrollmentRecord record = EnrollmentRecord_init_zero;

    pb_istream_t istream = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
    bool pb_status = pb_decode(&istream, EnrollmentRecord_fields, &record);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point hc0;
    mbedtls_ecp_point_init(&hc0);

    vsce_error_t status = vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_mpi y;
    mbedtls_mpi_init(&y);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&y, phe_client_ctx->client_private_key, sizeof(phe_client_ctx->client_private_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi minus_y;
    mbedtls_mpi_init(&minus_y);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_status = mbedtls_mpi_lset(&one, 1);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_sub_mpi(&minus_y, &phe_client_ctx->group.N, &y);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point t0;
    mbedtls_ecp_point_init(&t0);
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t_0, sizeof(record.t_0));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &c0, &one, &t0, &minus_y, &hc0);
    VSCE_ASSERT(mbedtls_status == 0);

    VerifyPasswordRequest request = VerifyPasswordRequest_init_zero;
    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, request.c_0, sizeof(request.c_0));
    VSCE_ASSERT(mbedtls_status == 0);
    memcpy(request.ns, record.ns, sizeof(record.ns));

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(verify_password_request), vsc_buffer_capacity(verify_password_request));
    pb_status = pb_encode(&ostream, VerifyPasswordRequest_fields, &request);
    VSCE_ASSERT(pb_status);
    vsc_buffer_reserve(verify_password_request, ostream.bytes_written);

    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&minus_y);
    mbedtls_mpi_free(&y);

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&t0);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_check_response_and_decrypt(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_data_t verify_password_response, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(account_key) == vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_make_secure(account_key);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    EnrollmentRecord record = EnrollmentRecord_init_zero;

    pb_istream_t istream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);
    bool pb_status = pb_decode(&istream1, EnrollmentRecord_fields, &record);
    VSCE_ASSERT(pb_status);

    VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;

    pb_istream_t istream2 = pb_istream_from_buffer(verify_password_response.bytes, verify_password_response.len);
    pb_status = pb_decode(&istream2, VerifyPasswordResponse_fields, &response);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point t0, t1, c1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&c1);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t_0, sizeof(record.t_0));
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t1, record.t_1, sizeof(record.t_1));
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &c1, response.c_1, sizeof(response.c_1));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point hc0, hc1;
    mbedtls_ecp_point_init(&hc0);
    mbedtls_ecp_point_init(&hc1);

    vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc0);
    vsce_phe_hash_hc1(phe_client_ctx->phe_hash, vsc_data(record.nc, sizeof(record.nc)), password, &hc1);

    mbedtls_mpi y;
    mbedtls_mpi_init(&y);
    mbedtls_status = mbedtls_mpi_read_binary(&y, phe_client_ctx->client_private_key, sizeof(phe_client_ctx->client_private_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi minus_y;
    mbedtls_mpi_init(&minus_y);
    mbedtls_status = mbedtls_mpi_sub_mpi(&minus_y, &phe_client_ctx->group.N, &y);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_status = mbedtls_mpi_lset(&one, 1);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);
    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &c0, &one, &t0, &minus_y, &hc0);
    VSCE_ASSERT(mbedtls_status == 0);

    if (response.res) {
        vsce_error_t status = vsce_SUCCESS;
        VSCE_ASSERT(response.which_proof == VerifyPasswordResponse_success_tag);
        status = vsce_phe_client_check_success_proof(phe_client_ctx, &response.proof.success,
                vsc_data(record.ns, sizeof(record.ns)), &c0, &c1);
        VSCE_ASSERT(status == vsce_SUCCESS);

        mbedtls_ecp_point M;
        mbedtls_ecp_point_init(&M);

        mbedtls_mpi minus_one;
        mbedtls_mpi_init(&minus_one);
        mbedtls_status = mbedtls_mpi_lset(&minus_one, -1);
        VSCE_ASSERT(mbedtls_status == 0);

        mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &M, &minus_one, &c1, &minus_y, &hc1);
        VSCE_ASSERT(mbedtls_status == 0);
        mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &M, &one, &t1, &one, &M);
        VSCE_ASSERT(mbedtls_status == 0);

        vsc_buffer_t *M_buf = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_POINT_LENGTH);
        vsc_buffer_make_secure(M_buf);

        vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();

        vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

        // FIXME: Why so easy word?
        char hkdf_info[] = "Secret";

        vscf_hkdf_derive(hkdf, vsc_buffer_data(M_buf), vsc_data_empty(),
                         vsc_data((byte *)hkdf_info, sizeof(hkdf_info)), account_key, vsc_buffer_capacity(account_key));
        vsc_buffer_destroy(&M_buf);
        vscf_hkdf_destroy(&hkdf);

        mbedtls_ecp_point_free(&M);
        mbedtls_mpi_free(&minus_one);
    }
    else {
        mbedtls_ecp_point hs0;
        mbedtls_ecp_point_init(&hs0);

        vsce_phe_hash_hs0(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);

        VSCE_ASSERT(response.which_proof == VerifyPasswordResponse_fail_tag);
        vsce_error_t status = vsce_SUCCESS;
        status = vsce_phe_client_check_fail_proof(phe_client_ctx, &response.proof.fail, &c0, &c1, &hs0);
        VSCE_ASSERT(status == vsce_SUCCESS);

        mbedtls_ecp_point_free(&hs0);
    }

    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&c1);

    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&hc1);

    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&minus_y);
    mbedtls_ecp_point_free(&c0);

    mbedtls_mpi_free(&one);

    return vsce_SUCCESS;
}

static vsce_error_t
vsce_phe_client_check_success_proof(vsce_phe_client_t *phe_client_ctx, const ProofOfSuccess *success_proof,
        vsc_data_t ns, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(success_proof);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);

    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    mbedtls_ecp_point term1, term2, term3;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term1, success_proof->term_1, sizeof(success_proof->term_1));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term2, success_proof->term_2, sizeof(success_proof->term_2));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term3, success_proof->term_3, sizeof(success_proof->term_3));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hs0(phe_client_ctx->phe_hash, ns, &hs0);
    VSCE_ASSERT(status == vsce_SUCCESS);
    status = vsce_phe_hash_hs1(phe_client_ctx->phe_hash, ns, &hs1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    status = vsce_phe_hash_hash_z_success(phe_client_ctx->phe_hash,
            vsc_data(phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key)),
            c0, c1, &term1, &term2, &term3, &challenge);
    VSCE_ASSERT(status == vsce_SUCCESS);

    //if term1 * (c0 ** challenge) != hs0 ** blind_x:
    // return False

    mbedtls_ecp_point t1, t2;
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&t2);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &term1, &challenge, c0);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_mul(&phe_client_ctx->group, &t2, &blind_x, &hs0, NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        // TODO: Free memory
        return vsce_INVALID_PROOF;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    // if term2 * (c1 ** challenge) != hs1 ** blind_x:
    // return False

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &term2, &challenge, c1);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_mul(&phe_client_ctx->group, &t2, &blind_x, &hs1, NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        // TODO: Free memory
        return vsce_INVALID_PROOF;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    //if term3 * (self.X ** challenge) != self.G ** blind_x:
    // return False

    mbedtls_ecp_point pub;
    mbedtls_ecp_point_init(&pub);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &pub, phe_client_ctx->server_public_key,
            sizeof(phe_client_ctx->server_public_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &term3, &challenge, &pub);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_mul(&phe_client_ctx->group, &t2, &blind_x, &phe_client_ctx->group.G, NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        // TODO: Free memory
        return vsce_INVALID_PROOF;
    }

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    mbedtls_ecp_point_free(&pub);

    mbedtls_mpi_free(&blind_x);

    mbedtls_mpi_free(&challenge);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);

    mbedtls_mpi_free(&one);

    return vsce_SUCCESS;
}

static vsce_error_t
vsce_phe_client_check_fail_proof(vsce_phe_client_t *phe_client_ctx, const ProofOfFail *fail_proof,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, const mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(fail_proof);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(hs0);

    mbedtls_ecp_point term1, term2, term3, term4;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);
    mbedtls_ecp_point_init(&term4);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term1, fail_proof->term_1, sizeof(fail_proof->term_1));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term2, fail_proof->term_2, sizeof(fail_proof->term_2));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term3, fail_proof->term_3, sizeof(fail_proof->term_3));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &term4, fail_proof->term_4, sizeof(fail_proof->term_4));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi blind_A, blind_B;
    mbedtls_mpi_init(&blind_A);
    mbedtls_mpi_init(&blind_B);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_A, fail_proof->blind_a, sizeof(fail_proof->blind_a));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_read_binary(&blind_B, fail_proof->blind_b, sizeof(fail_proof->blind_b));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hash_z_failure(phe_client_ctx->phe_hash,
                                          vsc_data(phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key)),
                                          c0, c1, &term1, &term2, &term3, &term4, &challenge);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_ecp_point t1, t2;
    mbedtls_ecp_point_init(&t1);
    mbedtls_ecp_point_init(&t2);

    //if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
    //return False

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &term1, &one, &term2);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &t1, &challenge, c1);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t2, &blind_A, c0, &blind_B, hs0);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        // TODO: Free memory
        return vsce_INVALID_PROOF;
    }

    //if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
    //return False
    mbedtls_ecp_point X;
    mbedtls_ecp_point_init(&X);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &X,
            phe_client_ctx->server_public_key, sizeof(phe_client_ctx->server_public_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t1, &one, &term3, &one, &term4);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &t2, &blind_A, &X, &blind_B, &phe_client_ctx->group.G);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&t1, &t2) != 0) {
        // TODO: Free memory
        return vsce_INVALID_PROOF;
    }

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);
    mbedtls_ecp_point_free(&term4);

    mbedtls_mpi_free(&challenge);

    mbedtls_mpi_free(&blind_A);
    mbedtls_mpi_free(&blind_B);

    mbedtls_mpi_free(&one);

    mbedtls_ecp_point_free(&t1);
    mbedtls_ecp_point_free(&t2);

    mbedtls_ecp_point_free(&X);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_rotate_keys(vsce_phe_client_t *phe_client_ctx, vsc_data_t update_token,
        vsc_buffer_t *new_client_private_key, vsc_buffer_t *new_server_public_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT(vsc_buffer_len(new_client_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(new_client_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_client_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    UpdateToken token = UpdateToken_init_zero;

    pb_istream_t stream = pb_istream_from_buffer(update_token.bytes, update_token.len);

    bool pb_status = pb_decode(&stream, UpdateToken_fields, &token);
    VSCE_ASSERT(pb_status);

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi y, new_y;
    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&new_y);
    mbedtls_status = mbedtls_mpi_read_binary(&y, phe_client_ctx->client_private_key, sizeof(phe_client_ctx->client_private_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_y, &y, &a);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_y, &new_y, &phe_client_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_write_binary(&new_y, vsc_buffer_ptr(new_client_private_key), vsc_buffer_capacity(new_client_private_key));
    vsc_buffer_reserve(new_client_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point X, new_X;
    mbedtls_ecp_point_init(&X);
    mbedtls_ecp_point_init(&new_X);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &X, phe_client_ctx->server_public_key,
            sizeof(phe_client_ctx->server_public_key));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &new_X, &a, &X, &b, &phe_client_ctx->group.G);
    VSCE_ASSERT(mbedtls_status == 0);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &new_X, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(new_server_public_key), vsc_buffer_capacity(new_server_public_key));
    vsc_buffer_reserve(new_server_public_key, olen);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&new_y);

    mbedtls_ecp_point_free(&X);
    mbedtls_ecp_point_free(&new_X);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_update_enrollment_record(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_record,
        vsc_data_t update_token, vsc_buffer_t *new_enrollment_record) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT(vsc_buffer_len(new_enrollment_record) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(new_enrollment_record) >= 0); // TODO: Check length

    EnrollmentRecord record = EnrollmentRecord_init_zero;

    pb_istream_t stream1 = pb_istream_from_buffer(enrollment_record.bytes, enrollment_record.len);

    bool pb_status = pb_decode(&stream1, EnrollmentRecord_fields, &record);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point t0, t1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t0, record.t_0, sizeof(record.t_0));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_client_ctx->group, &t1, record.t_1, sizeof(record.t_1));
    VSCE_ASSERT(mbedtls_status == 0);

    UpdateToken token = UpdateToken_init_zero;

    pb_istream_t stream2 = pb_istream_from_buffer(update_token.bytes, update_token.len);

    pb_status = pb_decode(&stream2, UpdateToken_fields, &token);
    VSCE_ASSERT(pb_status);

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    mbedtls_status = mbedtls_mpi_read_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_read_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs0);
    vsce_phe_hash_hs1(phe_client_ctx->phe_hash, vsc_data(record.ns, sizeof(record.ns)), &hs1);

    mbedtls_ecp_point new_t0, new_t1;
    mbedtls_ecp_point_init(&new_t0);
    mbedtls_ecp_point_init(&new_t1);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &new_t0, &a, &t0, &b, &hs0);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_muladd(&phe_client_ctx->group, &new_t1, &a, &t1, &b, &hs1);
    VSCE_ASSERT(mbedtls_status == 0);

    EnrollmentRecord new_record = EnrollmentRecord_init_zero;

    memcpy(new_record.ns, record.ns, sizeof(new_record.ns));
    memcpy(new_record.nc, record.nc, sizeof(new_record.nc));

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &new_t0, MBEDTLS_ECP_PF_UNCOMPRESSED,
            &olen, new_record.t_0, sizeof(new_record.t_0));
    VSCE_ASSERT(mbedtls_status == 0);

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_client_ctx->group, &new_t1, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    &olen, new_record.t_1, sizeof(new_record.t_1));
    VSCE_ASSERT(mbedtls_status == 0);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(new_enrollment_record), vsc_buffer_capacity(new_enrollment_record));

    pb_status = pb_encode(&ostream, EnrollmentRecord_fields, &new_record);
    vsc_buffer_reserve(new_enrollment_record, ostream.bytes_written);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);

    mbedtls_ecp_point_free(&new_t0);
    mbedtls_ecp_point_free(&new_t1);

    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);

    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

    return vsce_SUCCESS;
}
