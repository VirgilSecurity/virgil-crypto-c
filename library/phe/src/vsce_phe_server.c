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

#include "vsce_phe_server.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_server_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
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
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *phe_server_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *phe_server_ctx);

static vsce_error_t
vsce_phe_server_prove_success(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *hs0, const mbedtls_ecp_point *hs1,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, ProofOfSuccess *success_proof);

static vsce_error_t
vsce_phe_server_prove_failure(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *hs0, mbedtls_ecp_point *c1,
        ProofOfFail *failure_proof);

//
//  Return size of 'vsce_phe_server_t'.
//
VSCE_PUBLIC size_t
vsce_phe_server_ctx_size(void) {

    return sizeof(vsce_phe_server_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_server_init(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    vsce_zeroize(phe_server_ctx, sizeof(vsce_phe_server_t));

    phe_server_ctx->refcnt = 1;

    vsce_phe_server_init_ctx(phe_server_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_server_cleanup(vsce_phe_server_t *phe_server_ctx) {

    if (phe_server_ctx == NULL) {
        return;
    }

    if (phe_server_ctx->refcnt == 0) {
        return;
    }

    if (--phe_server_ctx->refcnt == 0) {
        vsce_phe_server_cleanup_ctx(phe_server_ctx);

        vsce_phe_server_release_random(phe_server_ctx);

        vsce_zeroize(phe_server_ctx, sizeof(vsce_phe_server_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_new(void) {

    vsce_phe_server_t *phe_server_ctx = (vsce_phe_server_t *) vsce_alloc(sizeof (vsce_phe_server_t));
    VSCE_ASSERT_ALLOC(phe_server_ctx);

    vsce_phe_server_init(phe_server_ctx);

    phe_server_ctx->self_dealloc_cb = vsce_dealloc;

    return phe_server_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_server_delete(vsce_phe_server_t *phe_server_ctx) {

    if (phe_server_ctx == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_server_ctx->self_dealloc_cb;

    vsce_phe_server_cleanup(phe_server_ctx);

    if (phe_server_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_server_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_server_new ()'.
//
VSCE_PUBLIC void
vsce_phe_server_destroy(vsce_phe_server_t **phe_server_ctx_ref) {

    VSCE_ASSERT_PTR(phe_server_ctx_ref);

    vsce_phe_server_t *phe_server_ctx = *phe_server_ctx_ref;
    *phe_server_ctx_ref = NULL;

    vsce_phe_server_delete(phe_server_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_copy(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    ++phe_server_ctx->refcnt;

    return phe_server_ctx;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_server_use_random(vsce_phe_server_t *phe_server_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_server_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_server_ctx->random = vscf_impl_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_server_take_random(vsce_phe_server_t *phe_server_ctx, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT_PTR(phe_server_ctx->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    phe_server_ctx->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_server_release_random(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    vscf_impl_destroy(&phe_server_ctx->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    phe_server_ctx->phe_hash = vsce_phe_hash_new();

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    vsce_phe_server_take_random(phe_server_ctx, vscf_ctr_drbg_impl(rng));

    phe_server_ctx->utils = vsce_phe_utils_new();
    vsce_phe_utils_use_random(phe_server_ctx->utils, phe_server_ctx->random);

    mbedtls_ecp_group_init(&phe_server_ctx->group);
    int status = mbedtls_ecp_group_load(&phe_server_ctx->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT(status == 0);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *phe_server_ctx) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    vsce_phe_hash_destroy(&phe_server_ctx->phe_hash);
    vsce_phe_utils_destroy(&phe_server_ctx->utils);
    mbedtls_ecp_group_free(&phe_server_ctx->group);
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_generate_server_key_pair(vsce_phe_server_t *phe_server_ctx, vsc_buffer_t *server_private_key,
        vsc_buffer_t *server_public_key) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT(vsc_buffer_len(server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_left(server_private_key) == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(server_private_key);
    VSCE_ASSERT(vsc_buffer_len(server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_left(server_public_key) == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &priv);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_write_binary(
            &priv, vsc_buffer_ptr(server_private_key), vsc_buffer_capacity(server_private_key));
    vsc_buffer_reserve(server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point pub;
    mbedtls_ecp_point_init(&pub);

    mbedtls_status =
            mbedtls_ecp_mul(&phe_server_ctx->group, &pub, &priv, &phe_server_ctx->group.G, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(server_public_key), vsc_buffer_capacity(server_public_key));
    vsc_buffer_reserve(server_public_key, olen);
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&priv);

    return vsce_SUCCESS;
}

VSCE_PUBLIC size_t
vsce_phe_server_enrollment_response_len(vsce_phe_server_t *phe_server_ctx) {

    VSCE_UNUSED(phe_server_ctx);
    size_t size = 0;
    // TODO: Optimize
    EnrollmentResponse response = EnrollmentResponse_init_zero;
    bool pb_status = true;
    pb_status = pb_get_encoded_size(&size, EnrollmentResponse_fields, &response);
    VSCE_ASSERT(pb_status);

    return size;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_get_enrollment(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, vsc_buffer_t *enrollment_response) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT(vsc_buffer_len(enrollment_response) == 0);
    VSCE_ASSERT(vsc_buffer_left(enrollment_response) >= 0); // TODO: Check size
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_t *ns = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);
    vscf_random(phe_server_ctx->random, vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH, ns);

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hs0(phe_server_ctx->phe_hash, vsc_buffer_data(ns), &hs0);
    VSCE_ASSERT(status == vsce_SUCCESS);
    status = vsce_phe_hash_hs1(phe_server_ctx->phe_hash, vsc_buffer_data(ns), &hs1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &c0, &x, &hs0, NULL /* FIXME */, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &c1, &x, &hs1, NULL /* FIXME */, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    EnrollmentResponse response = EnrollmentResponse_init_zero;

    memcpy(response.ns, vsc_buffer_bytes(ns), vsc_buffer_len(ns));

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &phe_server_ctx->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_0, sizeof(response.c_0));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1, sizeof(response.c_1));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    status = vsce_phe_server_prove_success(
            phe_server_ctx, server_private_key, server_public_key, &hs0, &hs1, &c0, &c1, &response.proof);
    VSCE_ASSERT(status == vsce_SUCCESS);

    pb_ostream_t ostream =
            pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_response), vsc_buffer_capacity(enrollment_response));

    bool pb_status = true;
    pb_status = pb_encode(&ostream, EnrollmentResponse_fields, &response);
    VSCE_ASSERT(pb_status);
    vsc_buffer_reserve(enrollment_response, ostream.bytes_written);

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);
    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

    mbedtls_mpi_free(&x);

    vsc_buffer_destroy(&ns);

    return vsce_SUCCESS;
}

VSCE_PUBLIC size_t
vsce_phe_server_verify_password_response_len(vsce_phe_server_t *phe_server_ctx) {

    VSCE_UNUSED(phe_server_ctx);
    size_t size1 = 0, size2 = 0;
    // TODO: Optimize
    VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
    response.which_proof = VerifyPasswordResponse_success_tag;
    bool pb_status = true;
    pb_status = pb_get_encoded_size(&size1, VerifyPasswordResponse_fields, &response);
    VSCE_ASSERT(pb_status);

    response.which_proof = VerifyPasswordResponse_fail_tag;
    pb_status = pb_get_encoded_size(&size2, VerifyPasswordResponse_fields, &response);
    VSCE_ASSERT(pb_status);

    return size1 > size2 ? size1 : size2;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_verify_password(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, vsc_data_t verify_password_request, vsc_buffer_t *verify_password_response) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT(vsc_buffer_len(verify_password_response) == 0);
    VSCE_ASSERT(vsc_buffer_left(verify_password_response) >= 0); // TODO: Check size
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    VerifyPasswordRequest request = VerifyPasswordRequest_init_zero;

    pb_istream_t istream = pb_istream_from_buffer(verify_password_request.bytes, verify_password_request.len);
    bool pb_status = true;
    pb_status = pb_decode(&istream, VerifyPasswordRequest_fields, &request);
    VSCE_ASSERT(pb_status);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_point_read_binary(&phe_server_ctx->group, &c0, request.c_0, sizeof(request.c_0));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hs0(phe_server_ctx->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs0);
    VSCE_ASSERT(status == vsce_SUCCESS);
    status = vsce_phe_hash_hs1(phe_server_ctx->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_ecp_point hs0x;
    mbedtls_ecp_point_init(&hs0x);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &hs0x, &x, &hs0, NULL /*FIXME*/, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    if (mbedtls_ecp_point_cmp(&c0, &hs0x) == 0) {
        // Password matches

        mbedtls_ecp_point c1;
        mbedtls_ecp_point_init(&c1);

        mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &c1, &x, &hs1, NULL /*FIXME*/, NULL);
        VSCE_ASSERT(mbedtls_status == 0);

        VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
        response.res = true;

        response.which_proof = VerifyPasswordResponse_success_tag;
        status = vsce_phe_server_prove_success(
                phe_server_ctx, server_private_key, server_public_key, &hs0, &hs1, &c0, &c1, &response.proof.success);
        VSCE_ASSERT(status == vsce_SUCCESS);

        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1, sizeof(response.c_1));
        VSCE_ASSERT(mbedtls_status == 0);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(
                vsc_buffer_ptr(verify_password_response), vsc_buffer_capacity(verify_password_response));
        bool pb_status = true;
        pb_status = pb_encode(&ostream, VerifyPasswordResponse_fields, &response);
        VSCE_ASSERT(pb_status);
        vsc_buffer_reserve(verify_password_response, ostream.bytes_written);

        mbedtls_ecp_point_free(&c1);
    } else {
        mbedtls_ecp_point c1;
        mbedtls_ecp_point_init(&c1);

        VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
        response.res = false;

        response.which_proof = VerifyPasswordResponse_fail_tag;
        status = vsce_phe_server_prove_failure(
                phe_server_ctx, server_private_key, server_public_key, &c0, &hs0, &c1, &response.proof.fail);
        VSCE_ASSERT(status == vsce_SUCCESS);


        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1, sizeof(response.c_1));
        VSCE_ASSERT(mbedtls_status == 0);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(
                vsc_buffer_ptr(verify_password_response), vsc_buffer_capacity(verify_password_response));
        bool pb_status = true;
        pb_status = pb_encode(&ostream, VerifyPasswordResponse_fields, &response);
        VSCE_ASSERT(pb_status);
        vsc_buffer_reserve(verify_password_response, ostream.bytes_written);

        mbedtls_ecp_point_free(&c1);
    }

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);
    mbedtls_ecp_point_free(&hs0x);

    mbedtls_mpi_free(&x);

    return vsce_SUCCESS;
}

static vsce_error_t
vsce_phe_server_prove_success(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *hs0, const mbedtls_ecp_point *hs1,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, ProofOfSuccess *success_proof) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(hs1);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(success_proof);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &blind_x);

    mbedtls_ecp_point term1, term2, term3;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);

    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &term1, &blind_x, hs0, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &term2, &blind_x, hs1, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status =
            mbedtls_ecp_mul(&phe_server_ctx->group, &term3, &blind_x, &phe_server_ctx->group.G, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hash_z_success(
            phe_server_ctx->phe_hash, server_public_key, c0, c1, &term1, &term2, &term3, &challenge);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge, &challenge, &x);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_add_mpi(&blind_x, &blind_x, &challenge);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_x, &blind_x, &phe_server_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term_1, sizeof(success_proof->term_1));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(success_proof->term_1));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term2, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term_2, sizeof(success_proof->term_2));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(success_proof->term_2));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term3, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term_3, sizeof(success_proof->term_3));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(success_proof->term_3));

    mbedtls_status = mbedtls_mpi_write_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi_free(&x);

    mbedtls_mpi_free(&challenge);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);

    mbedtls_mpi_free(&blind_x);

    return vsce_SUCCESS;
}

static vsce_error_t
vsce_phe_server_prove_failure(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *hs0, mbedtls_ecp_point *c1,
        ProofOfFail *failure_proof) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    VSCE_ASSERT_PTR(failure_proof);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &r);

    mbedtls_mpi minus_r;
    mbedtls_mpi_init(&minus_r);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_sub_mpi(&minus_r, &phe_server_ctx->group.N, &r);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi minus_RX;
    mbedtls_mpi_init(&minus_RX);

    mbedtls_status = mbedtls_mpi_mul_mpi(&minus_RX, &x, &minus_r);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_mod_mpi(&minus_RX, &minus_RX, &phe_server_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_muladd(&phe_server_ctx->group, c1, &r, c0, &minus_RX, hs0);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi blind_A, blind_B;
    mbedtls_mpi_init(&blind_A);
    mbedtls_mpi_init(&blind_B);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &blind_A);
    vsce_phe_utils_random_z(phe_server_ctx->utils, &blind_B);

    mbedtls_ecp_point X;
    mbedtls_ecp_point_init(&X);
    mbedtls_status =
            mbedtls_ecp_point_read_binary(&phe_server_ctx->group, &X, server_public_key.bytes, server_public_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point term1, term2, term3, term4;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);
    mbedtls_ecp_point_init(&term4);

    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &term1, &blind_A, c0, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &term2, &blind_B, hs0, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &term3, &blind_A, &X, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status =
            mbedtls_ecp_mul(&phe_server_ctx->group, &term4, &blind_B, &phe_server_ctx->group.G, /* FIXME */ NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi challenge_A, challenge_B;
    mbedtls_mpi_init(&challenge_A);
    mbedtls_mpi_init(&challenge_B);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_hash_z_failure(
            phe_server_ctx->phe_hash, server_public_key, c0, c1, &term1, &term2, &term3, &term4, &challenge_A);
    VSCE_ASSERT(status == vsce_SUCCESS);
    mbedtls_mpi_copy(&challenge_B, &challenge_A);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge_A, &challenge_A, &r);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_add_mpi(&blind_A, &blind_A, &challenge_A);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_A, &blind_A, &phe_server_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge_B, &challenge_B, &minus_RX);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_add_mpi(&blind_B, &blind_B, &challenge_B);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_B, &blind_B, &phe_server_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term_1, sizeof(failure_proof->term_1));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(failure_proof->term_1));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term2, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term_2, sizeof(failure_proof->term_2));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(failure_proof->term_2));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term3, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term_3, sizeof(failure_proof->term_3));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(failure_proof->term_3));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &term4, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term_4, sizeof(failure_proof->term_4));
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == sizeof(failure_proof->term_4));

    mbedtls_status = mbedtls_mpi_write_binary(&blind_A, failure_proof->blind_a, sizeof(failure_proof->blind_a));
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_write_binary(&blind_B, failure_proof->blind_b, sizeof(failure_proof->blind_b));
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi_free(&challenge_A);
    mbedtls_mpi_free(&challenge_B);

    mbedtls_mpi_free(&blind_A);
    mbedtls_mpi_free(&blind_B);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&minus_r);
    mbedtls_mpi_free(&minus_RX);
    mbedtls_mpi_free(&x);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);
    mbedtls_ecp_point_free(&term4);

    mbedtls_ecp_point_free(&X);

    return vsce_SUCCESS;
}

VSCE_PUBLIC size_t
vsce_phe_server_update_token_len(vsce_phe_server_t *phe_server_ctx) {

    VSCE_UNUSED(phe_server_ctx);
    size_t size = 0;
    // TODO: Optimize
    UpdateToken token = UpdateToken_init_zero;
    bool pb_status = true;
    pb_status = pb_get_encoded_size(&size, UpdateToken_fields, &token);
    VSCE_ASSERT(pb_status);

    return size;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_rotate_keys(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_buffer_t *new_server_private_key, vsc_buffer_t *new_server_public_key, vsc_buffer_t *update_token) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(update_token) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(update_token) >= vsce_phe_server_update_token_len(phe_server_ctx));
    VSCE_ASSERT(vsc_buffer_len(new_server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(new_server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_server_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &a);
    vsce_phe_utils_random_z(phe_server_ctx->utils, &b);

    UpdateToken token = UpdateToken_init_zero;

    mbedtls_status = mbedtls_mpi_write_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_write_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT(mbedtls_status == 0);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(update_token), vsc_buffer_capacity(update_token));
    bool pb_status = pb_encode(&ostream, UpdateToken_fields, &token);
    vsc_buffer_reserve(update_token, ostream.bytes_written);
    VSCE_ASSERT(pb_status);

    mbedtls_mpi new_x;
    mbedtls_mpi_init(&new_x);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_x, &x, &a);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_add_mpi(&new_x, &new_x, &b);
    VSCE_ASSERT(mbedtls_status == 0);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_x, &new_x, &phe_server_ctx->group.N);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_status = mbedtls_mpi_write_binary(
            &new_x, vsc_buffer_ptr(new_server_private_key), vsc_buffer_capacity(new_server_private_key));
    vsc_buffer_reserve(new_server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);

    mbedtls_ecp_point new_X;
    mbedtls_ecp_point_init(&new_X);

    mbedtls_status = mbedtls_ecp_mul(&phe_server_ctx->group, &new_X, &new_x, &phe_server_ctx->group.G, NULL, NULL);
    VSCE_ASSERT(mbedtls_status == 0);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &new_X, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(new_server_public_key), vsc_buffer_capacity(new_server_public_key));
    vsc_buffer_reserve(new_server_public_key, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT(mbedtls_status == 0);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&new_X);

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&new_x);

    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

    return vsce_SUCCESS;
}
