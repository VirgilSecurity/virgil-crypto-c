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
    mbedtls_ecp_group_load(&phe_server_ctx->group, MBEDTLS_ECP_DP_SECP256R1);
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
    VSCE_ASSERT(vsc_buffer_len(server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_left(server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_buffer_left(server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);

    vsce_phe_utils_random_z(phe_server_ctx->utils, &priv);

    mbedtls_mpi_write_binary(&priv, vsc_buffer_ptr(server_private_key), vsc_buffer_capacity(server_private_key));
    vsc_buffer_reserve(server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    mbedtls_ecp_point pub;
    mbedtls_ecp_point_init(&pub);

    mbedtls_ecp_mul(&phe_server_ctx->group, &pub, &priv, &phe_server_ctx->group.G, /* FIXME */ NULL, NULL);

    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(server_public_key), vsc_buffer_capacity(server_public_key));
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&priv);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_get_enrollment(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_buffer_t *enrollment_response) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    vsc_buffer_t *ns = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH);
    vscf_random(phe_server_ctx->random, vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH, ns);


    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(phe_server_ctx->phe_hash, vsc_buffer_data(ns), &hs0);
    vsce_phe_hash_hs1(phe_server_ctx->phe_hash, vsc_buffer_data(ns), &hs1);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    mbedtls_ecp_mul(&phe_server_ctx->group, &c0, &x, &hs0, NULL /* FIXME */, NULL);
    mbedtls_ecp_mul(&phe_server_ctx->group, &c1, &x, &hs1, NULL /* FIXME */, NULL);

    EnrollmentResponse response;

    memcpy(response.ns, vsc_buffer_bytes(ns), vsc_buffer_len(ns));

    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_0,
                                   sizeof(response.c_0));
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    olen = 0;
    mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1,
                                   sizeof(response.c_1));
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    // TODO: response.proof =

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_response), vsc_buffer_capacity(enrollment_response));

    pb_encode(&ostream, EnrollmentResponse_fields, &response);
    vsc_buffer_reserve(enrollment_response, ostream.bytes_written);

    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);
    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

    mbedtls_mpi_free(&x);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_verify_password(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, vsc_data_t verify_password_request, vsc_buffer_t *verify_password_response) {

    VSCE_ASSERT_PTR(phe_server_ctx);
    VSCE_ASSERT_PTR(verify_password_response);
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    VerifyPasswordRequest request;

    pb_istream_t istream = pb_istream_from_buffer(verify_password_request.bytes, verify_password_request.len);
    pb_decode(&istream, VerifyPasswordRequest_fields, &request);

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);

    mbedtls_ecp_point_read_binary(&phe_server_ctx->group, &c0, request.c_0, sizeof(request.c_0));

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(phe_server_ctx->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs0);
    vsce_phe_hash_hs1(phe_server_ctx->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs0);

    mbedtls_ecp_point hs0x;
    mbedtls_ecp_point_init(&hs0x);

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);

    mbedtls_ecp_mul(&phe_server_ctx->group, &hs0x, &x, &hs0, NULL /*FIXME*/, NULL);

    if (mbedtls_ecp_point_cmp(&c0, &hs0x) == 0) {
        // Password matches

        mbedtls_ecp_point c1;
        mbedtls_ecp_point_init(&c1);

        mbedtls_ecp_mul(&phe_server_ctx->group, &c1, &x, &hs1, NULL /*FIXME*/, NULL);

        VerifyPasswordResponse response;
        response.res = true;

        vsce_phe_server_prove_success(phe_server_ctx, server_private_key, server_public_key,
                &hs0, &hs1, &c0, &c1, &response.proof_success);

        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1,
                                       sizeof(response.c_1));
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(verify_password_response), vsc_buffer_capacity(verify_password_response));
        pb_encode(&ostream, VerifyPasswordResponse_fields, &response);
        vsc_buffer_reserve(verify_password_response, ostream.bytes_written);

        mbedtls_ecp_point_free(&c1);
    }
    else {
        mbedtls_ecp_point c1;
        mbedtls_ecp_point_init(&c1);

        VerifyPasswordResponse response;
        response.res = false;

        vsce_phe_server_prove_failure(phe_server_ctx, server_private_key, server_public_key,
                &c0, &hs0, &c1, &response.proof_fail);

        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&phe_server_ctx->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c_1,
                                       sizeof(response.c_1));
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(verify_password_response), vsc_buffer_capacity(verify_password_response));
        pb_encode(&ostream, VerifyPasswordResponse_fields, &response);
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

    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(hs1);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    VSCE_ASSERT_PTR(success_proof);
    //  TODO: This is STUB. Implement me.

    VSCE_UNUSED(server_private_key);
    VSCE_UNUSED(server_public_key);

    return vsce_SUCCESS;
}

static vsce_error_t
vsce_phe_server_prove_failure(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *hs0, mbedtls_ecp_point *c1,
        ProofOfFail *failure_proof) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    VSCE_ASSERT_PTR(failure_proof);

    VSCE_UNUSED(server_private_key);
    VSCE_UNUSED(server_public_key);

    //  TODO: This is STUB. Implement me.

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_server_rotate_server_private_key(vsce_phe_server_t *phe_server_ctx, vsc_data_t server_private_key,
        vsc_buffer_t *new_server_private_key, vsc_buffer_t *new_server_public_key, vsc_buffer_t *rotation_token) {

    VSCE_ASSERT_PTR(phe_server_ctx);

    VSCE_ASSERT_PTR(new_server_private_key);
    VSCE_ASSERT_PTR(new_server_public_key);
    VSCE_ASSERT_PTR(rotation_token);

    VSCE_UNUSED(server_private_key);

    //  TODO: This is STUB. Implement me.

    return vsce_SUCCESS;
}
