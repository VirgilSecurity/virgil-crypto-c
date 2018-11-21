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

        vsce_phe_client_release_phe_hash(phe_client_ctx);
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
//  Setup dependency to the class 'phe hash' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_phe_hash(vsce_phe_client_t *phe_client_ctx, vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(phe_client_ctx->phe_hash == NULL);

    phe_client_ctx->phe_hash = vsce_phe_hash_copy(phe_hash);
}

//
//  Setup dependency to the class 'phe hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_phe_hash(vsce_phe_client_t *phe_client_ctx, vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_client_ctx);
    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(phe_client_ctx->phe_hash == NULL);

    phe_client_ctx->phe_hash = phe_hash;
}

//
//  Release dependency to the class 'phe hash'.
//
VSCE_PUBLIC void
vsce_phe_client_release_phe_hash(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    vsce_phe_hash_destroy(&phe_client_ctx->phe_hash);
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

    vsce_phe_client_take_phe_hash(phe_client_ctx, vsce_phe_hash_new());

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    vsce_phe_client_take_random(phe_client_ctx, vscf_ctr_drbg_impl(rng));
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_client_cleanup_ctx(vsce_phe_client_t *phe_client_ctx) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    //  TODO: Release all inner resources.
}

VSCE_PUBLIC vsce_error_t
vsce_phe_client_enroll_account(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_response, vsc_data_t password,
        vsc_buffer_t *enrollment_record, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_client_ctx);

    VSCE_ASSERT(password.len > 0 && password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    EnrollmentResponse response;

    pb_istream_t stream = pb_istream_from_buffer(enrollment_response.bytes, enrollment_response.len);

    // TODO: Check error
    pb_decode(&stream, EnrollmentResponse_fields, &response);

    vsc_buffer_t *nc = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH, nc);

    mbedtls_ecp_point hc0, hc1;
    mbedtls_ecp_point_init(&hc0);
    mbedtls_ecp_point_init(&hc1);

    vsce_phe_hash_hc0(phe_client_ctx->phe_hash, vsc_buffer_data(nc), password, &hc0);
    vsce_phe_hash_hc1(phe_client_ctx->phe_hash, vsc_buffer_data(nc), password, &hc1);
    //    vsce_phe_hash_hs0(phe_client_ctx->phe_hash, vsc_data(response.ns, vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH), &hs0);
    //    vsce_phe_hash_hs1(phe_client_ctx->phe_hash, vsc_data(response.ns, vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH), &hs1);

    vsc_buffer_t *rnd_m = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    vsc_buffer_make_secure(rnd_m);
    vscf_random(phe_client_ctx->random, vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, rnd_m);

    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);

    vsce_phe_hash_data_to_point(phe_client_ctx->phe_hash, vsc_buffer_data(rnd_m), &M);
    vsc_buffer_destroy(&rnd_m);

    vsc_buffer_t *M_buf = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_POINT_LENGTH);
    vsc_buffer_make_secure(M_buf);
    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&group, &M, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_ptr(M_buf), vsce_phe_common_PHE_POINT_LENGTH);

    // TODO: Check me
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    vscf_hkdf_impl_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    char hkdf_info[] = "PHE ACCOUNT SECRET";

    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(account_key) == vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_make_secure(account_key);
    vscf_hkdf_derive(hkdf, vsc_buffer_data(M_buf), vsc_data_empty(),
            vsc_data((byte *)hkdf_info, sizeof(hkdf_info)), account_key, vsc_buffer_capacity(account_key));
    vsc_buffer_destroy(&M_buf);
    vscf_hkdf_destroy(&hkdf);

    // TODO: Check proof

    mbedtls_ecp_point t0, t1;
    mbedtls_ecp_point_init(&t0);
    mbedtls_ecp_point_init(&t1);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    mbedtls_ecp_point_read_binary(&group, &c0, response.c0, sizeof(response.c0));
    mbedtls_ecp_point_read_binary(&group, &c1, response.c1, sizeof(response.c1));

    mbedtls_mpi skc;
    mbedtls_mpi_init(&skc);
    mbedtls_mpi_read_binary(&skc, vsc_buffer_bytes(phe_client_ctx->secret_key), vsc_buffer_len(phe_client_ctx->secret_key));

    mbedtls_ecp_muladd(&group, &t0, &one, &c0, &skc, &hc0);
    mbedtls_ecp_muladd(&group, &t1, &one, &c1, &skc, &hc1);
    mbedtls_ecp_muladd(&group, &t1, &one, &t1, &skc, &M);

    EnrollmentRecord record;
    memcpy(record.ns, response.ns, sizeof(response.ns));
    memcpy(record.nc, vsc_buffer_bytes(nc), vsc_buffer_len(nc));
    olen = 0;
    mbedtls_ecp_point_write_binary(&group, &t0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t0, sizeof(record.t0));
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
    olen = 0;
    mbedtls_ecp_point_write_binary(&group, &t1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, record.t1, sizeof(record.t1));
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_record), vsc_buffer_capacity(enrollment_record));
    pb_encode(&ostream, EnrollmentRecord_fields, &record);

    mbedtls_ecp_point_free(&t0);
    mbedtls_ecp_point_free(&t1);

    mbedtls_ecp_point_free(&hc0);
    mbedtls_ecp_point_free(&hc1);
    mbedtls_ecp_point_free(&M);

    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&skc);

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

    vsc_buffer_destroy(&nc);

    mbedtls_ecp_group_free(&group);

    return vsce_SUCCESS;
}
