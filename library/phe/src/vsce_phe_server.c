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
//  Class for server-side PHE crypto operations.
//  This class is thread-safe in case if VSCE_MULTI_THREAD defined
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_phe_server.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_hash.h"

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
//  Handle 'phe server' context.
//
struct vsce_phe_server_t {
    //
    //  Function do deallocate self context.
    //
    vsce_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *random;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *operation_random;

    vsce_phe_hash_t *phe_hash;

    mbedtls_ecp_group group;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *self);

static vsce_error_t
vsce_phe_server_prove_success(vsce_phe_server_t *self, mbedtls_ecp_group *op_group, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *hs0, const mbedtls_ecp_point *hs1,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, ProofOfSuccess *success_proof);

static vsce_error_t
vsce_phe_server_prove_failure(vsce_phe_server_t *self, mbedtls_ecp_group *op_group, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *hs0, mbedtls_ecp_point *c1,
        ProofOfFail *failure_proof);

static mbedtls_ecp_group *
vsce_phe_server_get_op_group(vsce_phe_server_t *self);

static void
vsce_phe_server_free_op_group(mbedtls_ecp_group *op_group);

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
vsce_phe_server_init(vsce_phe_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_phe_server_t));

    self->refcnt = 1;

    vsce_phe_server_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_server_cleanup(vsce_phe_server_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vsce_phe_server_cleanup_ctx(self);

        vsce_phe_server_release_random(self);
        vsce_phe_server_release_operation_random(self);

        vsce_zeroize(self, sizeof(vsce_phe_server_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_new(void) {

    vsce_phe_server_t *self = (vsce_phe_server_t *) vsce_alloc(sizeof (vsce_phe_server_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_phe_server_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_server_delete(vsce_phe_server_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsce_phe_server_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_server_new ()'.
//
VSCE_PUBLIC void
vsce_phe_server_destroy(vsce_phe_server_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_phe_server_t *self = *self_ref;
    *self_ref = NULL;

    vsce_phe_server_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_server_t *
vsce_phe_server_shallow_copy(vsce_phe_server_t *self) {

    VSCE_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_server_use_random(vsce_phe_server_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_server_take_random(vsce_phe_server_t *self, vscf_impl_t *random) {

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
vsce_phe_server_release_random(vsce_phe_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_server_use_operation_random(vsce_phe_server_t *self, vscf_impl_t *operation_random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(operation_random);
    VSCE_ASSERT(self->operation_random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(operation_random));

    self->operation_random = vscf_impl_shallow_copy(operation_random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_server_take_operation_random(vsce_phe_server_t *self, vscf_impl_t *operation_random) {

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
vsce_phe_server_release_operation_random(vsce_phe_server_t *self) {

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
//  Note, this method is called automatically when method vsce_phe_server_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_server_init_ctx(vsce_phe_server_t *self) {

    VSCE_ASSERT_PTR(self);

    self->phe_hash = vsce_phe_hash_new();

    vscf_ctr_drbg_t *rng1, *rng2;
    rng1 = vscf_ctr_drbg_new();
    rng2 = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng1);
    vscf_ctr_drbg_setup_defaults(rng2);

    vsce_phe_server_take_random(self, vscf_ctr_drbg_impl(rng1));
    vsce_phe_server_take_operation_random(self, vscf_ctr_drbg_impl(rng2));

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
vsce_phe_server_cleanup_ctx(vsce_phe_server_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_phe_hash_destroy(&self->phe_hash);
    mbedtls_ecp_group_free(&self->group);
}

//
//  Generates new NIST P-256 server key pair for some client
//
VSCE_PUBLIC vsce_error_t
vsce_phe_server_generate_server_key_pair(
        vsce_phe_server_t *self, vsc_buffer_t *server_private_key, vsc_buffer_t *server_public_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(server_private_key);
    VSCE_ASSERT(vsc_buffer_len(server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_server_get_op_group(self);

    vsce_error_t status = vsce_SUCCESS;
    int mbedtls_status = 0;

    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);

    mbedtls_ecp_point pub;
    mbedtls_ecp_point_init(&pub);

    mbedtls_status = mbedtls_ecp_gen_keypair(op_group, &priv, &pub, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_status = mbedtls_mpi_write_binary(
            &priv, vsc_buffer_unused_bytes(server_private_key), vsc_buffer_capacity(server_private_key));
    vsc_buffer_inc_used(server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(server_public_key), vsc_buffer_capacity(server_public_key));
    vsc_buffer_inc_used(server_public_key, olen);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

err:
    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&priv);

    vsce_phe_server_free_op_group(op_group);

    return status;
}

//
//  Buffer size needed to fit EnrollmentResponse
//
VSCE_PUBLIC size_t
vsce_phe_server_enrollment_response_len(vsce_phe_server_t *self) {

    VSCE_UNUSED(self);

    return EnrollmentResponse_size;
}

//
//  Generates a new random enrollment and proof for a new user
//
VSCE_PUBLIC vsce_error_t
vsce_phe_server_get_enrollment(vsce_phe_server_t *self, vsc_data_t server_private_key, vsc_data_t server_public_key,
        vsc_buffer_t *enrollment_response) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(enrollment_response) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(enrollment_response) >= vsce_phe_server_enrollment_response_len(self));
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_server_get_op_group(self);

    vsce_error_t status = vsce_SUCCESS;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vsce_error_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    EnrollmentResponse response = EnrollmentResponse_init_zero;

    vsc_buffer_t ns;
    vsc_buffer_init(&ns);
    vsc_buffer_use(&ns, response.ns, sizeof(response.ns));

    vscf_error_t f_status = vscf_random(self->random, vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH, &ns);

    if (f_status != vscf_SUCCESS) {
        status = vsce_error_RNG_ERROR;
        goto rng_err;
    }

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(self->phe_hash, vsc_buffer_data(&ns), &hs0);
    vsce_phe_hash_hs1(self->phe_hash, vsc_buffer_data(&ns), &hs1);

    mbedtls_ecp_point c0, c1;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);

    mbedtls_status = mbedtls_ecp_mul(&self->group, &c0, &x, &hs0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_mul(&self->group, &c1, &x, &hs1, vscf_mbedtls_bridge_random, self->operation_random);

    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &c0, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c0, sizeof(response.c0));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(
            &self->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c1, sizeof(response.c1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    status = vsce_phe_server_prove_success(
            self, op_group, server_private_key, server_public_key, &hs0, &hs1, &c0, &c1, &response.proof);

    if (status != vsce_SUCCESS) {
        goto err;
    }

    pb_ostream_t ostream = pb_ostream_from_buffer(
            vsc_buffer_unused_bytes(enrollment_response), vsc_buffer_capacity(enrollment_response));

    VSCE_ASSERT(pb_encode(&ostream, EnrollmentResponse_fields, &response));
    vsc_buffer_inc_used(enrollment_response, ostream.bytes_written);

    vsce_zeroize(&response, sizeof(response));

err:
    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);
    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);

rng_err:
    vsc_buffer_delete(&ns);

priv_err:
    mbedtls_mpi_free(&x);

    vsce_phe_server_free_op_group(op_group);

    return status;
}

//
//  Buffer size needed to fit VerifyPasswordResponse
//
VSCE_PUBLIC size_t
vsce_phe_server_verify_password_response_len(vsce_phe_server_t *self) {

    VSCE_UNUSED(self);

    return VerifyPasswordResponse_size;
}

//
//  Verifies existing user's password and generates response with proof
//
VSCE_PUBLIC vsce_error_t
vsce_phe_server_verify_password(vsce_phe_server_t *self, vsc_data_t server_private_key, vsc_data_t server_public_key,
        vsc_data_t verify_password_request, vsc_buffer_t *verify_password_response) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(vsc_buffer_len(verify_password_response) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(verify_password_response) >= vsce_phe_server_verify_password_response_len(self));
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_server_get_op_group(self);

    vsce_error_t status = vsce_SUCCESS;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vsce_error_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    VerifyPasswordRequest request = VerifyPasswordRequest_init_zero;

    if (verify_password_request.len > VerifyPasswordRequest_size) {
        status = vsce_error_PROTOBUF_DECODE_ERROR;
        goto pb_err;
    }

    pb_istream_t istream = pb_istream_from_buffer(verify_password_request.bytes, verify_password_request.len);
    bool pb_status = pb_decode(&istream, VerifyPasswordRequest_fields, &request);

    if (!pb_status) {
        status = vsce_error_PROTOBUF_DECODE_ERROR;
        goto pb_err;
    }

    mbedtls_ecp_point c0;
    mbedtls_ecp_point_init(&c0);

    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &c0, request.c0, sizeof(request.c0));
    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &c0) != 0) {
        status = vsce_error_INVALID_ECP;
        goto ecp_err;
    }

    mbedtls_ecp_point hs0, hs1;
    mbedtls_ecp_point_init(&hs0);
    mbedtls_ecp_point_init(&hs1);

    vsce_phe_hash_hs0(self->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs0);
    vsce_phe_hash_hs1(self->phe_hash, vsc_data(request.ns, sizeof(request.ns)), &hs1);

    mbedtls_ecp_point hs0x;
    mbedtls_ecp_point_init(&hs0x);

    mbedtls_status = mbedtls_ecp_mul(&self->group, &hs0x, &x, &hs0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point c1;
    mbedtls_ecp_point_init(&c1);

    if (mbedtls_ecp_point_cmp(&c0, &hs0x) == 0) {
        // Password matches

        mbedtls_status =
                mbedtls_ecp_mul(&self->group, &c1, &x, &hs1, vscf_mbedtls_bridge_random, self->operation_random);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
        response.res = true;

        response.which_proof = VerifyPasswordResponse_success_tag;
        status = vsce_phe_server_prove_success(
                self, op_group, server_private_key, server_public_key, &hs0, &hs1, &c0, &c1, &response.proof.success);

        if (status != vsce_SUCCESS) {
            goto err;
        }

        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &self->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c1, sizeof(response.c1));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(
                vsc_buffer_unused_bytes(verify_password_response), vsc_buffer_capacity(verify_password_response));
        VSCE_ASSERT(pb_encode(&ostream, VerifyPasswordResponse_fields, &response));
        vsc_buffer_inc_used(verify_password_response, ostream.bytes_written);
        vsce_zeroize(&response, sizeof(response));
    } else {
        // Password doesn't match

        VerifyPasswordResponse response = VerifyPasswordResponse_init_zero;
        response.res = false;

        response.which_proof = VerifyPasswordResponse_fail_tag;
        status = vsce_phe_server_prove_failure(
                self, op_group, server_private_key, server_public_key, &c0, &hs0, &c1, &response.proof.fail);

        if (status != vsce_SUCCESS) {
            goto err;
        }

        size_t olen = 0;
        mbedtls_status = mbedtls_ecp_point_write_binary(
                &self->group, &c1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, response.c1, sizeof(response.c1));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

        pb_ostream_t ostream = pb_ostream_from_buffer(
                vsc_buffer_unused_bytes(verify_password_response), vsc_buffer_capacity(verify_password_response));
        VSCE_ASSERT(pb_encode(&ostream, VerifyPasswordResponse_fields, &response));
        vsc_buffer_inc_used(verify_password_response, ostream.bytes_written);
        vsce_zeroize(&response, sizeof(response));
    }

err:
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&hs0);
    mbedtls_ecp_point_free(&hs1);
    mbedtls_ecp_point_free(&hs0x);

ecp_err:
    mbedtls_ecp_point_free(&c0);

pb_err:
    vsce_zeroize(&request, sizeof(request));

priv_err:

    mbedtls_mpi_free(&x);

    vsce_phe_server_free_op_group(op_group);

    return status;
}

static vsce_error_t
vsce_phe_server_prove_success(vsce_phe_server_t *self, mbedtls_ecp_group *op_group, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *hs0, const mbedtls_ecp_point *hs1,
        const mbedtls_ecp_point *c0, const mbedtls_ecp_point *c1, ProofOfSuccess *success_proof) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(hs1);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(success_proof);

    vsce_error_t status = vsce_SUCCESS;

    mbedtls_mpi blind_x;
    mbedtls_mpi_init(&blind_x);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &blind_x, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vsce_error_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_ecp_point term1, term2, term3;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);

    mbedtls_status =
            mbedtls_ecp_mul(op_group, &term1, &blind_x, hs0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status =
            mbedtls_ecp_mul(op_group, &term2, &blind_x, hs1, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_mul(
            op_group, &term3, &blind_x, &self->group.G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi challenge;
    mbedtls_mpi_init(&challenge);

    vsce_phe_hash_hash_z_success(self->phe_hash, server_public_key, c0, c1, &term1, &term2, &term3, &challenge);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge, &challenge, &x);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_add_mpi(&blind_x, &blind_x, &challenge);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_x, &blind_x, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term1, sizeof(success_proof->term1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(success_proof->term1));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term2, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term2, sizeof(success_proof->term2));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(success_proof->term2));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term3, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            success_proof->term3, sizeof(success_proof->term3));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(success_proof->term3));

    mbedtls_status = mbedtls_mpi_write_binary(&blind_x, success_proof->blind_x, sizeof(success_proof->blind_x));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_free(&challenge);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);

priv_err:
    mbedtls_mpi_free(&x);

err:
    mbedtls_mpi_free(&blind_x);

    return status;
}

static vsce_error_t
vsce_phe_server_prove_failure(vsce_phe_server_t *self, mbedtls_ecp_group *op_group, vsc_data_t server_private_key,
        vsc_data_t server_public_key, const mbedtls_ecp_point *c0, const mbedtls_ecp_point *hs0, mbedtls_ecp_point *c1,
        ProofOfFail *failure_proof) {

    VSCE_ASSERT_PTR(self);

    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(server_public_key.len == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    VSCE_ASSERT_PTR(hs0);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);

    VSCE_ASSERT_PTR(failure_proof);

    vsce_error_t status = vsce_SUCCESS;

    int mbedtls_status = 0;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vsce_error_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_ecp_point X;
    mbedtls_ecp_point_init(&X);
    mbedtls_status = mbedtls_ecp_point_read_binary(&self->group, &X, server_public_key.bytes, server_public_key.len);

    if (mbedtls_status != 0 || mbedtls_ecp_check_pubkey(&self->group, &X) != 0) {
        status = vsce_error_INVALID_ECP;
        goto ecp_err;
    }

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_mpi blind_A, blind_B;
    mbedtls_mpi_init(&blind_A);
    mbedtls_mpi_init(&blind_B);

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &r, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &blind_A, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &blind_B, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_mpi minus_r;
    mbedtls_mpi_init(&minus_r);

    mbedtls_status = mbedtls_mpi_sub_mpi(&minus_r, &self->group.N, &r);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi minus_RX;
    mbedtls_mpi_init(&minus_RX);

    mbedtls_status = mbedtls_mpi_mul_mpi(&minus_RX, &x, &minus_r);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&minus_RX, &minus_RX, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_muladd(op_group, c1, &r, c0, &minus_RX, hs0);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point term1, term2, term3, term4;
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);
    mbedtls_ecp_point_init(&term4);

    mbedtls_status =
            mbedtls_ecp_mul(&self->group, &term1, &blind_A, c0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status =
            mbedtls_ecp_mul(op_group, &term2, &blind_B, hs0, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status =
            mbedtls_ecp_mul(&self->group, &term3, &blind_A, &X, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_ecp_mul(
            op_group, &term4, &blind_B, &self->group.G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi challenge_A, challenge_B;
    mbedtls_mpi_init(&challenge_A);
    mbedtls_mpi_init(&challenge_B);

    vsce_phe_hash_hash_z_failure(
            self->phe_hash, server_public_key, c0, c1, &term1, &term2, &term3, &term4, &challenge_A);

    mbedtls_mpi_copy(&challenge_B, &challenge_A);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge_A, &challenge_A, &r);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&blind_A, &blind_A, &challenge_A);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_A, &blind_A, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_mul_mpi(&challenge_B, &challenge_B, &minus_RX);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&blind_B, &blind_B, &challenge_B);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&blind_B, &blind_B, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term1, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term1, sizeof(failure_proof->term1));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(failure_proof->term1));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term2, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term2, sizeof(failure_proof->term2));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(failure_proof->term2));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term3, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term3, sizeof(failure_proof->term3));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(failure_proof->term3));

    olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &term4, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            failure_proof->term4, sizeof(failure_proof->term4));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == sizeof(failure_proof->term4));

    mbedtls_status = mbedtls_mpi_write_binary(&blind_A, failure_proof->blind_a, sizeof(failure_proof->blind_a));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_write_binary(&blind_B, failure_proof->blind_b, sizeof(failure_proof->blind_b));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_free(&challenge_A);
    mbedtls_mpi_free(&challenge_B);

    mbedtls_mpi_free(&minus_r);
    mbedtls_mpi_free(&minus_RX);

    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);
    mbedtls_ecp_point_free(&term4);

err:
    mbedtls_mpi_free(&r);

    mbedtls_mpi_free(&blind_A);
    mbedtls_mpi_free(&blind_B);

ecp_err:
    mbedtls_ecp_point_free(&X);

priv_err:
    mbedtls_mpi_free(&x);

    return status;
}

//
//  Buffer size needed to fit UpdateToken
//
VSCE_PUBLIC size_t
vsce_phe_server_update_token_len(vsce_phe_server_t *self) {

    VSCE_UNUSED(self);

    return UpdateToken_size;
}

//
//  Updates server's private and public keys and issues an update token for use on client's side
//
VSCE_PUBLIC vsce_error_t
vsce_phe_server_rotate_keys(vsce_phe_server_t *self, vsc_data_t server_private_key,
        vsc_buffer_t *new_server_private_key, vsc_buffer_t *new_server_public_key, vsc_buffer_t *update_token) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(server_private_key.len == vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT(vsc_buffer_len(update_token) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(update_token) >= vsce_phe_server_update_token_len(self));
    VSCE_ASSERT(vsc_buffer_len(new_server_private_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_private_key) >= vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_make_secure(new_server_private_key);
    VSCE_ASSERT(vsc_buffer_len(new_server_public_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(new_server_public_key) >= vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_group *op_group = vsce_phe_server_get_op_group(self);

    vsce_error_t status = vsce_SUCCESS;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&x, server_private_key.bytes, server_private_key.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_ecp_check_privkey(&self->group, &x);
    if (mbedtls_status != 0) {
        status = vsce_error_INVALID_PRIVATE_KEY;
        goto priv_err;
    }

    mbedtls_mpi a, b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &a, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    mbedtls_status = mbedtls_ecp_gen_privkey(&self->group, &b, vscf_mbedtls_bridge_random, self->random);

    if (mbedtls_status != 0) {
        status = vsce_error_RNG_ERROR;
        goto err;
    }

    UpdateToken token = UpdateToken_init_zero;

    mbedtls_status = mbedtls_mpi_write_binary(&a, token.a, sizeof(token.a));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_write_binary(&b, token.b, sizeof(token.b));
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    pb_ostream_t ostream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(update_token), vsc_buffer_capacity(update_token));
    VSCE_ASSERT(pb_encode(&ostream, UpdateToken_fields, &token));
    vsc_buffer_inc_used(update_token, ostream.bytes_written);
    vsce_zeroize(&token, sizeof(token));

    mbedtls_mpi new_x;
    mbedtls_mpi_init(&new_x);

    mbedtls_status = mbedtls_mpi_mul_mpi(&new_x, &x, &a);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&new_x, &new_x, &b);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&new_x, &new_x, &self->group.N);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_status = mbedtls_mpi_write_binary(
            &new_x, vsc_buffer_unused_bytes(new_server_private_key), vsc_buffer_capacity(new_server_private_key));
    vsc_buffer_inc_used(new_server_private_key, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_ecp_point new_X;
    mbedtls_ecp_point_init(&new_X);

    mbedtls_status = mbedtls_ecp_mul(
            op_group, &new_X, &new_x, &self->group.G, vscf_mbedtls_bridge_random, self->operation_random);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    size_t olen = 0;
    mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, &new_X, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(new_server_public_key), vsc_buffer_capacity(new_server_public_key));
    vsc_buffer_inc_used(new_server_public_key, vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    mbedtls_ecp_point_free(&new_X);

    mbedtls_mpi_free(&new_x);

err:
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

priv_err:
    mbedtls_mpi_free(&x);

    vsce_phe_server_free_op_group(op_group);

    return status;
}

static mbedtls_ecp_group *
vsce_phe_server_get_op_group(vsce_phe_server_t *self) {

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
vsce_phe_server_free_op_group(mbedtls_ecp_group *op_group) {

#if VSCE_MULTI_THREAD
    mbedtls_ecp_group_free(op_group);
    vsce_dealloc(op_group);
#endif
}
