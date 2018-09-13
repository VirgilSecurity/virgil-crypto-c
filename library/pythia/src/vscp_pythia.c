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


//  @description
// --------------------------------------------------------------------------
//  Provide Pythia implementation based on the Virgil Security.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscp_pythia.h"
#include "vscp_memory.h"
#include "vscp_assert.h"
#include "vscp_pythia_defs.h"

#include <pythia/pythia_init.h>
#include <pythia/pythia_wrapper.h>
#include <pythia/pythia_buf_sizes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
//  @end


static __thread mbedtls_entropy_context g_entropy_ctx;
static __thread mbedtls_ctr_drbg_context g_rng_ctx;
static __thread size_t g_instances = 0;


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Create puthia_buf_t object initializer from common class 'buffer'.
//
#define VSCP_PYTHIA_BUFFER_FROM_DATA(X) {.p = (uint8_t *)X.bytes, .allocated = X.len, .len = X.len}

//
//  Create puthia_buf_t object initializer from common class 'buffer'.
//
#define VSCP_PYTHIA_BUFFER_FROM_BUFFER(X) {.p = (uint8_t *)vsc_buffer_ptr(X), .allocated = vsc_buffer_left(X), .len = 0}

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscp_pythia_init() is called.
//  Note, that context is already zeroed.
//
static void
vscp_pythia_init_ctx(vscp_pythia_t *pythia_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscp_pythia_cleanup_ctx(vscp_pythia_t *pythia_ctx);

//
//  Callback for the pythia random.
//
static void
vscp_pythia_random_handler(byte *out, int out_len, void *ctx);

//
//  Return size of 'vscp_pythia_t'.
//
VSCP_PUBLIC size_t
vscp_pythia_ctx_size(void) {

    return sizeof(vscp_pythia_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCP_PUBLIC void
vscp_pythia_init(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    vscp_zeroize(pythia_ctx, sizeof(vscp_pythia_t));

    pythia_ctx->refcnt = 1;

    vscp_pythia_init_ctx(pythia_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCP_PUBLIC void
vscp_pythia_cleanup(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    if (pythia_ctx->refcnt == 0) {
        return;
    }

    if (--pythia_ctx->refcnt == 0) {
        vscp_pythia_cleanup_ctx(pythia_ctx);

        vscp_zeroize(pythia_ctx, sizeof(vscp_pythia_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCP_PUBLIC vscp_pythia_t *
vscp_pythia_new(void) {

    vscp_pythia_t *pythia_ctx = (vscp_pythia_t *) vscp_alloc(sizeof (vscp_pythia_t));
    VSCP_ASSERT_ALLOC(pythia_ctx);

    vscp_pythia_init(pythia_ctx);

    pythia_ctx->self_dealloc_cb = vscp_dealloc;

    return pythia_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCP_PUBLIC void
vscp_pythia_delete(vscp_pythia_t *pythia_ctx) {

    vscp_pythia_cleanup(pythia_ctx);

    vscp_dealloc_fn self_dealloc_cb = pythia_ctx->self_dealloc_cb;

    if (pythia_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(pythia_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscp_pythia_new ()'.
//
VSCP_PUBLIC void
vscp_pythia_destroy(vscp_pythia_t **pythia_ctx_ref) {

    VSCP_ASSERT_PTR(pythia_ctx_ref);

    vscp_pythia_t *pythia_ctx = *pythia_ctx_ref;
    *pythia_ctx_ref = NULL;

    vscp_pythia_delete(pythia_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCP_PUBLIC vscp_pythia_t *
vscp_pythia_copy(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    ++pythia_ctx->refcnt;

    return pythia_ctx;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscp_pythia_init() is called.
//  Note, that context is already zeroed.
//
static void
vscp_pythia_init_ctx(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    if (g_instances++ > 0) {
        return;
    }

    mbedtls_entropy_init(&g_entropy_ctx);
    mbedtls_ctr_drbg_init(&g_rng_ctx);

    const unsigned char pers[] = "vscp_pythia";
    size_t pers_len = sizeof(pers);
    VSCP_ASSERT_OPT(0 == mbedtls_ctr_drbg_seed(&g_rng_ctx, mbedtls_entropy_func, &g_entropy_ctx, pers, pers_len));
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscp_pythia_cleanup_ctx(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    if (--g_instances > 0) {
        return;
    }

    mbedtls_entropy_free(&g_entropy_ctx);
    mbedtls_ctr_drbg_free(&g_rng_ctx);
}

//
//  Performs global initialization of the pythia library.
//  Must be called once for entire application at startup.
//
VSCP_PUBLIC void
vscp_init(void) {

    pythia_init_args_t init_args;
    init_args.callback = vscp_pythia_random_handler;
    init_args.args = NULL;

    VSCP_ASSERT_OPT(0 == pythia_init(&init_args));
}

//
//  Performs global cleanup of the pythia library.
//  Must be called once for entire application before exit.
//
VSCP_PUBLIC void
vscp_cleanup(void) {

    pythia_deinit();
}

//
//  Return length of the buffer needed to hold 'blinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinded_password_buf_len(void) {

    return PYTHIA_G1_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'deblinded password'.
//
VSCP_PUBLIC size_t
vscp_pythia_deblinded_password_buf_len(void) {

    return PYTHIA_GT_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'blinding secret'.
//
VSCP_PUBLIC size_t
vscp_pythia_blinding_secret_buf_len(void) {

    return PYTHIA_BN_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'transformation private key'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformation_private_key_buf_len(void) {

    return PYTHIA_BN_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'transformation public key'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformation_public_key_buf_len(void) {

    return PYTHIA_G1_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'transformed password'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformed_password_buf_len(void) {

    return PYTHIA_GT_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'transformed tweak'.
//
VSCP_PUBLIC size_t
vscp_pythia_transformed_tweak_buf_len(void) {

    return PYTHIA_G2_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'proof value'.
//
VSCP_PUBLIC size_t
vscp_pythia_proof_value_buf_len(void) {

    return PYTHIA_BN_BUF_SIZE;
}

//
//  Return length of the buffer needed to hold 'password update token'.
//
VSCP_PUBLIC size_t
vscp_pythia_password_update_token_buf_len(void) {

    return PYTHIA_BN_BUF_SIZE;
}

//
//  Blinds password. Turns password into a pseudo-random string.
//  This step is necessary to prevent 3rd-parties from knowledge of end user's password.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_blind(
        vscp_pythia_t *pythia_ctx, vsc_data_t password, vsc_buffer_t *blinded_password, vsc_buffer_t *blinding_secret) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(password.bytes);
    VSCP_ASSERT_PTR(blinded_password);
    VSCP_ASSERT_PTR(blinding_secret);

    VSCP_ASSERT(vsc_buffer_left(blinded_password) >= vscp_pythia_blinded_password_buf_len());
    VSCP_ASSERT(vsc_buffer_left(blinding_secret) >= vscp_pythia_blinding_secret_buf_len());


    const pythia_buf_t password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(password);

    pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(blinded_password);
    pythia_buf_t blinding_secret_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(blinding_secret);

    if (0 != pythia_w_blind(&password_buf, &blinded_password_buf, &blinding_secret_buf)) {
        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(blinded_password, blinded_password_buf.len);
    vsc_buffer_reserve(blinding_secret, blinding_secret_buf.len);

    return vscp_SUCCESS;
}

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_deblind(vscp_pythia_t *pythia_ctx, vsc_data_t transformed_password, vsc_data_t blinding_secret,
        vsc_buffer_t *deblinded_password) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinding_secret.bytes);
    VSCP_ASSERT_PTR(deblinded_password);

    VSCP_ASSERT(vsc_buffer_left(deblinded_password) >= vscp_pythia_deblinded_password_buf_len());


    const pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_password);
    const pythia_buf_t blinding_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinding_secret);

    pythia_buf_t deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(deblinded_password);

    if (0 != pythia_w_deblind(&transformed_password_buf, &blinding_secret_buf, &deblinded_password_buf)) {
        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(deblinded_password, deblinded_password_buf.len);

    return vscp_SUCCESS;
}

//
//  Computes transformation private and public key.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_compute_transformation_key_pair(vscp_pythia_t *pythia_ctx, vsc_data_t transformation_key_id,
        vsc_data_t pythia_secret, vsc_data_t pythia_scope_secret, vsc_buffer_t *transformation_private_key,
        vsc_buffer_t *transformation_public_key) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(transformation_key_id.bytes);
    VSCP_ASSERT_PTR(pythia_secret.bytes);
    VSCP_ASSERT_PTR(pythia_scope_secret.bytes);
    VSCP_ASSERT_PTR(transformation_private_key);
    VSCP_ASSERT_PTR(transformation_public_key);

    VSCP_ASSERT(vsc_buffer_left(transformation_private_key) >= vscp_pythia_transformation_private_key_buf_len());
    VSCP_ASSERT(vsc_buffer_left(transformation_public_key) >= vscp_pythia_transformation_public_key_buf_len());

    const pythia_buf_t transformation_key_id_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_key_id);
    const pythia_buf_t pythia_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(pythia_secret);
    const pythia_buf_t pythia_scope_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(pythia_scope_secret);

    pythia_buf_t transformation_private_key_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformation_private_key);
    pythia_buf_t transformation_public_key_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformation_public_key);

    if (0 != pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &pythia_secret_buf,
                     &pythia_scope_secret_buf, &transformation_private_key_buf, &transformation_public_key_buf)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(transformation_private_key, transformation_private_key_buf.len);
    vsc_buffer_reserve(transformation_public_key, transformation_public_key_buf.len);

    return vscp_SUCCESS;
}

//
//  Transforms blinded password using transformation private key.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_transform(vscp_pythia_t *pythia_ctx, vsc_data_t blinded_password, vsc_data_t tweak,
        vsc_data_t transformation_private_key, vsc_buffer_t *transformed_password, vsc_buffer_t *transformed_tweak) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(blinded_password.bytes);
    VSCP_ASSERT_PTR(tweak.bytes);
    VSCP_ASSERT_PTR(transformation_private_key.bytes);
    VSCP_ASSERT_PTR(transformed_password);
    VSCP_ASSERT_PTR(transformed_tweak);

    VSCP_ASSERT(vsc_buffer_left(transformed_password) >= vscp_pythia_transformed_password_buf_len());
    VSCP_ASSERT(vsc_buffer_left(transformed_tweak) >= vscp_pythia_transformed_tweak_buf_len());

    const pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinded_password);
    const pythia_buf_t tweak_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(tweak);
    const pythia_buf_t transformation_private_key_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_private_key);

    pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformed_password);
    pythia_buf_t transformed_tweak_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformed_tweak);

    if (0 != pythia_w_transform(&blinded_password_buf, &tweak_buf, &transformation_private_key_buf,
                     &transformed_password_buf, &transformed_tweak_buf)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(transformed_password, transformed_password_buf.len);
    vsc_buffer_reserve(transformed_tweak, transformed_tweak_buf.len);

    return vscp_SUCCESS;
}

//
//  Generates proof that server possesses secret values that were used to transform password.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_prove(vscp_pythia_t *pythia_ctx, vsc_data_t transformed_password, vsc_data_t blinded_password,
        vsc_data_t transformed_tweak, vsc_data_t transformation_private_key, vsc_data_t transformation_public_key,
        vsc_buffer_t *proof_value_c, vsc_buffer_t *proof_value_u) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinded_password.bytes);
    VSCP_ASSERT_PTR(transformed_tweak.bytes);
    VSCP_ASSERT_PTR(transformation_private_key.bytes);
    VSCP_ASSERT_PTR(transformation_public_key.bytes);
    VSCP_ASSERT_PTR(proof_value_c);
    VSCP_ASSERT_PTR(proof_value_u);

    VSCP_ASSERT(vsc_buffer_left(proof_value_c) >= vscp_pythia_proof_value_buf_len());
    VSCP_ASSERT(vsc_buffer_left(proof_value_u) >= vscp_pythia_proof_value_buf_len());

    const pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_password);
    const pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinded_password);
    const pythia_buf_t transformed_tweak_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_tweak);
    const pythia_buf_t transformation_private_key_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_private_key);
    const pythia_buf_t transformation_public_key_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_public_key);

    pythia_buf_t proof_value_c_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(proof_value_c);
    pythia_buf_t proof_value_u_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(proof_value_u);

    if (0 != pythia_w_prove(&transformed_password_buf, &blinded_password_buf, &transformed_tweak_buf,
                     &transformation_private_key_buf, &transformation_public_key_buf, &proof_value_c_buf,
                     &proof_value_u_buf)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(proof_value_c, proof_value_c_buf.len);
    vsc_buffer_reserve(proof_value_u, proof_value_u_buf.len);

    return vscp_SUCCESS;
}

//
//  This operation allows client to verify that the output of transform() is correct,
//  assuming that client has previously stored transformation public key.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_verify(vscp_pythia_t *pythia_ctx, vsc_data_t transformed_password, vsc_data_t blinded_password,
        vsc_data_t tweak, vsc_data_t transformation_public_key, vsc_data_t proof_value_c, vsc_data_t proof_value_u) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinded_password.bytes);
    VSCP_ASSERT_PTR(tweak.bytes);
    VSCP_ASSERT_PTR(transformation_public_key.bytes);
    VSCP_ASSERT_PTR(proof_value_c.bytes);
    VSCP_ASSERT_PTR(proof_value_u.bytes);

    const pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_password);
    const pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinded_password);
    const pythia_buf_t tweak_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(tweak);
    const pythia_buf_t transformation_public_key_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_public_key);
    const pythia_buf_t proof_value_c_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(proof_value_c);
    const pythia_buf_t proof_value_u_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(proof_value_u);

    int verified = 0;

    if (0 != pythia_w_verify(&transformed_password_buf, &blinded_password_buf, &tweak_buf,
                     &transformation_public_key_buf, &proof_value_c_buf, &proof_value_u_buf, &verified)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    if (0 == verified) {
        return vscp_error_VERIFICATION_FAIL;
    }

    return vscp_SUCCESS;
}

//
//  Rotates old transformation key to new transformation key and generates 'password update token',
//  that can update 'deblinded password'(s).
//
//  This action should increment version of the 'pythia scope secret'.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_get_password_update_token(vscp_pythia_t *pythia_ctx, vsc_data_t previous_transformation_private_key,
        vsc_data_t new_transformation_private_key, vsc_buffer_t *password_update_token) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(previous_transformation_private_key.bytes);
    VSCP_ASSERT_PTR(new_transformation_private_key.bytes);
    VSCP_ASSERT_PTR(password_update_token);

    VSCP_ASSERT(vsc_buffer_left(password_update_token) >= vscp_pythia_proof_value_buf_len());

    const pythia_buf_t previous_transformation_private_key_buf =
            VSCP_PYTHIA_BUFFER_FROM_DATA(previous_transformation_private_key);

    const pythia_buf_t new_transformation_private_key_buf =
            VSCP_PYTHIA_BUFFER_FROM_DATA(new_transformation_private_key);

    pythia_buf_t password_update_token_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(password_update_token);

    if (0 != pythia_w_get_password_update_token(&previous_transformation_private_key_buf,
                     &new_transformation_private_key_buf, &password_update_token_buf)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(password_update_token, password_update_token_buf.len);

    return vscp_SUCCESS;
}

//
//  Updates previously stored 'deblinded password' with 'password update token'.
//  After this call, 'transform()' called with new arguments will return corresponding values.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_update_deblinded_with_token(vscp_pythia_t *pythia_ctx, vsc_data_t deblinded_password,
        vsc_data_t password_update_token, vsc_buffer_t *updated_deblinded_password) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(deblinded_password.bytes);
    VSCP_ASSERT_PTR(password_update_token.bytes);
    VSCP_ASSERT_PTR(updated_deblinded_password);

    VSCP_ASSERT(vsc_buffer_left(updated_deblinded_password) >= vscp_pythia_deblinded_password_buf_len());

    const pythia_buf_t deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(deblinded_password);
    const pythia_buf_t password_update_token_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(password_update_token);

    pythia_buf_t updated_deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(updated_deblinded_password);

    if (0 != pythia_w_update_deblinded_with_token(
                     &deblinded_password_buf, &password_update_token_buf, &updated_deblinded_password_buf)) {

        return vscp_error_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_reserve(updated_deblinded_password, updated_deblinded_password_buf.len);

    return vscp_SUCCESS;
}

//
//  Callback for the pythia random.
//
static void
vscp_pythia_random_handler(byte *out, int out_len, void *ctx) {

    VSCP_UNUSED(ctx);
    VSCP_ASSERT_OPT(0 == mbedtls_ctr_drbg_random(&g_rng_ctx, out, out_len));
}
