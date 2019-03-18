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

#include <pythia_init.h>
#include <pythia_wrapper.h>
#include <pythia_buf_sizes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>

// clang-format on
//  @end


#if VSCP_MULTI_THREAD
#define VSCP_LOCAL_THREAD_STORAGE __thread
#else
#define VSCP_LOCAL_THREAD_STORAGE
#endif

static VSCP_LOCAL_THREAD_STORAGE mbedtls_entropy_context g_entropy;
static VSCP_LOCAL_THREAD_STORAGE mbedtls_ctr_drbg_context g_rng;
static VSCP_LOCAL_THREAD_STORAGE size_t g_instances = 0;
static bool g_globally_inited = false;

#undef VSCP_LOCAL_THREAD_STORAGE


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
#define VSCP_PYTHIA_BUFFER_FROM_BUFFER(X) {.p = (uint8_t *)vsc_buffer_unused_bytes(X), .allocated = vsc_buffer_unused_len(X), .len = 0}

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscp_pythia_init() is called.
//  Note, that context is already zeroed.
//
static void
vscp_pythia_init_ctx(vscp_pythia_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscp_pythia_cleanup_ctx(vscp_pythia_t *self);

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
vscp_pythia_init(vscp_pythia_t *self) {

    VSCP_ASSERT_PTR(self);

    vscp_zeroize(self, sizeof(vscp_pythia_t));

    self->refcnt = 1;

    vscp_pythia_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCP_PUBLIC void
vscp_pythia_cleanup(vscp_pythia_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscp_pythia_cleanup_ctx(self);

        vscp_zeroize(self, sizeof(vscp_pythia_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCP_PUBLIC vscp_pythia_t *
vscp_pythia_new(void) {

    vscp_pythia_t *self = (vscp_pythia_t *) vscp_alloc(sizeof (vscp_pythia_t));
    VSCP_ASSERT_ALLOC(self);

    vscp_pythia_init(self);

    self->self_dealloc_cb = vscp_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCP_PUBLIC void
vscp_pythia_delete(vscp_pythia_t *self) {

    if (self == NULL) {
        return;
    }

    vscp_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscp_pythia_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscp_pythia_new ()'.
//
VSCP_PUBLIC void
vscp_pythia_destroy(vscp_pythia_t **self_ref) {

    VSCP_ASSERT_PTR(self_ref);

    vscp_pythia_t *self = *self_ref;
    *self_ref = NULL;

    vscp_pythia_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCP_PUBLIC vscp_pythia_t *
vscp_pythia_shallow_copy(vscp_pythia_t *self) {

    VSCP_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
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
vscp_pythia_init_ctx(vscp_pythia_t *self) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT(g_globally_inited && "Call vscp_global_init() before use any class function.");

    if (g_instances++ > 0) {
        return;
    }

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_rng);

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
    mbedtls_entropy_add_source(&g_entropy, mbedtls_platform_entropy_poll, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM,
            MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

#if defined(MBEDTLS_TIMING_C)
    mbedtls_entropy_add_source(
            &g_entropy, mbedtls_hardclock_poll, NULL, MBEDTLS_ENTROPY_MIN_HARDCLOCK, MBEDTLS_ENTROPY_SOURCE_WEAK);
#endif

#if defined(MBEDTLS_HAVEGE_C)
    mbedtls_entropy_add_source(&g_entropy, mbedtls_havege_poll, &g_entropy.havege_data, MBEDTLS_ENTROPY_MIN_HAVEGE,
            MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

    const unsigned char pers[] = "vscp_pythia";
    size_t pers_len = sizeof(pers);
    int status = mbedtls_ctr_drbg_seed(&g_rng, mbedtls_entropy_func, &g_entropy, pers, pers_len);
    VSCP_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscp_pythia_cleanup_ctx(vscp_pythia_t *self) {

    VSCP_ASSERT_PTR(self);

    if (--g_instances > 0) {
        return;
    }

    mbedtls_entropy_free(&g_entropy);
    mbedtls_ctr_drbg_free(&g_rng);
}

//
//  Performs global initialization of the pythia library.
//  Must be called once for entire application at startup.
//
VSCP_PUBLIC void
vscp_global_init(void) {

    if (g_globally_inited) {
        return;
    }

    g_globally_inited = true;
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
vscp_global_cleanup(void) {

    if (!g_globally_inited) {
        return;
    }

    g_globally_inited = false;
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
VSCP_PUBLIC vscp_status_t
vscp_pythia_blind(
        vscp_pythia_t *self, vsc_data_t password, vsc_buffer_t *blinded_password, vsc_buffer_t *blinding_secret) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(password.bytes);
    VSCP_ASSERT_PTR(blinded_password);
    VSCP_ASSERT_PTR(blinding_secret);

    VSCP_ASSERT(vsc_buffer_unused_len(blinded_password) >= vscp_pythia_blinded_password_buf_len());
    VSCP_ASSERT(vsc_buffer_unused_len(blinding_secret) >= vscp_pythia_blinding_secret_buf_len());


    const pythia_buf_t password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(password);

    pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(blinded_password);
    pythia_buf_t blinding_secret_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(blinding_secret);

    if (0 != pythia_w_blind(&password_buf, &blinded_password_buf, &blinding_secret_buf)) {
        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(blinded_password, blinded_password_buf.len);
    vsc_buffer_inc_used(blinding_secret, blinding_secret_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_deblind(vscp_pythia_t *self, vsc_data_t transformed_password, vsc_data_t blinding_secret,
        vsc_buffer_t *deblinded_password) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinding_secret.bytes);
    VSCP_ASSERT_PTR(deblinded_password);

    VSCP_ASSERT(vsc_buffer_unused_len(deblinded_password) >= vscp_pythia_deblinded_password_buf_len());


    const pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_password);
    const pythia_buf_t blinding_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinding_secret);

    pythia_buf_t deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(deblinded_password);

    if (0 != pythia_w_deblind(&transformed_password_buf, &blinding_secret_buf, &deblinded_password_buf)) {
        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(deblinded_password, deblinded_password_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Computes transformation private and public key.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_compute_transformation_key_pair(vscp_pythia_t *self, vsc_data_t transformation_key_id,
        vsc_data_t pythia_secret, vsc_data_t pythia_scope_secret, vsc_buffer_t *transformation_private_key,
        vsc_buffer_t *transformation_public_key) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(transformation_key_id.bytes);
    VSCP_ASSERT_PTR(pythia_secret.bytes);
    VSCP_ASSERT_PTR(pythia_scope_secret.bytes);
    VSCP_ASSERT_PTR(transformation_private_key);
    VSCP_ASSERT_PTR(transformation_public_key);

    VSCP_ASSERT(vsc_buffer_unused_len(transformation_private_key) >= vscp_pythia_transformation_private_key_buf_len());
    VSCP_ASSERT(vsc_buffer_unused_len(transformation_public_key) >= vscp_pythia_transformation_public_key_buf_len());

    const pythia_buf_t transformation_key_id_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_key_id);
    const pythia_buf_t pythia_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(pythia_secret);
    const pythia_buf_t pythia_scope_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(pythia_scope_secret);

    pythia_buf_t transformation_private_key_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformation_private_key);
    pythia_buf_t transformation_public_key_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformation_public_key);

    if (0 != pythia_w_compute_transformation_key_pair(&transformation_key_id_buf, &pythia_secret_buf,
                     &pythia_scope_secret_buf, &transformation_private_key_buf, &transformation_public_key_buf)) {

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(transformation_private_key, transformation_private_key_buf.len);
    vsc_buffer_inc_used(transformation_public_key, transformation_public_key_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Transforms blinded password using transformation private key.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_transform(vscp_pythia_t *self, vsc_data_t blinded_password, vsc_data_t tweak,
        vsc_data_t transformation_private_key, vsc_buffer_t *transformed_password, vsc_buffer_t *transformed_tweak) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(blinded_password.bytes);
    VSCP_ASSERT_PTR(tweak.bytes);
    VSCP_ASSERT_PTR(transformation_private_key.bytes);
    VSCP_ASSERT_PTR(transformed_password);
    VSCP_ASSERT_PTR(transformed_tweak);

    VSCP_ASSERT(vsc_buffer_unused_len(transformed_password) >= vscp_pythia_transformed_password_buf_len());
    VSCP_ASSERT(vsc_buffer_unused_len(transformed_tweak) >= vscp_pythia_transformed_tweak_buf_len());

    const pythia_buf_t blinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinded_password);
    const pythia_buf_t tweak_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(tweak);
    const pythia_buf_t transformation_private_key_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformation_private_key);

    pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformed_password);
    pythia_buf_t transformed_tweak_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(transformed_tweak);

    if (0 != pythia_w_transform(&blinded_password_buf, &tweak_buf, &transformation_private_key_buf,
                     &transformed_password_buf, &transformed_tweak_buf)) {

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(transformed_password, transformed_password_buf.len);
    vsc_buffer_inc_used(transformed_tweak, transformed_tweak_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Generates proof that server possesses secret values that were used to transform password.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_prove(vscp_pythia_t *self, vsc_data_t transformed_password, vsc_data_t blinded_password,
        vsc_data_t transformed_tweak, vsc_data_t transformation_private_key, vsc_data_t transformation_public_key,
        vsc_buffer_t *proof_value_c, vsc_buffer_t *proof_value_u) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinded_password.bytes);
    VSCP_ASSERT_PTR(transformed_tweak.bytes);
    VSCP_ASSERT_PTR(transformation_private_key.bytes);
    VSCP_ASSERT_PTR(transformation_public_key.bytes);
    VSCP_ASSERT_PTR(proof_value_c);
    VSCP_ASSERT_PTR(proof_value_u);

    VSCP_ASSERT(vsc_buffer_unused_len(proof_value_c) >= vscp_pythia_proof_value_buf_len());
    VSCP_ASSERT(vsc_buffer_unused_len(proof_value_u) >= vscp_pythia_proof_value_buf_len());

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

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(proof_value_c, proof_value_c_buf.len);
    vsc_buffer_inc_used(proof_value_u, proof_value_u_buf.len);

    return vscp_status_SUCCESS;
}

//
//  This operation allows client to verify that the output of transform() is correct,
//  assuming that client has previously stored transformation public key.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_verify(vscp_pythia_t *self, vsc_data_t transformed_password, vsc_data_t blinded_password, vsc_data_t tweak,
        vsc_data_t transformation_public_key, vsc_data_t proof_value_c, vsc_data_t proof_value_u) {

    VSCP_ASSERT_PTR(self);
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

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    if (0 == verified) {
        return vscp_status_ERROR_VERIFICATION_FAIL;
    }

    return vscp_status_SUCCESS;
}

//
//  Rotates old transformation key to new transformation key and generates 'password update token',
//  that can update 'deblinded password'(s).
//
//  This action should increment version of the 'pythia scope secret'.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_get_password_update_token(vscp_pythia_t *self, vsc_data_t previous_transformation_private_key,
        vsc_data_t new_transformation_private_key, vsc_buffer_t *password_update_token) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(previous_transformation_private_key.bytes);
    VSCP_ASSERT_PTR(new_transformation_private_key.bytes);
    VSCP_ASSERT_PTR(password_update_token);

    VSCP_ASSERT(vsc_buffer_unused_len(password_update_token) >= vscp_pythia_proof_value_buf_len());

    const pythia_buf_t previous_transformation_private_key_buf =
            VSCP_PYTHIA_BUFFER_FROM_DATA(previous_transformation_private_key);

    const pythia_buf_t new_transformation_private_key_buf =
            VSCP_PYTHIA_BUFFER_FROM_DATA(new_transformation_private_key);

    pythia_buf_t password_update_token_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(password_update_token);

    if (0 != pythia_w_get_password_update_token(&previous_transformation_private_key_buf,
                     &new_transformation_private_key_buf, &password_update_token_buf)) {

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(password_update_token, password_update_token_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Updates previously stored 'deblinded password' with 'password update token'.
//  After this call, 'transform()' called with new arguments will return corresponding values.
//
VSCP_PUBLIC vscp_status_t
vscp_pythia_update_deblinded_with_token(vscp_pythia_t *self, vsc_data_t deblinded_password,
        vsc_data_t password_update_token, vsc_buffer_t *updated_deblinded_password) {

    VSCP_ASSERT_PTR(self);
    VSCP_ASSERT_PTR(deblinded_password.bytes);
    VSCP_ASSERT_PTR(password_update_token.bytes);
    VSCP_ASSERT_PTR(updated_deblinded_password);

    VSCP_ASSERT(vsc_buffer_unused_len(updated_deblinded_password) >= vscp_pythia_deblinded_password_buf_len());

    const pythia_buf_t deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(deblinded_password);
    const pythia_buf_t password_update_token_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(password_update_token);

    pythia_buf_t updated_deblinded_password_buf = VSCP_PYTHIA_BUFFER_FROM_BUFFER(updated_deblinded_password);

    if (0 != pythia_w_update_deblinded_with_token(
                     &deblinded_password_buf, &password_update_token_buf, &updated_deblinded_password_buf)) {

        return vscp_status_ERROR_PYTHIA_INNER_FAIL;
    }

    vsc_buffer_inc_used(updated_deblinded_password, updated_deblinded_password_buf.len);

    return vscp_status_SUCCESS;
}

//
//  Callback for the pythia random.
//
static void
vscp_pythia_random_handler(byte *out, int out_len, void *ctx) {

    VSCP_UNUSED(ctx);
    int status = mbedtls_ctr_drbg_random(&g_rng, out, out_len);
    VSCP_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}
