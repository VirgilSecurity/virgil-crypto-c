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

#define VSCP_PYTHIA_BUFFER_FROM_DATA(X) {.p = (uint8_t *)X.bytes, .allocated = X.len, .len = X.len}

//
//  Callback for the pythia random.
//
static void
vscp_pythia_random_handler(byte* out, int out_len, void* ctx);

//
//  Allocate context and perform it's initialization.
//
VSCP_PUBLIC vscp_pythia_t*
vscp_pythia_new(void) {

    vscp_pythia_t *pythia_ctx = (vscp_pythia_t *) vscp_alloc(sizeof (vscp_pythia_t));
    if (NULL == pythia_ctx) {
        return NULL;
    }

    if (vscp_pythia_init(pythia_ctx) != vscp_SUCCESS) {
        vscp_dealloc(pythia_ctx);
        return NULL;
    }

    pythia_ctx->self_dealloc_cb = vscp_dealloc;

    return pythia_ctx;
}

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCP_PUBLIC void
vscp_pythia_delete(vscp_pythia_t* pythia_ctx) {

    if (NULL == pythia_ctx) {
        return;
    }

    vscp_pythia_cleanup(pythia_ctx);

    if (pythia_ctx->self_dealloc_cb != NULL) {
         pythia_ctx->self_dealloc_cb(pythia_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscp_pythia_new ()'.
//
VSCP_PUBLIC void
vscp_pythia_destroy(vscp_pythia_t** pythia_ctx_ref) {

    VSCP_ASSERT_PTR(pythia_ctx_ref);

    vscp_pythia_t *pythia_ctx = *pythia_ctx_ref;
    *pythia_ctx_ref = NULL;

    vscp_pythia_delete(pythia_ctx);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform initialization of pre-allocated context.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_init(vscp_pythia_t *pythia_ctx) {

    VSCP_ASSERT_PTR(pythia_ctx);

    if (g_instances++ > 0) {
        return vscp_SUCCESS;
    }

    mbedtls_entropy_init(&g_entropy_ctx);
    mbedtls_ctr_drbg_init(&g_rng_ctx);

    const unsigned char pers[] = "vscp_pythia";
    size_t pers_len = sizeof(pers);
    VSCP_ASSERT_OPT(0 == mbedtls_ctr_drbg_seed(&g_rng_ctx, mbedtls_entropy_func, &g_entropy_ctx, pers, pers_len));

    return vscp_SUCCESS;
}

//
//  Release all inner resources.
//
VSCP_PUBLIC void
vscp_pythia_cleanup(vscp_pythia_t *pythia_ctx) {

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
//  Blinds password. Turns password into a pseudo-random string.
//  This step is necessary to prevent 3rd-parties from knowledge of end user's password.
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_blind(vscp_pythia_t *pythia_ctx, const vsc_data_t password, vsc_buffer_t *blinded_password,
        vsc_buffer_t *blinding_secret) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(password.bytes);
    VSCP_ASSERT_PTR(blinded_password);
    VSCP_ASSERT_PTR(blinding_secret);

    VSCP_ASSERT(vsc_buffer_capacity(blinded_password) >= vscp_pythia_blinded_password_buf_len());
    VSCP_ASSERT(vsc_buffer_capacity(blinding_secret) >= vscp_pythia_blinding_secret_buf_len());


    const pythia_buf_t password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(password);


    if (0 != pythia_w_blind(&password_buf, (pythia_buf_t *)blinded_password, (pythia_buf_t *)blinding_secret)) {
        return vscp_error_PYTHIA_INNER_FAIL;
    }

    return vscp_SUCCESS;
}

//
//  Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
//
VSCP_PUBLIC vscp_error_t
vscp_pythia_deblind(vscp_pythia_t *pythia_ctx, const vsc_data_t transformed_password, const vsc_data_t blinding_secret,
        vsc_buffer_t *deblinded_password) {

    VSCP_ASSERT_PTR(pythia_ctx);
    VSCP_ASSERT_PTR(transformed_password.bytes);
    VSCP_ASSERT_PTR(blinding_secret.bytes);

    VSCP_ASSERT(vsc_buffer_capacity(deblinded_password) >= vscp_pythia_deblinded_password_buf_len());


    const pythia_buf_t transformed_password_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(transformed_password);
    const pythia_buf_t blinding_secret_buf = VSCP_PYTHIA_BUFFER_FROM_DATA(blinding_secret);


    if (0 != pythia_w_deblind(&transformed_password_buf, &blinding_secret_buf, (pythia_buf_t *)deblinded_password)) {
        return vscp_error_PYTHIA_INNER_FAIL;
    }

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
