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

#include "vsce_phe_hash.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_hash_defs.h"

#include <virgil/crypto/foundation/vscf_sha512.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *phe_hash_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *phe_hash_ctx);

//
//  Return size of 'vsce_phe_hash_t'.
//
VSCE_PUBLIC size_t
vsce_phe_hash_ctx_size(void) {

    return sizeof(vsce_phe_hash_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_hash_init(vsce_phe_hash_t *phe_hash_ctx) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    vsce_zeroize(phe_hash_ctx, sizeof(vsce_phe_hash_t));

    phe_hash_ctx->refcnt = 1;

    vsce_phe_hash_init_ctx(phe_hash_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_hash_cleanup(vsce_phe_hash_t *phe_hash_ctx) {

    if (phe_hash_ctx == NULL) {
        return;
    }

    if (phe_hash_ctx->refcnt == 0) {
        return;
    }

    if (--phe_hash_ctx->refcnt == 0) {
        vsce_phe_hash_cleanup_ctx(phe_hash_ctx);

        vsce_phe_hash_release_simple_swu(phe_hash_ctx);

        vsce_zeroize(phe_hash_ctx, sizeof(vsce_phe_hash_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_new(void) {

    vsce_phe_hash_t *phe_hash_ctx = (vsce_phe_hash_t *) vsce_alloc(sizeof (vsce_phe_hash_t));
    VSCE_ASSERT_ALLOC(phe_hash_ctx);

    vsce_phe_hash_init(phe_hash_ctx);

    phe_hash_ctx->self_dealloc_cb = vsce_dealloc;

    return phe_hash_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_hash_delete(vsce_phe_hash_t *phe_hash_ctx) {

    if (phe_hash_ctx == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_hash_ctx->self_dealloc_cb;

    vsce_phe_hash_cleanup(phe_hash_ctx);

    if (phe_hash_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_hash_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_hash_new ()'.
//
VSCE_PUBLIC void
vsce_phe_hash_destroy(vsce_phe_hash_t **phe_hash_ctx_ref) {

    VSCE_ASSERT_PTR(phe_hash_ctx_ref);

    vsce_phe_hash_t *phe_hash_ctx = *phe_hash_ctx_ref;
    *phe_hash_ctx_ref = NULL;

    vsce_phe_hash_delete(phe_hash_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_copy(vsce_phe_hash_t *phe_hash_ctx) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    ++phe_hash_ctx->refcnt;

    return phe_hash_ctx;
}

//
//  Setup dependency to the class 'simple swu' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_hash_use_simple_swu(vsce_phe_hash_t *phe_hash_ctx, vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(simple_swu);
    VSCE_ASSERT_PTR(phe_hash_ctx->simple_swu == NULL);

    phe_hash_ctx->simple_swu = vsce_simple_swu_copy(simple_swu);
}

//
//  Setup dependency to the class 'simple swu' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_hash_take_simple_swu(vsce_phe_hash_t *phe_hash_ctx, vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(simple_swu);
    VSCE_ASSERT_PTR(phe_hash_ctx->simple_swu == NULL);

    phe_hash_ctx->simple_swu = simple_swu;
}

//
//  Release dependency to the class 'simple swu'.
//
VSCE_PUBLIC void
vsce_phe_hash_release_simple_swu(vsce_phe_hash_t *phe_hash_ctx) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    vsce_simple_swu_destroy(&phe_hash_ctx->simple_swu);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *phe_hash_ctx) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    vsce_phe_hash_take_simple_swu(phe_hash_ctx, vsce_simple_swu_new());
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *phe_hash_ctx) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    //  TODO: Release all inner resources.
}

VSCE_PUBLIC vsce_error_t
vsce_phe_hash_data_to_point(vsce_phe_hash_t *phe_hash_ctx, vsc_data_t data, mbedtls_ecp_point *p) {

    VSCE_ASSERT_PTR(phe_hash_ctx);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_hash(data, buffer);

    mbedtls_mpi t;
    mbedtls_mpi_init(&t);

    vsc_data_t buff_data = vsc_data_slice_beg(vsc_buffer_data(buffer), 0, vsce_simple_swu_HASH_LEN);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&t, buff_data.bytes, buff_data.len);
    VSCE_ASSERT(mbedtls_status == 0);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_simple_swu_bignum_to_point(phe_hash_ctx->simple_swu, &t, p);
    VSCE_ASSERT(status == vsce_SUCCESS);

    mbedtls_mpi_free(&t);
    vsc_buffer_destroy(&buffer);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_hash_hc0(vsce_phe_hash_t *phe_hash_ctx, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc0) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(hc0);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    char hc0_domain[] = "dhco";

    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(sizeof(hc0_domain)
            + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len);
    vsc_buffer_make_secure(buff);

    memcpy(vsc_buffer_ptr(buff), hc0_domain, sizeof(hc0_domain));
    vsc_buffer_reserve(buff, sizeof(hc0_domain));

    memcpy(vsc_buffer_ptr(buff), nc.bytes, nc.len);
    vsc_buffer_reserve(buff, nc.len);

    memcpy(vsc_buffer_ptr(buff), password.bytes, password.len);
    vsc_buffer_reserve(buff, password.len);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_data_to_point(phe_hash_ctx, vsc_buffer_data(buff), hc0);
    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_destroy(&buff);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_hash_hc1(vsce_phe_hash_t *phe_hash_ctx, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc1) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(hc1);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    char hc1_domain[] = "dhc1";

    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(sizeof(hc1_domain)
            + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len);
    vsc_buffer_make_secure(buff);

    memcpy(vsc_buffer_ptr(buff), hc1_domain, sizeof(hc1_domain));
    vsc_buffer_reserve(buff, sizeof(hc1_domain));

    memcpy(vsc_buffer_ptr(buff), nc.bytes, nc.len);
    vsc_buffer_reserve(buff, nc.len);

    memcpy(vsc_buffer_ptr(buff), password.bytes, password.len);
    vsc_buffer_reserve(buff, password.len);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_data_to_point(phe_hash_ctx, vsc_buffer_data(buff), hc1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_destroy(&buff);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_hash_hs0(vsce_phe_hash_t *phe_hash_ctx, vsc_data_t ns, mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(hs0);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    char hs0_domain[] = "dhs0";

    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(sizeof(hs0_domain)
            + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    memcpy(vsc_buffer_ptr(buff), hs0_domain, sizeof(hs0_domain));
    vsc_buffer_reserve(buff, sizeof(hs0_domain));

    memcpy(vsc_buffer_ptr(buff), ns.bytes, ns.len);
    vsc_buffer_reserve(buff, ns.len);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_data_to_point(phe_hash_ctx, vsc_buffer_data(buff), hs0);
    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_destroy(&buff);

    return vsce_SUCCESS;
}

VSCE_PUBLIC vsce_error_t
vsce_phe_hash_hs1(vsce_phe_hash_t *phe_hash_ctx, vsc_data_t ns, mbedtls_ecp_point *hs1) {

    VSCE_ASSERT_PTR(phe_hash_ctx);
    VSCE_ASSERT_PTR(hs1);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    char hs1_domain[] = "dhs1";

    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(sizeof(hs1_domain)
            + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    memcpy(vsc_buffer_ptr(buff), hs1_domain, sizeof(hs1_domain));
    vsc_buffer_reserve(buff, sizeof(hs1_domain));

    memcpy(vsc_buffer_ptr(buff), ns.bytes, ns.len);
    vsc_buffer_reserve(buff, ns.len);

    vsce_error_t status = vsce_SUCCESS;
    status = vsce_phe_hash_data_to_point(phe_hash_ctx, vsc_buffer_data(buff), hs1);
    VSCE_ASSERT(status == vsce_SUCCESS);

    vsc_buffer_destroy(&buff);

    return vsce_SUCCESS;
}
