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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_simple_swu.h"
#include "vsce_memory.h"
#include "vsce_assert.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <virgil/crypto/foundation/vscf_sha512.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'simple swu' context.
//
struct vsce_simple_swu_t {
    //
    //  Function do deallocate self context.
    //
    vsce_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    mbedtls_ecp_group group;

    mbedtls_mpi a;

    mbedtls_mpi two;

    mbedtls_mpi three;

    mbedtls_mpi p34;

    mbedtls_mpi p14;

    mbedtls_mpi mba;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_simple_swu_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_simple_swu_init_ctx(vsce_simple_swu_t *simple_swu);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_simple_swu_cleanup_ctx(vsce_simple_swu_t *simple_swu);

//
//  Return size of 'vsce_simple_swu_t'.
//
VSCE_PUBLIC size_t
vsce_simple_swu_ctx_size(void) {

    return sizeof(vsce_simple_swu_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_simple_swu_init(vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(simple_swu);

    vsce_zeroize(simple_swu, sizeof(vsce_simple_swu_t));

    simple_swu->refcnt = 1;

    vsce_simple_swu_init_ctx(simple_swu);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_simple_swu_cleanup(vsce_simple_swu_t *simple_swu) {

    if (simple_swu == NULL) {
        return;
    }

    if (simple_swu->refcnt == 0) {
        return;
    }

    if (--simple_swu->refcnt == 0) {
        vsce_simple_swu_cleanup_ctx(simple_swu);

        vsce_zeroize(simple_swu, sizeof(vsce_simple_swu_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_simple_swu_t *
vsce_simple_swu_new(void) {

    vsce_simple_swu_t *simple_swu = (vsce_simple_swu_t *) vsce_alloc(sizeof (vsce_simple_swu_t));
    VSCE_ASSERT_ALLOC(simple_swu);

    vsce_simple_swu_init(simple_swu);

    simple_swu->self_dealloc_cb = vsce_dealloc;

    return simple_swu;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_simple_swu_delete(vsce_simple_swu_t *simple_swu) {

    if (simple_swu == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = simple_swu->self_dealloc_cb;

    vsce_simple_swu_cleanup(simple_swu);

    if (simple_swu->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(simple_swu);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_simple_swu_new ()'.
//
VSCE_PUBLIC void
vsce_simple_swu_destroy(vsce_simple_swu_t **simple_swu_ref) {

    VSCE_ASSERT_PTR(simple_swu_ref);

    vsce_simple_swu_t *simple_swu = *simple_swu_ref;
    *simple_swu_ref = NULL;

    vsce_simple_swu_delete(simple_swu);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_simple_swu_t *
vsce_simple_swu_shallow_copy(vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(simple_swu);

    ++simple_swu->refcnt;

    return simple_swu;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_simple_swu_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_simple_swu_init_ctx(vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(simple_swu);

    mbedtls_ecp_group_init(&simple_swu->group);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_group_load(&simple_swu->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->a);
    mbedtls_status = mbedtls_mpi_sub_int(&simple_swu->a, &simple_swu->group.P, 3);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->two);
    mbedtls_status = mbedtls_mpi_lset(&simple_swu->two, 2);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->three);
    mbedtls_status = mbedtls_mpi_lset(&simple_swu->three, 3);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->p34);
    mbedtls_status = mbedtls_mpi_copy(&simple_swu->p34, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_int(&simple_swu->p34, &simple_swu->p34, 3);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_div_int(&simple_swu->p34, NULL, &simple_swu->p34, 4);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->p14);
    mbedtls_status = mbedtls_mpi_copy(&simple_swu->p14, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_int(&simple_swu->p14, &simple_swu->p14, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_div_int(&simple_swu->p14, NULL, &simple_swu->p14, 4);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&simple_swu->mba);
    mbedtls_status = mbedtls_mpi_inv_mod(&simple_swu->mba, &simple_swu->a, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&simple_swu->mba, &simple_swu->mba, &simple_swu->group.B);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_mpi(&simple_swu->mba, &simple_swu->group.P, &simple_swu->mba);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_simple_swu_cleanup_ctx(vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(simple_swu);

    mbedtls_mpi_free(&simple_swu->a);
    mbedtls_ecp_group_free(&simple_swu->group);
    mbedtls_mpi_free(&simple_swu->two);
    mbedtls_mpi_free(&simple_swu->three);
    mbedtls_mpi_free(&simple_swu->p34);
    mbedtls_mpi_free(&simple_swu->p14);
    mbedtls_mpi_free(&simple_swu->mba);
}

VSCE_PUBLIC void
vsce_simple_swu_bignum_to_point(vsce_simple_swu_t *simple_swu, const mbedtls_mpi *t, mbedtls_ecp_point *p) {

    VSCE_ASSERT_PTR(simple_swu);
    VSCE_ASSERT_PTR(t);
    VSCE_ASSERT_PTR(p);

    mbedtls_mpi alpha;
    mbedtls_mpi_init(&alpha);

    mbedtls_mpi R;
    mbedtls_mpi_init(&R);

    //   alpha = -t^2
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_exp_mod(&alpha, t, &simple_swu->two, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_mpi(&alpha, &simple_swu->group.P, &alpha);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
    mbedtls_mpi x2;
    mbedtls_mpi_init(&x2);

    mbedtls_status = mbedtls_mpi_copy(&x2, &alpha);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_exp_mod(&x2, &x2, &simple_swu->two, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&x2, &x2, &alpha);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_inv_mod(&x2, &x2, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_int(&x2, &x2, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&x2, &x2, &simple_swu->mba);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&x2, &x2, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    x3 = alpha * x2
    mbedtls_mpi x3;
    mbedtls_mpi_init(&x3);
    mbedtls_status = mbedtls_mpi_mul_mpi(&x3, &alpha, &x2);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&x3, &x3, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    h2 = x2^3 + a*x2 + b
    mbedtls_mpi h2;
    mbedtls_mpi_init(&h2);
    mbedtls_status = mbedtls_mpi_exp_mod(&h2, &x2, &simple_swu->three, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi h2_temp;
    mbedtls_mpi_init(&h2_temp);
    mbedtls_status = mbedtls_mpi_mul_mpi(&h2_temp, &x2, &simple_swu->a);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h2_temp, &h2_temp, &simple_swu->group.B);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h2, &h2, &h2_temp);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&h2, &h2, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    h3 = x3^3 + a*x3 + b
    mbedtls_mpi h3;
    mbedtls_mpi_init(&h3);
    mbedtls_status = mbedtls_mpi_exp_mod(&h3, &x3, &simple_swu->three, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi h3_temp;
    mbedtls_mpi_init(&h3_temp);
    mbedtls_status = mbedtls_mpi_mul_mpi(&h3_temp, &x3, &simple_swu->a);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h3_temp, &h3_temp, &simple_swu->group.B);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h3, &h3, &h3_temp);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&h3, &h3, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    tmp = h2 ^ ((p - 3) // 4)
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_status = mbedtls_mpi_exp_mod(&tmp, &h2, &simple_swu->p34, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    if tmp^2 * h2 == 1:
    mbedtls_mpi tmp22h2;
    mbedtls_mpi_init(&tmp22h2);
    mbedtls_status = mbedtls_mpi_copy(&tmp22h2, &tmp);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_exp_mod(&tmp22h2, &tmp22h2, &simple_swu->two, &simple_swu->group.P, &R);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&tmp22h2, &tmp22h2, &h2);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&tmp22h2, &tmp22h2, &simple_swu->group.P);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_mpi_cmp_int(&tmp22h2, 1) == 0) {
        //    return (x2, tmp * h2)
        mbedtls_status = mbedtls_mpi_copy(&p->X, &x2);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_mul_mpi(&p->Y, &tmp, &h2);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_mod_mpi(&p->Y, &p->Y, &simple_swu->group.P);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    } else {
        //    return (x3, h3 ^ ((p+1)//4))
        mbedtls_status = mbedtls_mpi_copy(&p->X, &x3);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_exp_mod(&p->Y, &h3, &simple_swu->p14, &simple_swu->group.P, &R);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    }

    mbedtls_status = mbedtls_mpi_lset(&p->Z, 1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_free(&R);

    mbedtls_mpi_free(&alpha);
    mbedtls_mpi_free(&x2);
    mbedtls_mpi_free(&x3);
    mbedtls_mpi_free(&h2);
    mbedtls_mpi_free(&h2_temp);
    mbedtls_mpi_free(&h3);
    mbedtls_mpi_free(&h3_temp);
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&tmp22h2);
}
