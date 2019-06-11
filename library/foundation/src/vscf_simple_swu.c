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

#include "vscf_simple_swu.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_simple_swu_defs.h"
#include "vscf_sha512.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_simple_swu_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_simple_swu_init_ctx(vscf_simple_swu_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_simple_swu_cleanup_ctx(vscf_simple_swu_t *self);

//
//  Return size of 'vscf_simple_swu_t'.
//
VSCF_PUBLIC size_t
vscf_simple_swu_ctx_size(void) {

    return sizeof(vscf_simple_swu_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_simple_swu_init(vscf_simple_swu_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_simple_swu_t));

    self->refcnt = 1;

    vscf_simple_swu_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_simple_swu_cleanup(vscf_simple_swu_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_simple_swu_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_simple_swu_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_simple_swu_t *
vscf_simple_swu_new(void) {

    vscf_simple_swu_t *self = (vscf_simple_swu_t *) vscf_alloc(sizeof (vscf_simple_swu_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_simple_swu_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_simple_swu_delete(vscf_simple_swu_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0 || (new_counter == old_counter)) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_simple_swu_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_simple_swu_new ()'.
//
VSCF_PUBLIC void
vscf_simple_swu_destroy(vscf_simple_swu_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_simple_swu_t *self = *self_ref;
    *self_ref = NULL;

    vscf_simple_swu_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_simple_swu_t *
vscf_simple_swu_shallow_copy(vscf_simple_swu_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_simple_swu_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_simple_swu_init_ctx(vscf_simple_swu_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->group);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->a);
    mbedtls_status = mbedtls_mpi_sub_int(&self->a, &self->group.P, 3);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->two);
    mbedtls_status = mbedtls_mpi_lset(&self->two, 2);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->three);
    mbedtls_status = mbedtls_mpi_lset(&self->three, 3);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->p34);
    mbedtls_status = mbedtls_mpi_copy(&self->p34, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_int(&self->p34, &self->p34, 3);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_div_int(&self->p34, NULL, &self->p34, 4);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->p14);
    mbedtls_status = mbedtls_mpi_copy(&self->p14, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_int(&self->p14, &self->p14, 1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_div_int(&self->p14, NULL, &self->p14, 4);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi_init(&self->mba);
    mbedtls_status = mbedtls_mpi_inv_mod(&self->mba, &self->a, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&self->mba, &self->mba, &self->group.B);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_mpi(&self->mba, &self->group.P, &self->mba);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_simple_swu_cleanup_ctx(vscf_simple_swu_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_mpi_free(&self->a);
    mbedtls_ecp_group_free(&self->group);
    mbedtls_mpi_free(&self->two);
    mbedtls_mpi_free(&self->three);
    mbedtls_mpi_free(&self->p34);
    mbedtls_mpi_free(&self->p14);
    mbedtls_mpi_free(&self->mba);
}

VSCF_PUBLIC void
vscf_simple_swu_bignum_to_point(vscf_simple_swu_t *self, const mbedtls_mpi *t, mbedtls_ecp_point *p) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(t);
    VSCF_ASSERT_PTR(p);

    mbedtls_mpi alpha;
    mbedtls_mpi_init(&alpha);

    mbedtls_mpi R;
    mbedtls_mpi_init(&R);

    //   alpha = -t^2
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_exp_mod(&alpha, t, &self->two, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_sub_mpi(&alpha, &self->group.P, &alpha);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
    mbedtls_mpi x2;
    mbedtls_mpi_init(&x2);

    mbedtls_status = mbedtls_mpi_copy(&x2, &alpha);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_exp_mod(&x2, &x2, &self->two, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&x2, &x2, &alpha);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_inv_mod(&x2, &x2, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_int(&x2, &x2, 1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&x2, &x2, &self->mba);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&x2, &x2, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    x3 = alpha * x2
    mbedtls_mpi x3;
    mbedtls_mpi_init(&x3);
    mbedtls_status = mbedtls_mpi_mul_mpi(&x3, &alpha, &x2);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&x3, &x3, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    h2 = x2^3 + a*x2 + b
    mbedtls_mpi h2;
    mbedtls_mpi_init(&h2);
    mbedtls_status = mbedtls_mpi_exp_mod(&h2, &x2, &self->three, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi h2_temp;
    mbedtls_mpi_init(&h2_temp);
    mbedtls_status = mbedtls_mpi_mul_mpi(&h2_temp, &x2, &self->a);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h2_temp, &h2_temp, &self->group.B);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h2, &h2, &h2_temp);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&h2, &h2, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    h3 = x3^3 + a*x3 + b
    mbedtls_mpi h3;
    mbedtls_mpi_init(&h3);
    mbedtls_status = mbedtls_mpi_exp_mod(&h3, &x3, &self->three, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    mbedtls_mpi h3_temp;
    mbedtls_mpi_init(&h3_temp);
    mbedtls_status = mbedtls_mpi_mul_mpi(&h3_temp, &x3, &self->a);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h3_temp, &h3_temp, &self->group.B);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_add_mpi(&h3, &h3, &h3_temp);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&h3, &h3, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    tmp = h2 ^ ((p - 3) // 4)
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_status = mbedtls_mpi_exp_mod(&tmp, &h2, &self->p34, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    //    if tmp^2 * h2 == 1:
    mbedtls_mpi tmp22h2;
    mbedtls_mpi_init(&tmp22h2);
    mbedtls_status = mbedtls_mpi_copy(&tmp22h2, &tmp);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_exp_mod(&tmp22h2, &tmp22h2, &self->two, &self->group.P, &R);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mul_mpi(&tmp22h2, &tmp22h2, &h2);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    mbedtls_status = mbedtls_mpi_mod_mpi(&tmp22h2, &tmp22h2, &self->group.P);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    if (mbedtls_mpi_cmp_int(&tmp22h2, 1) == 0) {
        //    return (x2, tmp * h2)
        mbedtls_status = mbedtls_mpi_copy(&p->X, &x2);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_mul_mpi(&p->Y, &tmp, &h2);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_mod_mpi(&p->Y, &p->Y, &self->group.P);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    } else {
        //    return (x3, h3 ^ ((p+1)//4))
        mbedtls_status = mbedtls_mpi_copy(&p->X, &x3);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        mbedtls_status = mbedtls_mpi_exp_mod(&p->Y, &h3, &self->p14, &self->group.P, &R);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    }

    mbedtls_status = mbedtls_mpi_lset(&p->Z, 1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

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

VSCF_PUBLIC void
vscf_simple_swu_data_to_point(vscf_simple_swu_t *self, vsc_data_t data, mbedtls_ecp_point *p) {

    VSCF_ASSERT_PTR(self);

    byte buffer[vscf_sha512_DIGEST_LEN];
    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    vscf_sha512_hash(data, &buff);

    mbedtls_mpi t;
    mbedtls_mpi_init(&t);

    vsc_data_t buff_data = vsc_data_slice_beg(vsc_buffer_data(&buff), 0, vscf_simple_swu_HASH_LEN);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&t, buff_data.bytes, buff_data.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vscf_simple_swu_bignum_to_point(self, &t, p);

    mbedtls_mpi_free(&t);
    vsc_buffer_delete(&buff);
    vscf_zeroize(buffer, sizeof(buffer));
}
