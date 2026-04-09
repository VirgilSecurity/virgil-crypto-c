//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Provide method to write type 'mbedtls_mpi' ASN.1 INTEGER.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1_tag.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_mbedtls_bignum_asn1_writer_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_mbedtls_bignum_asn1_writer_init_ctx(vscf_mbedtls_bignum_asn1_writer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_mbedtls_bignum_asn1_writer_cleanup_ctx(vscf_mbedtls_bignum_asn1_writer_t *self);

//
//  Return size of 'vscf_mbedtls_bignum_asn1_writer_t'.
//
VSCF_PUBLIC size_t
vscf_mbedtls_bignum_asn1_writer_ctx_size(void) {

    return sizeof(vscf_mbedtls_bignum_asn1_writer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_mbedtls_bignum_asn1_writer_init(vscf_mbedtls_bignum_asn1_writer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_bignum_asn1_writer_t));

    self->refcnt = 1;

    vscf_mbedtls_bignum_asn1_writer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_mbedtls_bignum_asn1_writer_cleanup(vscf_mbedtls_bignum_asn1_writer_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_mbedtls_bignum_asn1_writer_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vscf_mbedtls_bignum_asn1_writer_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_mbedtls_bignum_asn1_writer_t *
vscf_mbedtls_bignum_asn1_writer_new(void) {

    vscf_mbedtls_bignum_asn1_writer_t *self = (vscf_mbedtls_bignum_asn1_writer_t *) vsc_alloc(sizeof (vscf_mbedtls_bignum_asn1_writer_t));
    VSC_ASSERT_ALLOC(self);

    vscf_mbedtls_bignum_asn1_writer_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_mbedtls_bignum_asn1_writer_delete(vscf_mbedtls_bignum_asn1_writer_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_mbedtls_bignum_asn1_writer_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_mbedtls_bignum_asn1_writer_new ()'.
//
VSCF_PUBLIC void
vscf_mbedtls_bignum_asn1_writer_destroy(vscf_mbedtls_bignum_asn1_writer_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_mbedtls_bignum_asn1_writer_t *self = *self_ref;
    *self_ref = NULL;

    vscf_mbedtls_bignum_asn1_writer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_mbedtls_bignum_asn1_writer_t *
vscf_mbedtls_bignum_asn1_writer_shallow_copy(vscf_mbedtls_bignum_asn1_writer_t *self) {

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
//  Write given MbedTLS big number as ASN.1 INTEGER type.
//  Returns size of written data.
//
VSCF_PUBLIC size_t
vscf_mbedtls_bignum_write_asn1(vscf_impl_t *asn1wr, const mbedtls_mpi *bignum) {

    VSCF_ASSERT_PTR(bignum);
    VSCF_ASSERT_PTR(asn1wr);

    size_t bignum_len = mbedtls_mpi_size(bignum);
    byte *bignum_start = vscf_asn1_writer_reserve(asn1wr, bignum_len);

    if (vscf_asn1_writer_has_error(asn1wr)) {
        return 0;
    }

    int mpi_ret = mbedtls_mpi_write_binary(bignum, bignum_start, bignum_len);
    VSCF_ASSERT_OPT(0 == mpi_ret);

    //   if number is positive, but most left bit is one, then prepend it with zero byte
    if (1 == bignum->s && *bignum_start & 0x80) {
        bignum_start = vscf_asn1_writer_reserve(asn1wr, 1);

        if (vscf_asn1_writer_has_error(asn1wr)) {
            return 0;
        }

        *bignum_start = 0x00;
        bignum_len += 1;
    }

    size_t asn1_len = bignum_len;

    asn1_len += vscf_asn1_writer_write_len(asn1wr, bignum_len);
    asn1_len += vscf_asn1_writer_write_tag(asn1wr, vscf_asn1_tag_INTEGER);

    return asn1_len;
}
