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
//  This module contains 'rsa public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_rsa_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_rsa_public_key_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return public key exponent.
//
static size_t
vscf_rsa_public_key_key_exponent(vscf_rsa_public_key_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_rsa_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_rsa_public_key_init_ctx(vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_rsa_init(&self->rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_NONE);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_rsa_public_key_cleanup_ctx(vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_rsa_free(&self->rsa_ctx);
}

//
//  Return public key exponent.
//
static size_t
vscf_rsa_public_key_key_exponent(vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1wr);
    VSCF_ASSERT_PTR(self->asn1rd);

    vscf_error_t error;
    vscf_error_reset(&error);

    byte exponent_asn1[10] = {0x00};
    vscf_asn1_writer_reset(self->asn1wr, exponent_asn1, sizeof(exponent_asn1));
    vscf_mbedtls_bignum_write_asn1(self->asn1wr, &self->rsa_ctx.E, &error);
    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1wr));
    VSCF_ASSERT(!vscf_error_has_error(&error));

    vscf_asn1_reader_reset(self->asn1rd, vsc_data(exponent_asn1, sizeof(exponent_asn1)));
    const size_t exponent = vscf_asn1_reader_read_uint(self->asn1rd);
    VSCF_ASSERT(!vscf_asn1_reader_has_error(self->asn1rd));

    return exponent;
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_public_key_alg_id(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_RSA;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_len(const vscf_rsa_public_key_t *self) {

    //  TODO: This is STUB. Implement me.
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_bitlen(const vscf_rsa_public_key_t *self) {

    //  TODO: This is STUB. Implement me.
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_rsa_public_key_impl_tag(const vscf_rsa_public_key_t *self) {

    //  TODO: This is STUB. Implement me.
}
