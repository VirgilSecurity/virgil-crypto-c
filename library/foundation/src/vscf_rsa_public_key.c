//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_simple_alg_info.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_rsa_public_key_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


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

    vscf_impl_destroy(&self->alg_info);
    mbedtls_rsa_free(&self->rsa_ctx);
}

//
//  Return public key exponent.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_exponent(vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_SAFE(vscf_rsa_public_key_is_valid(self));

    byte exponent_asn1[2 + 8] = {0x00};

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, exponent_asn1, sizeof(exponent_asn1));

    vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.E);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_cleanup(&asn1wr);

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);

    vscf_asn1rd_reset(&asn1rd, vsc_data(exponent_asn1, sizeof(exponent_asn1)));
    const size_t exponent = vscf_asn1rd_read_uint(&asn1rd);
    VSCF_ASSERT(!vscf_asn1rd_has_error(&asn1rd));
    vscf_asn1rd_cleanup(&asn1rd);

    return exponent;
}

//
//  Import public key from the raw binary format.
//
//  RSAPublicKey ::= SEQUENCE {
//      modulus INTEGER, -- n
//      publicExponent INTEGER -- e
//  }
//
VSCF_PRIVATE vscf_status_t
vscf_rsa_public_key_import(vscf_rsa_public_key_t *self, const vscf_raw_public_key_t *raw_public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(raw_public_key));

    vscf_impl_destroy(&self->alg_info);
    //  TODO: Remove type cast when extend "const" semantic will be implemented.
    self->alg_info = vscf_impl_shallow_copy((vscf_impl_t *)vscf_raw_public_key_alg_info(raw_public_key));

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);

    vscf_asn1rd_reset(&asn1rd, vscf_raw_public_key_data(raw_public_key));

    // start
    vscf_asn1rd_read_sequence(&asn1rd);

    // modulus
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.N);

    // exponent
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.E);

    const bool has_parse_error = vscf_asn1rd_has_error(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (has_parse_error) {
        return vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY;
    }

    self->rsa_ctx.len = mbedtls_mpi_size(&self->rsa_ctx.N);

    if (mbedtls_rsa_complete(&self->rsa_ctx) != 0 || mbedtls_rsa_check_pubkey(&self->rsa_ctx) != 0) {
        return vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY;
    }

    return vscf_status_SUCCESS;
}

//
//  Export public key in the raw binary format.
//
//  RSAPublicKey ::= SEQUENCE {
//      modulus INTEGER, -- n
//      publicExponent INTEGER -- e
//  }
//
VSCF_PRIVATE vscf_raw_public_key_t *
vscf_rsa_public_key_export(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_SAFE(vscf_rsa_public_key_is_valid(self));

    const size_t out_len = 1 + 2 + 3 + 4 + 4 + vscf_rsa_public_key_len(self);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    size_t len = 0;

    len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.E);
    len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.N);
    len += vscf_asn1wr_write_sequence(&asn1wr, len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);

    vscf_impl_t *alg_info_copy = vscf_impl_shallow_copy(self->alg_info);
    return vscf_raw_public_key_new_with_buffer(&out, &alg_info_copy);
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_public_key_alg_id(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return vscf_alg_info_alg_id(self->alg_info);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_rsa_public_key_alg_info(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_len(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_bitlen(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return 8 * mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_rsa_public_key_impl_tag(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->impl_tag;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_rsa_public_key_is_valid(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (vscf_impl_tag_BEGIN == self->impl_tag) {
        return false;
    }

    return mbedtls_rsa_check_pubkey(&self->rsa_ctx) == 0;
}
