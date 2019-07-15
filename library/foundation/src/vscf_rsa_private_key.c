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
//  This module contains 'rsa private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_rsa_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_simple_alg_info.h"
#include "vscf_rsa_private_key_defs.h"
#include "vscf_rsa_private_key_internal.h"

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
//  Note, this method is called automatically when method vscf_rsa_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_rsa_private_key_init_ctx(vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    self->impl_tag = vscf_impl_tag_RSA;
    mbedtls_rsa_init(&self->rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_NONE);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_rsa_private_key_cleanup_ctx(vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->alg_info);
    mbedtls_rsa_free(&self->rsa_ctx);
}

//
//  Import public key from the raw binary format.
//
//  RSAPrivateKey ::= SEQUENCE {
//       version Version,
//       modulus INTEGER, -- n
//       publicExponent INTEGER, -- e
//       privateExponent INTEGER, -- d
//       prime1 INTEGER, -- p
//       prime2 INTEGER, -- q
//       exponent1 INTEGER, -- d mod (p-1)
//       exponent2 INTEGER, -- d mod (q-1)
//       coefficient INTEGER -- (inverse of q) mod p
//   }
//
VSCF_PRIVATE vscf_status_t
vscf_rsa_private_key_import(vscf_rsa_private_key_t *self, const vscf_raw_private_key_t *raw_private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(raw_private_key));

    vscf_impl_destroy(&self->alg_info);
    //  TODO: Remove type cast when extend "const" semantic will be implemented.
    self->alg_info = vscf_impl_shallow_copy((vscf_impl_t *)vscf_raw_private_key_alg_info(raw_private_key));

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);

    // start
    vscf_asn1rd_reset(&asn1rd, vscf_raw_private_key_data(raw_private_key));
    vscf_asn1rd_read_sequence(&asn1rd);

    // version
    int version = vscf_asn1rd_read_int(&asn1rd);
    if (version != 0) {
        vscf_asn1rd_cleanup(&asn1rd);
        return vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY;
    }

    // modulus
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.N);

    // publicExponent
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.E);

    // privateExponent
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.D);

    // prime1
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.P);

    // prime2
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), &self->rsa_ctx.Q);

    const bool has_parse_error = vscf_asn1rd_has_error(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (has_parse_error) {
        return vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY;
    }

    /* Complete the RSA private key */
    self->rsa_ctx.len = mbedtls_mpi_size(&self->rsa_ctx.N);

    if (mbedtls_rsa_complete(&self->rsa_ctx) != 0 || mbedtls_rsa_check_privkey(&self->rsa_ctx) != 0) {
        return vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY;
    }

    return vscf_status_SUCCESS;
}

//
//  Export public key in the raw binary format.
//
//  RSAPrivateKey ::= SEQUENCE {
//       version Version,
//       modulus INTEGER, -- n
//       publicExponent INTEGER, -- e
//       privateExponent INTEGER, -- d
//       prime1 INTEGER, -- p
//       prime2 INTEGER, -- q
//       exponent1 INTEGER, -- d mod (p-1)
//       exponent2 INTEGER, -- d mod (q-1)
//       coefficient INTEGER -- (inverse of q) mod p
//   }
//
VSCF_PRIVATE vscf_raw_private_key_t *
vscf_rsa_private_key_export(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_SAFE(vscf_rsa_private_key_is_valid(self));

    const size_t key_len = vscf_rsa_private_key_len(self);

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);

    //
    //  Export public key
    //
    const size_t pub_out_capacity = 1 + 2 + 3 + 4 + 4 + key_len;
    vsc_buffer_t *pub_out = vsc_buffer_new_with_capacity(pub_out_capacity);

    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(pub_out), pub_out_capacity);

    size_t pub_out_len = 0;

    pub_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.E);
    pub_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.N);
    pub_out_len += vscf_asn1wr_write_sequence(&asn1wr, pub_out_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(pub_out));
    vsc_buffer_inc_used(pub_out, pub_out_len);

    vscf_impl_t *alg_info_copy = vscf_impl_shallow_copy(self->alg_info);
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_buffer(&pub_out, &alg_info_copy);

    //
    //  Export private key
    //
    const size_t top_tag_and_len = 4;
    const size_t version = 3;
    const size_t modulus = 5;
    const size_t int_tag_plus_len_plus_padding = 1 + 4 + 1;
    const size_t priv_out_capacity = top_tag_and_len + version + modulus +
                                     5 * (int_tag_plus_len_plus_padding + (key_len >> 1)) +
                                     2 * (int_tag_plus_len_plus_padding + key_len);

    vsc_buffer_t *priv_out = vsc_buffer_new_with_capacity(priv_out_capacity);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(priv_out), priv_out_capacity);
    size_t priv_out_len = 0;

    // Write QP - 1 / (Q % P)
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.QP);

    // Write DQ - D % (Q - 1)
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.DQ);

    // Write DP - D % (P - 1)
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.DP);

    // Write Q - The second prime factor
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.Q);

    // Write P - The first prime factor
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.P);

    // Write D - The private exponent
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.D);

    // Write E - The public exponent
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.E);

    // Write N - The public modulus
    priv_out_len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), &self->rsa_ctx.N);

    // Write version (0)
    priv_out_len += vscf_asn1wr_write_int(&asn1wr, 0);

    priv_out_len += vscf_asn1wr_write_sequence(&asn1wr, priv_out_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(priv_out));
    vsc_buffer_inc_used(priv_out, priv_out_len);

    vscf_impl_t *priv_alg_info = vscf_impl_shallow_copy(self->alg_info);
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_buffer(&priv_out, &priv_alg_info);
    vscf_raw_private_key_set_public_key(raw_private_key, &raw_public_key);

    return raw_private_key;
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_private_key_alg_id(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return vscf_alg_info_alg_id(self->alg_info);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_rsa_private_key_alg_info(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_len(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_bitlen(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return 8 * mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_rsa_private_key_impl_tag(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->impl_tag;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_rsa_private_key_is_valid(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (vscf_impl_tag_BEGIN == self->impl_tag) {
        return false;
    }

    return mbedtls_rsa_check_privkey(&self->rsa_ctx) == 0;
}

//
//  Extract public key from the private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_extract_public_key(const vscf_rsa_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);
    VSCF_ASSERT_SAFE(vscf_rsa_private_key_is_valid(self));

    vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();

    const int copy_n_ret = mbedtls_mpi_copy(&rsa_public_key->rsa_ctx.N, &self->rsa_ctx.N);
    const int copy_e_ret = mbedtls_mpi_copy(&rsa_public_key->rsa_ctx.E, &self->rsa_ctx.E);

    VSCF_ASSERT_ALLOC((copy_n_ret == 0) && (copy_e_ret == 0));

    rsa_public_key->rsa_ctx.len = self->rsa_ctx.len;
    rsa_public_key->alg_info = vscf_impl_shallow_copy(self->alg_info);
    rsa_public_key->impl_tag = self->impl_tag;

    return vscf_rsa_public_key_impl(rsa_public_key);
}
