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
#include "vscf_asn1.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_md.h"
#include "vscf_export_public_key.h"
#include "vscf_random.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_rsa_private_key_impl.h"
#include "vscf_rsa_private_key_internal.h"

#include <virgil/foundation/private/vscf_rsa_public_key_impl.h>
#include <mbedtls/bignum.h>
//  @end


typedef int (*mbedtls_random_cb)(void *, unsigned char *, size_t);


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
//
VSCF_PRIVATE void
vscf_rsa_private_key_init_ctx(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    mbedtls_rsa_init(&rsa_private_key_impl->rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_NONE);

    rsa_private_key_impl->gen_bitlen = 4096;
    rsa_private_key_impl->gen_exponent = 65537;
}

//
//  Provides cleanup of the implementation specific context.
//
VSCF_PRIVATE void
vscf_rsa_private_key_cleanup_ctx(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    mbedtls_rsa_free(&rsa_private_key_impl->rsa_ctx);
}

//
//  Setup parameters that is used during key generation.
//
VSCF_PUBLIC void
vscf_rsa_private_key_set_keygen_params(
        vscf_rsa_private_key_impl_t *rsa_private_key_impl, size_t bitlen, size_t exponent) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT(bitlen >= 128 && bitlen <= 16384);
    VSCF_ASSERT(bitlen % 2 == 0);
    VSCF_ASSERT(exponent >= 3);

    rsa_private_key_impl->gen_bitlen = bitlen;
    rsa_private_key_impl->gen_exponent = exponent;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    return mbedtls_rsa_get_len(&rsa_private_key_impl->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_bitlen(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    return 8 * mbedtls_rsa_get_len(&rsa_private_key_impl->rsa_ctx);
}

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_generate_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    int ret = mbedtls_rsa_gen_key(&rsa_private_key_impl->rsa_ctx, (mbedtls_random_cb)vscf_random,
            rsa_private_key_impl->random, rsa_private_key_impl->gen_bitlen, rsa_private_key_impl->gen_exponent);

    return ret == 0 ? vscf_SUCCESS : vscf_error_KEY_GENERATION_FAILED;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_extract_public_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT(mbedtls_rsa_check_pubkey(&rsa_private_key_impl->rsa_ctx) == 0);

    vscf_rsa_public_key_impl_t *rsa_public_key_impl = vscf_rsa_public_key_new();
    if (NULL == rsa_public_key_impl) {
        return NULL;
    }

    mbedtls_rsa_context *rsa_public_ctx = &rsa_public_key_impl->rsa_ctx;
    mbedtls_rsa_context *rsa_private_ctx = &rsa_private_key_impl->rsa_ctx;

    int copy_n_ret = mbedtls_mpi_copy(&rsa_public_ctx->N, &rsa_private_ctx->N);
    int copy_e_ret = mbedtls_mpi_copy(&rsa_public_ctx->E, &rsa_private_ctx->E);

    if ((0 != copy_n_ret) || (0 != copy_e_ret)) {
        vscf_rsa_public_key_destroy(&rsa_public_key_impl);
        return NULL;
    }

    rsa_public_ctx->len = rsa_private_ctx->len;

    if (rsa_private_key_impl->hash) {
        vscf_rsa_public_key_use_hash(rsa_public_key_impl, rsa_private_key_impl->hash);
    }

    if (rsa_private_key_impl->random) {
        vscf_rsa_public_key_use_random(rsa_public_key_impl, rsa_private_key_impl->random);
    }

    if (rsa_private_key_impl->asn1rd) {
        vscf_rsa_public_key_use_asn1_reader(rsa_public_key_impl, rsa_private_key_impl->asn1rd);
    }

    if (rsa_private_key_impl->asn1wr) {
        vscf_rsa_public_key_use_asn1_writer(rsa_public_key_impl, rsa_private_key_impl->asn1wr);
    }

    return vscf_rsa_public_key_impl(rsa_public_key_impl);
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_decrypt(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(rsa_private_key_impl->random);
    VSCF_ASSERT_PTR(rsa_private_key_impl->hash);
    VSCF_ASSERT_PTR(out);

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT_OPT(vsc_buffer_left(out) >= vscf_rsa_private_key_decrypted_len(rsa_private_key_impl, data.len));

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key_impl->rsa_ctx) == 0);

    if (data.len != vscf_rsa_private_key_key_len(rsa_private_key_impl)) {
        return vscf_error_BAD_ENCRYPTED_DATA;
    }

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_map_impl_tag(vscf_hash_impl_tag(rsa_private_key_impl->hash));
    mbedtls_rsa_set_padding(&rsa_private_key_impl->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    size_t out_len = 0;
    int ret = mbedtls_rsa_rsaes_oaep_decrypt(&rsa_private_key_impl->rsa_ctx, (mbedtls_random_cb)vscf_random,
            rsa_private_key_impl->random, MBEDTLS_RSA_PRIVATE, NULL, 0, &out_len, data.bytes, vsc_buffer_ptr(out),
            vsc_buffer_left(out));

    if (ret != 0) {
        return vscf_error_BAD_ENCRYPTED_DATA;
    }

    vsc_buffer_reserve(out, out_len);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_decrypted_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl, size_t data_len) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_UNUSED(data_len);

    return vscf_rsa_private_key_key_len(rsa_private_key_impl);
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_sign(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT_PTR(rsa_private_key_impl->random);
    VSCF_ASSERT_PTR(rsa_private_key_impl->hash);
    VSCF_ASSERT_PTR(signature);

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(signature));

    VSCF_ASSERT_OPT(vsc_buffer_left(signature) >= vscf_rsa_private_key_signature_len(rsa_private_key_impl));

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key_impl->rsa_ctx) == 0);

    //  Hash
    size_t data_hash_len = vscf_hash_info_digest_len(vscf_hash_hash_info_api(rsa_private_key_impl->hash));
    vsc_buffer_t *data_hash_buf = vsc_buffer_new_with_capacity(data_hash_len);
    VSCF_ASSERT_PTR(data_hash_buf);

    vscf_hash(rsa_private_key_impl->hash, data, data_hash_buf);

    //  Sign
    mbedtls_rsa_context *rsa_ctx = &rsa_private_key_impl->rsa_ctx;
    mbedtls_md_type_t md_alg = vscf_mbedtls_md_map_impl_tag(vscf_hash_impl_tag(rsa_private_key_impl->hash));

    mbedtls_rsa_set_padding(&rsa_private_key_impl->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int ret = mbedtls_rsa_rsassa_pss_sign(rsa_ctx, (mbedtls_random_cb)vscf_random, rsa_private_key_impl->random,
            MBEDTLS_RSA_PRIVATE, md_alg, vsc_buffer_len(data_hash_buf), vsc_buffer_bytes(data_hash_buf),
            vsc_buffer_ptr(signature));

    vsc_buffer_destroy(&data_hash_buf);

    VSCF_ASSERT_ALLOC(ret != MBEDTLS_ERR_MD_ALLOC_FAILED);

    switch (ret) {
    case 0:
        vsc_buffer_reserve(signature, vscf_rsa_private_key_signature_len(rsa_private_key_impl));
        return vscf_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_error_RANDOM_FAILED;

    default:
        return vscf_error_BAD_ARGUMENTS;
    }
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_signature_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_ASSERT_PTR(rsa_private_key_impl);

    return vscf_rsa_private_key_key_len(rsa_private_key_impl);
}

//
//  Export private key in the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_export_private_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_buffer_t *out) {

    //  RSAPrivateKey ::= SEQUENCE {
    //       version Version,
    //       modulus INTEGER, -- n
    //       publicExponent INTEGER, -- e
    //       privateExponent INTEGER, -- d
    //       prime1 INTEGER, -- p
    //       prime2 INTEGER, -- q
    //       exponent1 INTEGER, -- d mod (p-1)
    //       exponent2 INTEGER, -- d mod (q-1)
    //       coefficient INTEGER -- (inverse of q) mod p }

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1wr);

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key_impl->rsa_ctx) == 0);

    vscf_impl_t *asn1wr = rsa_private_key_impl->asn1wr;
    mbedtls_rsa_context *rsa_ctx = &rsa_private_key_impl->rsa_ctx;


    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    vscf_asn1_writer_reset(asn1wr, out);

    size_t top_sequence_len = 0;

    // Write QP - modulus
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->QP, &error_ctx);

    // Write DQ - publicExponent
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->DQ, &error_ctx);

    // Write DP - privateExponent
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->DP, &error_ctx);

    // Write Q - prime1
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->Q, &error_ctx);

    // Write P - prime2
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->P, &error_ctx);

    // Write D - exponent1
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->D, &error_ctx);

    // Write E - exponent2
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->E, &error_ctx);

    // Write N - coefficient
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa_ctx->N, &error_ctx);

    // Write version (0)
    top_sequence_len += vscf_asn1_writer_write_int(asn1wr, 0);

    vscf_asn1_writer_write_sequence(asn1wr, top_sequence_len);

    vscf_error_ctx_update(&error_ctx, vscf_asn1_writer_error(asn1wr));

    if (vscf_error_ctx_error(&error_ctx) != vscf_SUCCESS) {
        return vscf_error_SMALL_BUFFER;
    }

    vscf_asn1_writer_seal(asn1wr);

    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_exported_private_key_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl) {

    VSCF_UNUSED(rsa_private_key_impl);

    size_t key_len = vscf_rsa_private_key_key_len(rsa_private_key_impl);

    size_t top_tag_and_len = 4;
    size_t version = 3;
    size_t modulus = 5;
    size_t int_tag_plus_len_plus_padding = 1 + 4 + 1;

    return top_tag_and_len + version + modulus + 5 * (int_tag_plus_len_plus_padding + (key_len >> 1)) +
           2 * (int_tag_plus_len_plus_padding + key_len);
}

//
//  Import private key from the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_import_private_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data) {

    //  RSAPrivateKey ::= SEQUENCE {
    //       version Version,
    //       modulus INTEGER, -- n
    //       publicExponent INTEGER, -- e
    //       privateExponent INTEGER, -- d
    //       prime1 INTEGER, -- p
    //       prime2 INTEGER, -- q
    //       exponent1 INTEGER, -- d mod (p-1)
    //       exponent2 INTEGER, -- d mod (q-1)
    //       coefficient INTEGER -- (inverse of q) mod p }

    VSCF_ASSERT_PTR(rsa_private_key_impl);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(rsa_private_key_impl->asn1rd);

    vscf_impl_t *asn1rd = rsa_private_key_impl->asn1rd;
    mbedtls_rsa_context *rsa_ctx = &rsa_private_key_impl->rsa_ctx;

    // start
    vscf_asn1_reader_reset(asn1rd, data);
    vscf_asn1_reader_read_sequence(asn1rd);

    // version
    int version = vscf_asn1_reader_read_int(asn1rd);
    if (version != 0) {
        return vscf_error_BAD_PKCS1_PRIVATE_KEY;
    }

    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    // modulus
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa_ctx->N, &error_ctx);

    // publicExponent
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa_ctx->E, &error_ctx);

    // privateExponent
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa_ctx->D, &error_ctx);

    // prime1
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa_ctx->P, &error_ctx);

    // prime2
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa_ctx->Q, &error_ctx);

    // Handle both errors: ASN.1 reader and mbedtls bignum reader.
    if (vscf_error_ctx_error(&error_ctx) != vscf_SUCCESS) {
        return vscf_error_BAD_PKCS1_PRIVATE_KEY;
    }

    /* Complete the RSA private key */
    rsa_ctx->len = mbedtls_mpi_size(&rsa_ctx->N);

    int rsa_complete_ret = mbedtls_rsa_complete(rsa_ctx);
    VSCF_ASSERT_ALLOC(rsa_complete_ret == 0);

    return vscf_SUCCESS;
}
