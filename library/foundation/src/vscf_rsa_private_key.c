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
#include "vscf_asn1_tag.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_mbedtls_md.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_random.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_rsa_private_key_defs.h"
#include "vscf_rsa_private_key_internal.h"

#include <mbedtls/bignum.h>

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
vscf_rsa_private_key_init_ctx(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    mbedtls_rsa_init(&rsa_private_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_NONE);

    rsa_private_key->gen_bitlen = 4096;
    rsa_private_key->gen_exponent = 65537;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_rsa_private_key_cleanup_ctx(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    mbedtls_rsa_free(&rsa_private_key->rsa_ctx);
}

//
//  Setup parameters that is used during key generation.
//
VSCF_PUBLIC void
vscf_rsa_private_key_set_keygen_params(vscf_rsa_private_key_t *rsa_private_key, size_t bitlen, size_t exponent) {

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT(bitlen >= 128 && bitlen <= 16384);
    VSCF_ASSERT(bitlen % 2 == 0);
    VSCF_ASSERT(exponent >= 3 && exponent <= 65537);

    rsa_private_key->gen_bitlen = bitlen;
    rsa_private_key->gen_exponent = exponent;
}

//
//  Return implemented asymmetric key algorithm type.
//
VSCF_PUBLIC vscf_key_alg_t
vscf_rsa_private_key_alg(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);
    return vscf_key_alg_RSA;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_len(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    return mbedtls_rsa_get_len(&rsa_private_key->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_bitlen(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    return 8 * mbedtls_rsa_get_len(&rsa_private_key->rsa_ctx);
}

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_generate_key(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    int ret = mbedtls_rsa_gen_key(&rsa_private_key->rsa_ctx, vscf_mbedtls_bridge_random, rsa_private_key->random,
            (unsigned int)rsa_private_key->gen_bitlen, (int)rsa_private_key->gen_exponent);

    return ret == 0 ? vscf_SUCCESS : vscf_error_KEY_GENERATION_FAILED;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_decrypt(vscf_rsa_private_key_t *rsa_private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT_PTR(rsa_private_key->random);
    VSCF_ASSERT_PTR(rsa_private_key->hash);
    VSCF_ASSERT_PTR(out);

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT_OPT(vsc_buffer_unused_len(out) >= vscf_rsa_private_key_decrypted_len(rsa_private_key, data.len));

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key->rsa_ctx) == 0);

    if (data.len != vscf_rsa_private_key_key_len(rsa_private_key)) {
        return vscf_error_BAD_ENCRYPTED_DATA;
    }

    mbedtls_md_type_t md_alg =
            vscf_mbedtls_md_from_hash_alg(vscf_hash_info_alg(vscf_hash_hash_info_api(rsa_private_key->hash)));
    mbedtls_rsa_set_padding(&rsa_private_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    size_t out_len = 0;
    int ret = mbedtls_rsa_rsaes_oaep_decrypt(&rsa_private_key->rsa_ctx, vscf_mbedtls_bridge_random,
            rsa_private_key->random, MBEDTLS_RSA_PRIVATE, NULL, 0, &out_len, data.bytes, vsc_buffer_unused_bytes(out),
            vsc_buffer_unused_len(out));

    if (ret != 0) {
        return vscf_error_BAD_ENCRYPTED_DATA;
    }

    vsc_buffer_inc_used(out, out_len);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_decrypted_len(vscf_rsa_private_key_t *rsa_private_key, size_t data_len) {

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_UNUSED(data_len);

    return vscf_rsa_private_key_key_len(rsa_private_key);
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_sign(vscf_rsa_private_key_t *rsa_private_key, vsc_data_t data, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT_PTR(rsa_private_key->random);
    VSCF_ASSERT_PTR(rsa_private_key->hash);
    VSCF_ASSERT_PTR(signature);

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(signature));

    VSCF_ASSERT_OPT(vsc_buffer_unused_len(signature) >= vscf_rsa_private_key_signature_len(rsa_private_key));

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key->rsa_ctx) == 0);

    //  Hash
    size_t data_hash_len = vscf_hash_info_digest_len(vscf_hash_hash_info_api(rsa_private_key->hash));
    vsc_buffer_t *data_hash_buf = vsc_buffer_new_with_capacity(data_hash_len);
    VSCF_ASSERT(data_hash_len <= UINT_MAX);

    vscf_hash(rsa_private_key->hash, data, data_hash_buf);

    //  Sign
    mbedtls_rsa_context *rsa = &rsa_private_key->rsa_ctx;
    mbedtls_md_type_t md_alg =
            vscf_mbedtls_md_from_hash_alg(vscf_hash_info_alg(vscf_hash_hash_info_api(rsa_private_key->hash)));

    mbedtls_rsa_set_padding(&rsa_private_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int ret = mbedtls_rsa_rsassa_pss_sign(rsa, vscf_mbedtls_bridge_random, rsa_private_key->random, MBEDTLS_RSA_PRIVATE,
            md_alg, (unsigned int)vsc_buffer_len(data_hash_buf), vsc_buffer_bytes(data_hash_buf),
            vsc_buffer_unused_bytes(signature));

    vsc_buffer_destroy(&data_hash_buf);

    VSCF_ASSERT_ALLOC(ret != MBEDTLS_ERR_MD_ALLOC_FAILED);

    switch (ret) {
    case 0:
        vsc_buffer_inc_used(signature, vscf_rsa_private_key_signature_len(rsa_private_key));
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
vscf_rsa_private_key_signature_len(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);

    return vscf_rsa_private_key_key_len(rsa_private_key);
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_extract_public_key(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT(mbedtls_rsa_check_pubkey(&rsa_private_key->rsa_ctx) == 0);

#if VSCF_RSA_PUBLIC_KEY
    vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();
    VSCF_ASSERT_ALLOC(rsa_public_key != NULL);

    mbedtls_rsa_context *rsa_public = &rsa_public_key->rsa_ctx;
    mbedtls_rsa_context *rsa_private = &rsa_private_key->rsa_ctx;

    int copy_n_ret = mbedtls_mpi_copy(&rsa_public->N, &rsa_private->N);
    int copy_e_ret = mbedtls_mpi_copy(&rsa_public->E, &rsa_private->E);

    VSCF_ASSERT_ALLOC(rsa_public_key != NULL);
    VSCF_ASSERT_ALLOC((0 == copy_n_ret) && (0 == copy_e_ret));

    rsa_public->len = rsa_private->len;

    if (rsa_private_key->hash) {
        vscf_rsa_public_key_use_hash(rsa_public_key, rsa_private_key->hash);
    }

    if (rsa_private_key->random) {
        vscf_rsa_public_key_use_random(rsa_public_key, rsa_private_key->random);
    }

    if (rsa_private_key->asn1rd) {
        vscf_rsa_public_key_use_asn1rd(rsa_public_key, rsa_private_key->asn1rd);
    }

    if (rsa_private_key->asn1wr) {
        vscf_rsa_public_key_use_asn1wr(rsa_public_key, rsa_private_key->asn1wr);
    }

    return vscf_rsa_public_key_impl(rsa_public_key);
#else
    VSCF_ASSERT(VSCF_RSA_PUBLIC_KEY && "VSCF_RSA_PUBLIC_KEY feature is diabled");
    return NULL;
#endif
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_export_private_key(vscf_rsa_private_key_t *rsa_private_key, vsc_buffer_t *out) {

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

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT_PTR(rsa_private_key->asn1wr);

    VSCF_ASSERT(mbedtls_rsa_check_privkey(&rsa_private_key->rsa_ctx) == 0);

    vscf_impl_t *asn1wr = rsa_private_key->asn1wr;
    mbedtls_rsa_context *rsa = &rsa_private_key->rsa_ctx;


    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vscf_asn1_writer_reset(asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    size_t top_sequence_len = 0;

    // Write QP - modulus
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->QP, &error);

    // Write DQ - publicExponent
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->DQ, &error);

    // Write DP - privateExponent
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->DP, &error);

    // Write Q - prime1
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->Q, &error);

    // Write P - prime2
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->P, &error);

    // Write D - exponent1
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->D, &error);

    // Write E - exponent2
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->E, &error);

    // Write N - coefficient
    top_sequence_len += vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->N, &error);

    // Write version (0)
    top_sequence_len += vscf_asn1_writer_write_int(asn1wr, 0);

    vscf_asn1_writer_write_sequence(asn1wr, top_sequence_len);

    vscf_error_ctx_update(&error, vscf_asn1_writer_error(asn1wr));

    if (vscf_error_ctx_error(&error) != vscf_SUCCESS) {
        return vscf_error_SMALL_BUFFER;
    }

    size_t writtenBytes = vscf_asn1_writer_finish(asn1wr);
    vsc_buffer_inc_used(out, writtenBytes);

    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_exported_private_key_len(vscf_rsa_private_key_t *rsa_private_key) {

    VSCF_UNUSED(rsa_private_key);

    size_t key_len = vscf_rsa_private_key_key_len(rsa_private_key);

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
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_import_private_key(vscf_rsa_private_key_t *rsa_private_key, vsc_data_t data) {

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

    VSCF_ASSERT_PTR(rsa_private_key);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(rsa_private_key->asn1rd);

    vscf_impl_t *asn1rd = rsa_private_key->asn1rd;
    mbedtls_rsa_context *rsa = &rsa_private_key->rsa_ctx;

    // start
    vscf_asn1_reader_reset(asn1rd, data);
    vscf_asn1_reader_read_sequence(asn1rd);

    // version
    int version = vscf_asn1_reader_read_int(asn1rd);
    if (version != 0) {
        return vscf_error_BAD_PKCS1_PRIVATE_KEY;
    }

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    // modulus
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->N, &error);

    // publicExponent
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->E, &error);

    // privateExponent
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->D, &error);

    // prime1
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->P, &error);

    // prime2
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->Q, &error);

    // Handle both errors: ASN.1 reader and mbedtls bignum reader.
    if (vscf_error_ctx_error(&error) != vscf_SUCCESS) {
        return vscf_error_BAD_PKCS1_PRIVATE_KEY;
    }

    /* Complete the RSA private key */
    rsa->len = mbedtls_mpi_size(&rsa->N);

    int rsa_complete_ret = mbedtls_rsa_complete(rsa);
    VSCF_ASSERT_ALLOC(rsa_complete_ret == 0);

    return vscf_SUCCESS;
}
