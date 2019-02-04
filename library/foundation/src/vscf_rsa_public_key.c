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
#include "vscf_asn1_tag.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_mbedtls_md.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_hash.h"
#include "vscf_random.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
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
vscf_rsa_public_key_init_ctx(vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);

    mbedtls_rsa_init(&rsa_public_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_NONE);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_rsa_public_key_cleanup_ctx(vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);

    mbedtls_rsa_free(&rsa_public_key->rsa_ctx);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_public_key_alg_id(const vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);
    return vscf_alg_id_RSA;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_public_key_produce_alg_info(const vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_restore_alg_info(vscf_rsa_public_key_t *rsa_public_key, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_RSA);

    return vscf_SUCCESS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_len(const vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);

    return mbedtls_rsa_get_len(&rsa_public_key->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_bitlen(const vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);

    return 8 * mbedtls_rsa_get_len(&rsa_public_key->rsa_ctx);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_encrypt(vscf_rsa_public_key_t *rsa_public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_ASSERT_PTR(rsa_public_key->random);
    VSCF_ASSERT_PTR(rsa_public_key->hash);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT_OPT(vsc_buffer_unused_len(out) >= vscf_rsa_public_key_key_len(rsa_public_key));

    size_t hash_len = vscf_hash_info_digest_len(vscf_hash_hash_info_api(vscf_hash_api(rsa_public_key->hash)));
    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(rsa_public_key) >= data.len + 2 * hash_len + 2);

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(vscf_alg_alg_id(rsa_public_key->hash));
    mbedtls_rsa_set_padding(&rsa_public_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int result = mbedtls_rsa_rsaes_oaep_encrypt(&rsa_public_key->rsa_ctx, vscf_mbedtls_bridge_random,
            rsa_public_key->random, MBEDTLS_RSA_PUBLIC, NULL, 0, data.len, data.bytes, vsc_buffer_unused_bytes(out));

    switch (result) {
    case 0:
        vsc_buffer_inc_used(out, vscf_rsa_public_key_key_len(rsa_public_key));
        return vscf_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_error_RANDOM_FAILED;

    default:
        return vscf_error_BAD_ARGUMENTS;
    }
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_encrypted_len(vscf_rsa_public_key_t *rsa_public_key, size_t data_len) {

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_UNUSED(data_len);

    return vscf_rsa_public_key_key_len(rsa_public_key);
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_rsa_public_key_verify(vscf_rsa_public_key_t *rsa_public_key, vsc_data_t data, vsc_data_t signature) {

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_ASSERT_PTR(rsa_public_key->random);
    VSCF_ASSERT_PTR(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(vsc_data_is_valid(signature));

    if (signature.len != vscf_rsa_public_key_key_len(rsa_public_key)) {
        return false;
    }

    //  Hash
    size_t data_hash_len = vscf_hash_info_digest_len(vscf_hash_hash_info_api(vscf_hash_api(rsa_public_key->hash)));
    vsc_buffer_t *data_hash_buf = vsc_buffer_new_with_capacity(data_hash_len);
    VSCF_ASSERT(data_hash_len <= UINT_MAX);

    vscf_hash(vscf_hash_api(rsa_public_key->hash), data, data_hash_buf);

    //  Verify
    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(vscf_alg_alg_id(rsa_public_key->hash));
    mbedtls_rsa_set_padding(&rsa_public_key->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int result = mbedtls_rsa_rsassa_pss_verify(&rsa_public_key->rsa_ctx, vscf_mbedtls_bridge_random,
            rsa_public_key->random, MBEDTLS_RSA_PUBLIC, md_alg, (unsigned int)vsc_buffer_len(data_hash_buf),
            vsc_buffer_bytes(data_hash_buf), signature.bytes);

    //  Cleanup
    vsc_buffer_destroy(&data_hash_buf);

    return result == 0 ? true : false;
}

//
//  Export public key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_export_public_key(const vscf_rsa_public_key_t *rsa_public_key, vsc_buffer_t *out) {

    // RSAPublicKey ::= SEQUENCE {
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e
    // }

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_ASSERT_PTR(rsa_public_key->asn1wr);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));

    VSCF_ASSERT(mbedtls_rsa_check_pubkey(&rsa_public_key->rsa_ctx) == 0);

    vscf_impl_t *asn1wr = rsa_public_key->asn1wr;
    const mbedtls_rsa_context *rsa = &rsa_public_key->rsa_ctx;

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vscf_asn1_writer_reset(asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    vscf_asn1_writer_write_sequence(asn1wr, vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->E, &error) +
                                                    vscf_mbedtls_bignum_write_asn1(asn1wr, &rsa->N, &error));

    vscf_error_ctx_update(&error, vscf_asn1_writer_error(asn1wr));

    if (vscf_error_ctx_error(&error) != vscf_SUCCESS) {
        return vscf_error_SMALL_BUFFER;
    }

    size_t writtenBytes = vscf_asn1_writer_finish(asn1wr);
    vsc_buffer_inc_used(out, writtenBytes);

    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_exported_public_key_len(const vscf_rsa_public_key_t *rsa_public_key) {

    VSCF_ASSERT_PTR(rsa_public_key);

    return 1 + 2 + 3 + 4 + 4 + vscf_rsa_public_key_key_len(rsa_public_key);
}

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_import_public_key(vscf_rsa_public_key_t *rsa_public_key, vsc_data_t data) {

    // RSAPublicKey ::= SEQUENCE {
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e
    // }

    VSCF_ASSERT_PTR(rsa_public_key);
    VSCF_ASSERT_PTR(rsa_public_key->asn1rd);
    VSCF_ASSERT_PTR(data.bytes);
    VSCF_ASSERT_PTR(data.len > 0);

    vscf_impl_t *asn1rd = rsa_public_key->asn1rd;
    mbedtls_rsa_context *rsa = &rsa_public_key->rsa_ctx;

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vscf_asn1_reader_reset(asn1rd, data);
    vscf_asn1_reader_read_sequence(asn1rd);

    vscf_error_ctx_update(&error, vscf_asn1_reader_error(asn1rd));

    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->N, &error);
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->E, &error);


    if (vscf_error_ctx_error(&error) != vscf_SUCCESS) {
        return vscf_error_BAD_PKCS1_PUBLIC_KEY;
    }

    rsa->len = mbedtls_mpi_size(&rsa->N);

    if (mbedtls_rsa_complete(rsa) != 0 || mbedtls_rsa_check_pubkey(rsa) != 0) {
        return vscf_error_BAD_PKCS1_PUBLIC_KEY;
    }

    return vscf_SUCCESS;
}
