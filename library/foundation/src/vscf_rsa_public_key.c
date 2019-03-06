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
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_md.h"
#include "vscf_simple_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_ctr_drbg.h"
#include "vscf_rsa_private_key.h"
#include "vscf_sha384.h"
#include "vscf_alg_info.h"
#include "vscf_alg.h"
#include "vscf_mbedtls_bridge_random.h"
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
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_public_key_setup_defaults(vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }
        self->random = vscf_ctr_drbg_impl(random);
    }

    if (NULL == self->hash) {
        self->hash = vscf_sha384_impl(vscf_sha384_new());
    }

    if (NULL == self->asn1rd) {
        self->asn1rd = vscf_asn1rd_impl(vscf_asn1rd_new());
    }

    if (NULL == self->asn1wr) {
        self->asn1wr = vscf_asn1wr_impl(vscf_asn1wr_new());
    }

    return vscf_status_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_public_key_alg_id(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_RSA;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_public_key_produce_alg_info(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_public_key_restore_alg_info(vscf_rsa_public_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_RSA);

    return vscf_status_SUCCESS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_len(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_bitlen(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return 8 * mbedtls_rsa_get_len(&self->rsa_ctx);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_public_key_encrypt(vscf_rsa_public_key_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT_OPT(vsc_buffer_unused_len(out) >= vscf_rsa_public_key_key_len(self));

    size_t hash_len = vscf_hash_digest_len(vscf_hash_api(self->hash));
    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(self) >= data.len + 2 * hash_len + 2);

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(vscf_alg_alg_id(self->hash));
    mbedtls_rsa_set_padding(&self->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int result = mbedtls_rsa_rsaes_oaep_encrypt(&self->rsa_ctx, vscf_mbedtls_bridge_random, self->random,
            MBEDTLS_RSA_PUBLIC, NULL, 0, data.len, data.bytes, vsc_buffer_unused_bytes(out));

    switch (result) {
    case 0:
        vsc_buffer_inc_used(out, vscf_rsa_public_key_key_len(self));
        return vscf_status_SUCCESS;

    case MBEDTLS_ERR_RSA_RNG_FAILED:
        return vscf_status_ERROR_RANDOM_FAILED;

    default:
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_encrypted_len(vscf_rsa_public_key_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(data_len);

    return vscf_rsa_public_key_key_len(self);
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_rsa_public_key_verify(vscf_rsa_public_key_t *self, vsc_data_t data, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(vsc_data_is_valid(signature));

    if (signature.len != vscf_rsa_public_key_key_len(self)) {
        return false;
    }

    //  Hash
    size_t data_hash_len = vscf_hash_digest_len(vscf_hash_api(self->hash));
    vsc_buffer_t *data_hash_buf = vsc_buffer_new_with_capacity(data_hash_len);
    VSCF_ASSERT(data_hash_len <= UINT_MAX);

    vscf_hash(vscf_hash_api(self->hash), data, data_hash_buf);

    //  Verify
    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(vscf_alg_alg_id(self->hash));
    mbedtls_rsa_set_padding(&self->rsa_ctx, MBEDTLS_RSA_PKCS_V21, md_alg);

    int result = mbedtls_rsa_rsassa_pss_verify(&self->rsa_ctx, vscf_mbedtls_bridge_random, self->random,
            MBEDTLS_RSA_PUBLIC, md_alg, (unsigned int)vsc_buffer_len(data_hash_buf), vsc_buffer_bytes(data_hash_buf),
            signature.bytes);

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
VSCF_PUBLIC vscf_status_t
vscf_rsa_public_key_export_public_key(const vscf_rsa_public_key_t *self, vsc_buffer_t *out) {

    // RSAPublicKey ::= SEQUENCE {
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e
    // }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1wr);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));
    VSCF_ASSERT(mbedtls_rsa_check_pubkey(&self->rsa_ctx) == 0);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_rsa_public_key_exported_public_key_len(self));

    vscf_asn1_writer_reset(self->asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    vscf_error_t error;
    vscf_error_reset(&error);

    size_t len = 0;

    len += vscf_mbedtls_bignum_write_asn1(self->asn1wr, &self->rsa_ctx.E, &error);
    len += vscf_mbedtls_bignum_write_asn1(self->asn1wr, &self->rsa_ctx.N, &error);
    len += vscf_asn1_writer_write_sequence(self->asn1wr, len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1wr));
    VSCF_ASSERT(!vscf_error_has_error(&error));

    vsc_buffer_inc_used(out, len);

    if (!vsc_buffer_is_reverse(out)) {
        vscf_asn1_writer_finish(self->asn1wr);
    }

    return vscf_status_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_exported_public_key_len(const vscf_rsa_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return 1 + 2 + 3 + 4 + 4 + vscf_rsa_public_key_key_len(self);
}

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_rsa_public_key_import_public_key(vscf_rsa_public_key_t *self, vsc_data_t data) {

    // RSAPublicKey ::= SEQUENCE {
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e
    // }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1rd);
    VSCF_ASSERT_PTR(data.bytes);
    VSCF_ASSERT_PTR(data.len > 0);

    vscf_impl_t *asn1rd = self->asn1rd;
    mbedtls_rsa_context *rsa = &self->rsa_ctx;

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1_reader_reset(asn1rd, data);
    vscf_asn1_reader_read_sequence(asn1rd);

    vscf_error_update(&error, vscf_asn1_reader_status(asn1rd));

    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->N, &error);
    vscf_mbedtls_bignum_read_asn1(asn1rd, &rsa->E, &error);


    if (vscf_error_has_error(&error)) {
        return vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY;
    }

    rsa->len = mbedtls_mpi_size(&rsa->N);

    if (mbedtls_rsa_complete(rsa) != 0 || mbedtls_rsa_check_pubkey(rsa) != 0) {
        return vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY;
    }

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_public_key_generate_ephemeral_key(vscf_rsa_public_key_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();
    vscf_rsa_private_key_use_random(private_key, self->random);

    const size_t bitlen = vscf_rsa_public_key_key_bitlen(self);
    const size_t exponent = vscf_rsa_public_key_key_exponent(self);

    vscf_rsa_private_key_set_keygen_params(private_key, bitlen, exponent);
    vscf_status_t status = vscf_rsa_private_key_generate_key(private_key);
    if (status != vscf_status_SUCCESS) {
        vscf_rsa_private_key_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    return vscf_rsa_private_key_impl(private_key);
}
