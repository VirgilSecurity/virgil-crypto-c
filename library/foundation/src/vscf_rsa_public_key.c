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
#include "vscf_random.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1.h"
#include "vscf_rsa_public_key_impl.h"
#include "vscf_rsa_public_key_internal.h"

#include <virgil/common/private/vsc_buffer_defs.h>
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
VSCF_PRIVATE vscf_error_t
vscf_rsa_public_key_init_ctx(vscf_rsa_public_key_impl_t *rsa_public_key_impl) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    mbedtls_rsa_init(&rsa_public_key_impl->rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);

    return vscf_SUCCESS;
}

//
//  Provides cleanup of the implementation specific context.
//
VSCF_PRIVATE void
vscf_rsa_public_key_cleanup_ctx(vscf_rsa_public_key_impl_t *rsa_public_key_impl) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    mbedtls_rsa_free(&rsa_public_key_impl->rsa_ctx);
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_len(vscf_rsa_public_key_impl_t *rsa_public_key_impl) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    return mbedtls_rsa_get_len(&rsa_public_key_impl->rsa_ctx);
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_bitlen(vscf_rsa_public_key_impl_t *rsa_public_key_impl) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    return 8 * mbedtls_rsa_get_len(&rsa_public_key_impl->rsa_ctx);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_encrypt(vscf_rsa_public_key_impl_t *rsa_public_key_impl, const vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);
    VSCF_ASSERT_PTR(rsa_public_key_impl->random);

    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(rsa_public_key_impl) > 11);
    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(rsa_public_key_impl) - 11 >= data.len);

    int result = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&rsa_public_key_impl->rsa_ctx, (mbedtls_random_cb)vscf_random,
            rsa_public_key_impl->random, MBEDTLS_RSA_PUBLIC, data.len, data.bytes, out->bytes);

    switch (result) {
    case 0:
        return vscf_SUCCESS;

    default:
        return vscf_error_BAD_ARGUMENTS;
    }
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_encrypted_len(vscf_rsa_public_key_impl_t *rsa_public_key_impl, size_t data_len) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(rsa_public_key_impl) > 11);
    VSCF_ASSERT_OPT(vscf_rsa_public_key_key_len(rsa_public_key_impl) - 11 >= data_len);

    return vscf_rsa_public_key_key_len(rsa_public_key_impl);
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_rsa_public_key_verify(
        vscf_rsa_public_key_impl_t *rsa_public_key_impl, const vsc_data_t data, const vsc_data_t signature) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);
    VSCF_ASSERT_PTR(rsa_public_key_impl->random);

    if (signature.len != vscf_rsa_public_key_key_len(rsa_public_key_impl)) {
        return false;
    }

    int result = mbedtls_rsa_rsassa_pkcs1_v15_verify(&rsa_public_key_impl->rsa_ctx, (mbedtls_random_cb)vscf_random,
            rsa_public_key_impl->random, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, data.len, data.bytes, signature.bytes);

    return result == 0 ? true : false;
}

//
//  Export public key in the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_export_public_key(vscf_rsa_public_key_impl_t *rsa_public_key_impl, vsc_buffer_t *out) {

    // RSAPublicKey ::= SEQUENCE {
    //     modulus INTEGER, -- n
    //     publicExponent INTEGER -- e
    // }

    VSCF_ASSERT_PTR(rsa_public_key_impl);
    VSCF_ASSERT_PTR(rsa_public_key_impl->asn1wr);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(out->bytes);

    VSCF_ASSERT(mbedtls_rsa_check_pubkey(&rsa_public_key_impl->rsa_ctx) == 0);

    vscf_impl_t *asn1wr = rsa_public_key_impl->asn1wr;
    mbedtls_rsa_context *rsa_ctx = &rsa_public_key_impl->rsa_ctx;
    size_t asn1_len = 0;

    vscf_asn1_writer_reset(asn1wr, out);

    //   Write: publicKey
    size_t exponent_len = mbedtls_mpi_size(&rsa_ctx->E);
    byte *exponent_start = vscf_asn1_writer_reserve(asn1wr, exponent_len);

    if (exponent_start == NULL) {
        return vscf_error_SMALL_BUFFER;
    }

    int mpi_ret = mbedtls_mpi_write_binary(&rsa_ctx->E, exponent_start, exponent_len);
    VSCF_ASSERT_OPT(0 == mpi_ret);

    //   if number is positive, but most left bit is one, then prepend it with zero byte
    if (1 == rsa_ctx->E.s && *exponent_start & 0x80) {
        exponent_start = vscf_asn1_writer_reserve(asn1wr, 1);

        if (exponent_start == NULL) {
            return vscf_error_SMALL_BUFFER;
        }

        *exponent_start = 0x00;
        exponent_len += 1;
    }

    asn1_len += exponent_len;

    asn1_len += vscf_asn1_writer_write_len(asn1wr, exponent_len);
    asn1_len += vscf_asn1_writer_write_tag(asn1wr, vscf_asn1_tag_INTEGER);

    if (vscf_asn1_writer_error(asn1wr) != vscf_SUCCESS) {
        return vscf_asn1_writer_error(asn1wr);
    }

    //   Write: modulus
    size_t modulus_len = mbedtls_mpi_size(&rsa_ctx->N);
    byte *modulus_start = vscf_asn1_writer_reserve(asn1wr, modulus_len);

    if (modulus_start == NULL) {
        return vscf_error_SMALL_BUFFER;
    }

    mpi_ret = mbedtls_mpi_write_binary(&rsa_ctx->N, modulus_start, modulus_len);
    VSCF_ASSERT_OPT(0 == mpi_ret);

    //   if number is positive, but most left bit is one, then prepend it with zero byte
    if (1 == rsa_ctx->N.s && *modulus_start & 0x80) {
        modulus_start = vscf_asn1_writer_reserve(asn1wr, 1);

        if (modulus_start == NULL) {
            return vscf_error_SMALL_BUFFER;
        }

        *modulus_start = 0x00;
        modulus_len += 1;
    }

    asn1_len += modulus_len;

    asn1_len += vscf_asn1_writer_write_len(asn1wr, modulus_len);
    asn1_len += vscf_asn1_writer_write_tag(asn1wr, vscf_asn1_tag_INTEGER);
    (void)vscf_asn1_writer_write_sequence(asn1wr, asn1_len);

    if (vscf_asn1_writer_error(asn1wr) != vscf_SUCCESS) {
        return vscf_error_SMALL_BUFFER;
    }

    vscf_asn1_writer_seal(asn1wr);

    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_exported_public_key_len(vscf_rsa_public_key_impl_t *rsa_public_key_impl) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);

    return 0;
}

//
//  Import public key from the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_public_key_import_public_key(vscf_rsa_public_key_impl_t *rsa_public_key_impl, const vsc_data_t data) {

    VSCF_ASSERT_PTR(rsa_public_key_impl);
    VSCF_ASSERT_PTR(data.bytes);
    VSCF_ASSERT_PTR(data.len > 0);

    return vscf_SUCCESS;
}
