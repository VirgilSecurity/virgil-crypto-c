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
//  This module contains 'ecc' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecc.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_md.h"
#include "vscf_mbedtls_ecp.h"
#include "vscf_simple_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_ctr_drbg.h"
#include "vscf_alg_info.h"
#include "vscf_alg.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_ecc_private_key_defs.h"
#include "vscf_ecc_public_key_defs.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_random.h"
#include "vscf_ecc_defs.h"
#include "vscf_ecc_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Validate if "alg id" belongs to ECC.
//
static vscf_status_t
vscf_ecc_load_group(vscf_alg_id_t alg_id, mbedtls_ecp_group *ecc_grp) VSCF_NODISCARD;

//
//  Write R and S to ASN.1 structure.
//
//  ECDSA-Sig-Value ::= SEQUENCE {
//      r INTEGER,
//      s INTEGER
//  }
//
static void
vscf_ecc_write_signature(const mbedtls_mpi *r, const mbedtls_mpi *s, vsc_buffer_t *signature);

//
//  Read R and S from ASN.1 structure.
//
//  ECDSA-Sig-Value ::= SEQUENCE {
//      r INTEGER,
//      s INTEGER
//  }
//
static vscf_status_t
vscf_ecc_read_signature(vsc_data_t signature, mbedtls_mpi *r, mbedtls_mpi *s) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_setup_defaults(vscf_ecc_t *self) {

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

    if (NULL == self->ecies) {
        vscf_ecies_t *ecies = vscf_ecies_new();
        vscf_ecies_use_random(ecies, self->random);
        vscf_status_t status = vscf_ecies_setup_defaults(ecies);

        if (status != vscf_status_SUCCESS) {
            vscf_ecies_destroy(&ecies);
            return status;
        }

        self->ecies = ecies;
    }

    return vscf_status_SUCCESS;
}

//
//  Validate if "alg id" belongs to ECC.
//
static vscf_status_t
vscf_ecc_load_group(vscf_alg_id_t alg_id, mbedtls_ecp_group *ecc_grp) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(ecc_grp);

    const mbedtls_ecp_group_id grp_id = vscf_mbedtls_ecp_group_id_from_alg_id(alg_id);

    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    const int status = mbedtls_ecp_group_load(ecc_grp, grp_id);
    VSCF_ASSERT_ALLOC(status != MBEDTLS_ERR_MPI_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    return vscf_status_SUCCESS;
}

//
//  Write R and S to ASN.1 structure.
//
//  ECDSA-Sig-Value ::= SEQUENCE {
//      r INTEGER,
//      s INTEGER
//  }
//
static void
vscf_ecc_write_signature(const mbedtls_mpi *r, const mbedtls_mpi *s, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(r);
    VSCF_ASSERT_PTR(s);
    VSCF_ASSERT_PTR(signature);

    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(signature), vsc_buffer_unused_len(signature));

    size_t len = 0;
    len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), s, NULL);
    len += vscf_mbedtls_bignum_write_asn1(vscf_asn1wr_impl(&asn1wr), r, NULL);

    vscf_asn1wr_write_sequence(&asn1wr, len);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(signature));

    vscf_asn1wr_cleanup(&asn1wr);
}

//
//  Read R and S from ASN.1 structure.
//
//  ECDSA-Sig-Value ::= SEQUENCE {
//      r INTEGER,
//      s INTEGER
//  }
//
static vscf_status_t
vscf_ecc_read_signature(vsc_data_t signature, mbedtls_mpi *r, mbedtls_mpi *s) {

    VSCF_ASSERT(vsc_data_is_valid(signature));
    VSCF_ASSERT_PTR(r);
    VSCF_ASSERT_PTR(s);

    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, signature);

    vscf_asn1rd_read_sequence(&asn1rd);
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), r, NULL);
    vscf_mbedtls_bignum_read_asn1(vscf_asn1rd_impl(&asn1rd), s, NULL);

    vscf_asn1rd_cleanup(&asn1rd);

    if (vscf_asn1rd_has_error(&asn1rd)) {
        return vscf_status_ERROR_BAD_SIGNATURE;
    } else {
        return vscf_status_SUCCESS;
    }
}

//
//  Generate new private key.
//  Supported algorithm ids:
//      - secp256r1.
//
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_generate_key(const vscf_ecc_t *self, vscf_alg_id_t alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_ecc_private_key_t *private_key = vscf_ecc_private_key_new();

    const vscf_status_t status = vscf_ecc_load_group(alg_id, &private_key->ecc_grp);
    if (status != vscf_status_SUCCESS) {
        vscf_ecc_private_key_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    const int mbed_status = mbedtls_ecp_gen_privkey(
            &private_key->ecc_grp, &private_key->ecc_priv, vscf_mbedtls_bridge_random, self->random);
    VSCF_ASSERT_ALLOC(status != MBEDTLS_ERR_MPI_ALLOC_FAILED);

    if (mbed_status != 0) {
        vscf_ecc_private_key_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_KEY_GENERATION_FAILED);
        return NULL;
    }

    return vscf_ecc_private_key_impl(private_key);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_ecc_alg_id(const vscf_ecc_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_ECC;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_produce_alg_info(const vscf_ecc_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ECC));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_restore_alg_info(vscf_ecc_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_ECC);

    return vscf_status_SUCCESS;
}

//
//  Extract public key from the private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_extract_public_key(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_ECC_PRIVATE_KEY);
    const vscf_ecc_private_key_t *ecc_private_key = (const vscf_ecc_private_key_t *)private_key;
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&ecc_private_key->ecc_grp, &ecc_private_key->ecc_priv));

    vscf_ecc_public_key_t *ecc_public_key = vscf_ecc_public_key_new();

    int mbed_status = mbedtls_ecp_group_copy(&ecc_public_key->ecc_grp, &ecc_private_key->ecc_grp);
    VSCF_ASSERT_ALLOC(mbed_status == 0);

    mbed_status = mbedtls_ecp_mul(&ecc_public_key->ecc_grp, &ecc_public_key->ecc_pub, &ecc_private_key->ecc_priv,
            &ecc_public_key->ecc_grp.G, vscf_mbedtls_bridge_random, self->random);
    VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MPI_ALLOC_FAILED);

    if (mbed_status != 0) {
        vscf_ecc_public_key_destroy(&ecc_public_key);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_RANDOM_FAILED);
        return NULL;
    }

    return vscf_ecc_public_key_impl(ecc_public_key);
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_generate_ephemeral_key(const vscf_ecc_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    return vscf_ecc_generate_key(self, vscf_key_alg_id(key), error);
}

//
//  Import public key from the raw binary format.
//
//  Return public key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_import_public_key(vscf_ecc_t *self, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(vscf_raw_key_is_public(raw_key));

    vscf_ecc_public_key_t *ecc_public_key = vscf_ecc_public_key_new();
    vscf_status_t status = vscf_ecc_load_group(vscf_raw_key_alg_id(raw_key), &ecc_public_key->ecc_grp);
    if (status != vscf_status_SUCCESS) {
        vscf_ecc_public_key_destroy(&ecc_public_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    vsc_data_t raw_key_data = vscf_raw_key_data(raw_key);
    VSCF_ASSERT(vsc_data_is_valid(raw_key_data));

    const int mbed_status = mbedtls_ecp_point_read_binary(
            &ecc_public_key->ecc_grp, &ecc_public_key->ecc_pub, raw_key_data.bytes, raw_key_data.len);

    if (mbed_status != 0) {
        VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MPI_ALLOC_FAILED);
        vscf_ecc_public_key_destroy(&ecc_public_key);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY);
        return NULL;
    }

    return vscf_ecc_public_key_impl(ecc_public_key);
}

//
//  Export public key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_ecc_export_public_key(const vscf_ecc_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_ECC_PUBLIC_KEY);
    const vscf_ecc_public_key_t *ecc_public_key = (const vscf_ecc_public_key_t *)public_key;
    VSCF_ASSERT(0 == mbedtls_ecp_check_pubkey(&ecc_public_key->ecc_grp, &ecc_public_key->ecc_pub));

    const size_t buffer_len = 2 * mbedtls_mpi_size(&ecc_public_key->ecc_grp.P) + 1 /* compression flag */;
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    size_t out_len = 0;
    const int mbed_status = mbedtls_ecp_point_write_binary(&ecc_public_key->ecc_grp, &ecc_public_key->ecc_pub,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &out_len, vsc_buffer_unused_bytes(buffer), vsc_buffer_unused_len(buffer));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);
    VSCF_ASSERT(out_len <= vsc_buffer_unused_len(buffer));
    vsc_buffer_inc_used(buffer, out_len);

    return vscf_raw_key_new_public_with_buffer(
            vscf_mbedtls_ecp_group_id_to_alg_id(ecc_public_key->ecc_grp.id), &buffer);
}

//
//  Import private key from the raw binary format.
//
//  Return private key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_import_private_key(vscf_ecc_t *self, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    //
    //  Import private key from Octet String (SEC1 2.3.7)
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT(!vscf_raw_key_is_public(raw_key));

    vscf_ecc_private_key_t *ecc_private_key = vscf_ecc_private_key_new();
    vscf_status_t status = vscf_ecc_load_group(vscf_raw_key_alg_id(raw_key), &ecc_private_key->ecc_grp);
    if (status != vscf_status_SUCCESS) {
        vscf_ecc_private_key_destroy(&ecc_private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    vsc_data_t raw_key_data = vscf_raw_key_data(raw_key);
    VSCF_ASSERT(vsc_data_is_valid(raw_key_data));

    const int mbed_status = mbedtls_mpi_read_binary(&ecc_private_key->ecc_priv, raw_key_data.bytes, raw_key_data.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);

    if (0 != mbedtls_ecp_check_privkey(&ecc_private_key->ecc_grp, &ecc_private_key->ecc_priv)) {
        vscf_ecc_private_key_destroy(&ecc_private_key);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    return vscf_ecc_private_key_impl(ecc_private_key);
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_ecc_export_private_key(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    //
    //  Export private key into Octet String (SEC1 2.3.7)
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_ECC_PRIVATE_KEY);
    const vscf_ecc_private_key_t *ecc_private_key = (const vscf_ecc_private_key_t *)private_key;
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&ecc_private_key->ecc_grp, &ecc_private_key->ecc_priv));

    const size_t buffer_len = mbedtls_mpi_size(&ecc_private_key->ecc_priv);
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    const int mbed_status = mbedtls_mpi_write_binary(
            &ecc_private_key->ecc_priv, vsc_buffer_unused_bytes(buffer), vsc_buffer_unused_len(buffer));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);
    vsc_buffer_inc_used(buffer, buffer_len);

    return vscf_raw_key_new_private_with_buffer(
            vscf_mbedtls_ecp_group_id_to_alg_id(ecc_private_key->ecc_grp.id), &buffer);
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_encrypt(const vscf_ecc_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    bool is_my_impl = vscf_key_impl_tag(public_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_encrypt(const vscf_ecc_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecc_encrypted_len(self, public_key, data.len));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    vscf_status_t status = vscf_ecies_encrypt(self->ecies, public_key, vscf_ecc_impl_const(self), data, out);
    return status;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ecc_encrypted_len(const vscf_ecc_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT_PTR(public_key);

    return vscf_ecies_encrypted_len(self->ecies, public_key, vscf_ecc_impl_const(self), data_len);
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_ecc_can_decrypt(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    bool is_my_impl = vscf_key_impl_tag(private_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_decrypt(const vscf_ecc_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecc_decrypted_len(self, private_key, data.len));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM;
    }


    vscf_status_t status = vscf_ecies_decrypt(self->ecies, private_key, vscf_ecc_impl_const(self), data, out);
    return status;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ecc_decrypted_len(const vscf_ecc_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT_PTR(private_key);

    return vscf_ecies_decrypted_len(self->ecies, private_key, vscf_ecc_impl_const(self), data_len);
}

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_sign(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    bool is_my_impl = vscf_key_impl_tag(private_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_ecc_signature_len(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_ecc_can_sign(self, private_key));

    //  ECDSA-Sig-Value ::= SEQUENCE {
    //      r INTEGER,
    //      s INTEGER
    //  }

    size_t len = 2 * vscf_key_len(private_key) + 9 /* mbedTLS requirement */;
    return len;
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_sign_hash(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_ecc_can_sign(self, private_key));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_ecc_signature_len(self, private_key));
    VSCF_ASSERT(vsc_data_is_valid(digest));

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_ECC_PUBLIC_KEY);
    const vscf_ecc_private_key_t *ecc_private_key = (const vscf_ecc_private_key_t *)private_key;


    mbedtls_ecp_group tmp_ecp_grp;
    mbedtls_ecp_group_init(&tmp_ecp_grp);
    int mbed_status = mbedtls_ecp_group_copy(&tmp_ecp_grp, &ecc_private_key->ecc_grp);
    VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MPI_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (self->random) {
        mbed_status = mbedtls_ecdsa_sign(&tmp_ecp_grp, &r, &s, &ecc_private_key->ecc_priv, digest.bytes, digest.len,
                vscf_mbedtls_bridge_random, (void *)self->random);
    } else {
        mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(hash_id);
        mbed_status = mbedtls_ecdsa_sign_det(
                &tmp_ecp_grp, &r, &s, &ecc_private_key->ecc_priv, digest.bytes, digest.len, md_alg);
    }

    if (mbed_status != 0) {
        goto cleanup;
    }

    vscf_ecc_write_signature(&r, &s, signature);

cleanup:
    mbedtls_ecp_group_free(&tmp_ecp_grp);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (MBEDTLS_ERR_ECP_RANDOM_FAILED == mbed_status) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);
    return vscf_status_SUCCESS;
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_verify(const vscf_ecc_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    bool is_my_impl = vscf_key_impl_tag(public_key) == self->info->impl_tag;
    return is_my_impl;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_ecc_verify_hash(const vscf_ecc_t *self, const vscf_impl_t *public_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_ecc_can_verify(self, public_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    vscf_status_t status = vscf_ecc_read_signature(signature, &r, &s);
    if (status != vscf_status_SUCCESS) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return false;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_ECC_PUBLIC_KEY);
    const vscf_ecc_public_key_t *ecc_public_key = (const vscf_ecc_public_key_t *)public_key;

    mbedtls_ecp_group tmp_ecp_grp;
    mbedtls_ecp_group_init(&tmp_ecp_grp);
    int mbed_status = mbedtls_ecp_group_copy(&tmp_ecp_grp, &ecc_public_key->ecc_grp);
    VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MPI_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);

    mbed_status = mbedtls_ecdsa_verify(&tmp_ecp_grp, digest.bytes, digest.len, &ecc_public_key->ecc_pub, &r, &s);

    mbedtls_ecp_group_free(&tmp_ecp_grp);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return 0 == mbed_status;
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, computed shared key can be used only within symmetric cryptography.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_compute_shared_key(const vscf_ecc_t *self, const vscf_impl_t *public_key, const vscf_impl_t *private_key,
        vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= vscf_ecc_shared_key_len(self, public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_ECC_PUBLIC_KEY);
    const vscf_ecc_public_key_t *ecc_public_key = (const vscf_ecc_public_key_t *)public_key;


    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_ECC_PRIVATE_KEY);
    const vscf_ecc_private_key_t *ecc_private_key = (const vscf_ecc_private_key_t *)private_key;

    if (ecc_public_key->ecc_grp.id != ecc_private_key->ecc_grp.id) {
        return vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED;
    }

    mbedtls_ecp_group tmp_ecp_grp;
    mbedtls_ecp_group_init(&tmp_ecp_grp);
    int mbed_status = mbedtls_ecp_group_copy(&tmp_ecp_grp, &ecc_public_key->ecc_grp);
    VSCF_ASSERT_ALLOC(mbed_status != MBEDTLS_ERR_MPI_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);

    mbedtls_mpi shared_key_mpi;
    mbedtls_mpi_init(&shared_key_mpi);

    int (*f_rng)(void *, byte *, size_t) = NULL;
    void *p_rng = NULL;

    if (self->random) {
        f_rng = vscf_mbedtls_bridge_random;
        p_rng = (void *)self->random;
    }

    mbed_status = mbedtls_ecdh_compute_shared(
            &tmp_ecp_grp, &shared_key_mpi, &ecc_public_key->ecc_pub, &ecc_private_key->ecc_priv, f_rng, p_rng);

    mbedtls_ecp_group_free(&tmp_ecp_grp);

    if (mbed_status != 0) {
        mbedtls_mpi_free(&shared_key_mpi);
        return vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED;
    }

    size_t shared_key_len = mbedtls_mpi_size(&shared_key_mpi);
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= shared_key_len);
    mbed_status = mbedtls_mpi_write_binary(&shared_key_mpi, vsc_buffer_unused_bytes(shared_key), shared_key_len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbed_status);

    vsc_buffer_inc_used(shared_key, shared_key_len);

    mbedtls_mpi_free(&shared_key_mpi);
    return vscf_status_SUCCESS;
}

//
//  Return number of bytes required to hold shared key.
//  Expect Public Key or Private Key.
//
VSCF_PUBLIC size_t
vscf_ecc_shared_key_len(const vscf_ecc_t *self, const vscf_impl_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    return MBEDTLS_ECP_MAX_BYTES;
}
