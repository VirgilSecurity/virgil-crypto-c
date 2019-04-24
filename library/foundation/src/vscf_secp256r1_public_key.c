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
//  This module contains 'secp256r1 public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_secp256r1_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_md.h"
#include "vscf_ec_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_ctr_drbg.h"
#include "vscf_secp256r1_private_key.h"
#include "vscf_alg_info.h"
#include "vscf_alg.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_random.h"
#include "vscf_secp256r1_public_key_defs.h"
#include "vscf_secp256r1_public_key_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vscf_secp256r1_public_key_KEY_LEN = 32,
    vscf_secp256r1_public_key_KEY_BITLEN = 256
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_secp256r1_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_secp256r1_public_key_init_ctx(vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_group_init(&self->ecp_group);
    mbedtls_ecp_point_init(&self->ecp);

    int status = mbedtls_ecp_group_load(&self->ecp_group, MBEDTLS_ECP_DP_SECP256R1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_secp256r1_public_key_cleanup_ctx(vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_group_free(&self->ecp_group);
    mbedtls_ecp_point_free(&self->ecp);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_setup_defaults(vscf_secp256r1_public_key_t *self) {

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
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_secp256r1_public_key_alg_id(const vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_SECP256R1;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_public_key_produce_alg_info(const vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ec_alg_info_t *ec_alg_info = vscf_ec_alg_info_new_with_members(
            vscf_alg_id_SECP256R1, vscf_oid_id_EC_GENERIC_KEY, vscf_oid_id_EC_DOMAIN_SECP256R1);

    return vscf_ec_alg_info_impl(ec_alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_restore_alg_info(vscf_secp256r1_public_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_impl_tag(alg_info) == vscf_impl_tag_EC_ALG_INFO);

    const vscf_ec_alg_info_t *ec_alg_info = (const vscf_ec_alg_info_t *)alg_info;

    if (vscf_ec_alg_info_key_id(ec_alg_info) != vscf_oid_id_EC_GENERIC_KEY) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    if (vscf_ec_alg_info_domain_id(ec_alg_info) != vscf_oid_id_EC_DOMAIN_SECP256R1) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    return vscf_status_SUCCESS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_key_len(const vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_secp256r1_public_key_KEY_LEN;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_key_bitlen(const vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_secp256r1_public_key_KEY_BITLEN;
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_encrypt(vscf_secp256r1_public_key_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_secp256r1_public_key_encrypted_len(self, data.len));
    VSCF_ASSERT(mbedtls_ecp_check_pubkey(&self->ecp_group, &self->ecp));

    vscf_ecies_use_encryption_key(self->ecies, vscf_secp256r1_public_key_impl(self));
    vscf_status_t status = vscf_ecies_encrypt(self->ecies, data, out);
    vscf_ecies_release_encryption_key(self->ecies);

    if (status != vscf_status_SUCCESS) {
        //  TODO: Log underlying error
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_encrypted_len(vscf_secp256r1_public_key_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);

    return vscf_ecies_encrypted_len(self->ecies, data_len);
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_secp256r1_public_key_verify_hash(
        vscf_secp256r1_public_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(hash_digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));
    VSCF_ASSERT(mbedtls_ecp_check_pubkey(&self->ecp_group, &self->ecp));
    VSCF_UNUSED(hash_id);

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    ctx.grp = self->ecp_group;
    ctx.Q = self->ecp;

    int status = mbedtls_ecdsa_read_signature(&ctx, hash_digest.bytes, hash_digest.len, signature.bytes, signature.len);

    return 0 == status;
}

//
//  Export public key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_export_public_key(const vscf_secp256r1_public_key_t *self, vsc_buffer_t *out) {

    //
    //  Export public key into Octet String (SEC1 2.3.3)
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(mbedtls_ecp_check_pubkey(&self->ecp_group, &self->ecp));

    size_t out_len = 0;
    int status = mbedtls_ecp_point_write_binary(&self->ecp_group, &self->ecp, MBEDTLS_ECP_PF_UNCOMPRESSED, &out_len,
            vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
    VSCF_ASSERT(out_len <= vsc_buffer_unused_len(out));
    vsc_buffer_inc_used(out, out_len);

    return vscf_status_SUCCESS;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_exported_public_key_len(const vscf_secp256r1_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return 2 * mbedtls_mpi_size(&self->ecp_group.P) + 1 /* compression flag */;
}

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_import_public_key(vscf_secp256r1_public_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));

    int status = mbedtls_ecp_point_read_binary(&self->ecp_group, &self->ecp, data.bytes, data.len);
    if (status != 0) {
        return vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY;
    }

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_public_key_generate_ephemeral_key(vscf_secp256r1_public_key_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    vscf_secp256r1_private_key_t *private_key = vscf_secp256r1_private_key_new();
    vscf_secp256r1_private_key_use_random(private_key, self->random);

    vscf_status_t status = vscf_secp256r1_private_key_generate_key(private_key);
    if (status != vscf_status_SUCCESS) {
        vscf_secp256r1_private_key_destroy(&private_key);
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    if (self->ecies) {
        vscf_secp256r1_private_key_use_ecies(private_key, self->ecies);
    }

    return vscf_secp256r1_private_key_impl(private_key);
}
