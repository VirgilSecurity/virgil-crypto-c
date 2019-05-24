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
//  This module contains 'secp256r1 private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_secp256r1_private_key.h"
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
#include "vscf_alg_info.h"
#include "vscf_alg.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_secp256r1_public_key_defs.h"
#include "vscf_random.h"
#include "vscf_secp256r1_private_key_defs.h"
#include "vscf_secp256r1_private_key_internal.h"

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
    vscf_secp256r1_private_key_KEY_LEN = 32,
    vscf_secp256r1_private_key_KEY_BITLEN = 256,
    vscf_secp256r1_private_key_SHARED_KEY_LEN = 32
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_secp256r1_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_secp256r1_private_key_init_ctx(vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_keypair_init(&self->ecp_keypair);
    int status = mbedtls_ecp_group_load(&self->ecp_keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_secp256r1_private_key_cleanup_ctx(vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_ecp_keypair_free(&self->ecp_keypair);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_setup_defaults(vscf_secp256r1_private_key_t *self) {

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
vscf_secp256r1_private_key_alg_id(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_SECP256R1;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_private_key_produce_alg_info(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ec_alg_info_t *ec_alg_info = vscf_ec_alg_info_new_with_members(
            vscf_alg_id_SECP256R1, vscf_oid_id_EC_GENERIC_KEY, vscf_oid_id_EC_DOMAIN_SECP256R1);

    return vscf_ec_alg_info_impl(ec_alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_restore_alg_info(vscf_secp256r1_private_key_t *self, const vscf_impl_t *alg_info) {

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
vscf_secp256r1_private_key_key_len(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_secp256r1_private_key_KEY_LEN;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_secp256r1_private_key_key_bitlen(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_secp256r1_private_key_KEY_BITLEN;
}

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_generate_key(vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    int status = mbedtls_ecp_gen_keypair(&self->ecp_keypair.grp, &self->ecp_keypair.d, &self->ecp_keypair.Q,
            vscf_mbedtls_bridge_random, self->random);

    return status == 0 ? vscf_status_SUCCESS : vscf_status_ERROR_KEY_GENERATION_FAILED;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_decrypt(vscf_secp256r1_private_key_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_secp256r1_private_key_decrypted_len(self, data.len));

    vscf_ecies_use_decryption_key(self->ecies, vscf_secp256r1_private_key_impl(self));
    vscf_status_t status = vscf_ecies_decrypt(self->ecies, data, out);
    vscf_ecies_release_decryption_key(self->ecies);

    if (status != vscf_status_SUCCESS) {
        //  TODO: Log underlying error
        return vscf_status_ERROR_BAD_ENCRYPTED_DATA;
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_secp256r1_private_key_decrypted_len(vscf_secp256r1_private_key_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ecies);

    return vscf_ecies_decrypted_len(self->ecies, data_len);
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_secp256r1_private_key_signature_len(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  ECDSA-Sig-Value ::= SEQUENCE {
    //      r INTEGER,
    //      s INTEGER
    //  }

    size_t len = 2 * vscf_secp256r1_private_key_key_len(self) + 9 /* mbedTLS requirement */;
    return len;
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_sign_hash(
        vscf_secp256r1_private_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&self->ecp_keypair.grp, &self->ecp_keypair.d));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_secp256r1_private_key_signature_len(self));
    VSCF_ASSERT(vsc_data_is_valid(hash_digest));

    mbedtls_md_type_t md_alg = vscf_mbedtls_md_from_alg_id(hash_id);
    size_t signature_len = vsc_buffer_unused_len(signature);

    int (*f_rng)(void *, byte *, size_t) = NULL;
    void *p_rng = NULL;

    if (self->random) {
        f_rng = vscf_mbedtls_bridge_random;
        p_rng = self->random;
    }

    int status = mbedtls_ecdsa_write_signature(&self->ecp_keypair, md_alg, hash_digest.bytes, hash_digest.len,
            vsc_buffer_unused_bytes(signature), &signature_len, f_rng, p_rng);

    if (MBEDTLS_ERR_ECP_RANDOM_FAILED == status) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
    vsc_buffer_inc_used(signature, signature_len);

    return vscf_status_SUCCESS;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_private_key_extract_public_key(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(0 == mbedtls_ecp_check_pubkey(&self->ecp_keypair.grp, &self->ecp_keypair.Q));

    vscf_secp256r1_public_key_t *secp256r1_public_key = vscf_secp256r1_public_key_new();


    int status = mbedtls_ecp_group_copy(&secp256r1_public_key->ecp_group, &self->ecp_keypair.grp);
    VSCF_ASSERT_ALLOC(status == 0);

    status = mbedtls_ecp_copy(&secp256r1_public_key->ecp, &self->ecp_keypair.Q);
    VSCF_ASSERT_ALLOC(status == 0);

    if (self->random) {
        vscf_secp256r1_public_key_use_random(secp256r1_public_key, self->random);
    }

    if (self->ecies) {
        vscf_secp256r1_public_key_use_ecies(secp256r1_public_key, self->ecies);
    }

    return vscf_secp256r1_public_key_impl(secp256r1_public_key);
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_export_private_key(const vscf_secp256r1_private_key_t *self, vsc_buffer_t *out) {

    //
    //  Export private key into Octet String (SEC1 2.3.7)
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&self->ecp_keypair.grp, &self->ecp_keypair.d));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_secp256r1_private_key_exported_private_key_len(self));

    size_t len = mbedtls_mpi_size(&self->ecp_keypair.d);

    int status = mbedtls_mpi_write_binary(&self->ecp_keypair.d, vsc_buffer_unused_bytes(out), len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vsc_buffer_inc_used(out, len);

    return vscf_status_SUCCESS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_secp256r1_private_key_exported_private_key_len(const vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&self->ecp_keypair.grp, &self->ecp_keypair.d));

    return mbedtls_mpi_size(&self->ecp_keypair.d);
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_import_private_key(vscf_secp256r1_private_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));

    int status = mbedtls_mpi_read_binary(&self->ecp_keypair.d, data.bytes, data.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    status = mbedtls_mpi_read_binary(&self->ecp_keypair.d, data.bytes, data.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    if (0 != mbedtls_ecp_check_privkey(&self->ecp_keypair.grp, &self->ecp_keypair.d)) {
        return vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY;
    }

    int (*f_rng)(void *, byte *, size_t) = NULL;
    void *p_rng = NULL;

    if (self->random) {
        f_rng = vscf_mbedtls_bridge_random;
        p_rng = self->random;
    }

    status = mbedtls_ecp_mul(
            &self->ecp_keypair.grp, &self->ecp_keypair.Q, &self->ecp_keypair.d, &self->ecp_keypair.grp.G, f_rng, p_rng);

    if (MBEDTLS_ERR_ECP_RANDOM_FAILED == status) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    return vscf_status_SUCCESS;
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, shared key can be used only for symmetric cryptography.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_private_key_compute_shared_key(
        vscf_secp256r1_private_key_t *self, const vscf_impl_t *public_key, vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(0 == mbedtls_ecp_check_privkey(&self->ecp_keypair.grp, &self->ecp_keypair.d));
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_SECP256R1_PUBLIC_KEY);
    VSCF_ASSERT_PTR(shared_key);
    VSCF_ASSERT(vsc_buffer_is_valid(shared_key));
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= vscf_secp256r1_private_key_shared_key_len(self));

    const vscf_secp256r1_public_key_t *secp256r1_public_key = (const vscf_secp256r1_public_key_t *)public_key;

    if (self->ecp_keypair.grp.id != secp256r1_public_key->ecp_group.id) {
        return vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED;
    }

    VSCF_ASSERT(0 == mbedtls_ecp_check_pubkey(&secp256r1_public_key->ecp_group, &secp256r1_public_key->ecp));

    int (*f_rng)(void *, byte *, size_t) = NULL;
    void *p_rng = NULL;

    if (self->random) {
        f_rng = vscf_mbedtls_bridge_random;
        p_rng = self->random;
    }

    mbedtls_mpi shared_key_mpi;
    mbedtls_mpi_init(&shared_key_mpi);

    int status = mbedtls_ecdh_compute_shared(
            &self->ecp_keypair.grp, &shared_key_mpi, &secp256r1_public_key->ecp, &self->ecp_keypair.d, f_rng, p_rng);

    if (MBEDTLS_ERR_ECP_RANDOM_FAILED == status) {
        mbedtls_mpi_free(&shared_key_mpi);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    size_t shared_key_len = mbedtls_mpi_size(&shared_key_mpi);
    VSCF_ASSERT(vsc_buffer_unused_len(shared_key) >= shared_key_len);
    status = mbedtls_mpi_write_binary(&shared_key_mpi, vsc_buffer_unused_bytes(shared_key), shared_key_len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vsc_buffer_inc_used(shared_key, shared_key_len);

    mbedtls_mpi_free(&shared_key_mpi);
    return vscf_status_SUCCESS;
}

//
//  Return number of bytes required to hold shared key.
//
VSCF_PUBLIC size_t
vscf_secp256r1_private_key_shared_key_len(vscf_secp256r1_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_secp256r1_private_key_SHARED_KEY_LEN;
}
