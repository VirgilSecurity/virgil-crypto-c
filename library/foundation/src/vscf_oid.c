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
//  Provide conversion logic between OID and algorithm tags.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_oid.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

// clang-format on
//  @end


static const byte oid_rsa_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
static const vsc_data_t oid_rsa = {oid_rsa_bytes, sizeof(oid_rsa_bytes)};

static const byte oid_ed25519_bytes[] = {0x2B, 0x65, 0x70};
static const vsc_data_t oid_ed25519 = {oid_ed25519_bytes, sizeof(oid_ed25519_bytes)};

static const byte oid_curve25519_bytes[] = {0x2B, 0x65, 0x6E};
static const vsc_data_t oid_curve25519 = {oid_curve25519_bytes, sizeof(oid_curve25519_bytes)};

static const byte oid_sha224_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04};
static const vsc_data_t oid_sha224 = {oid_sha224_bytes, sizeof(oid_sha224_bytes)};

static const byte oid_sha256_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
static const vsc_data_t oid_sha256 = {oid_sha256_bytes, sizeof(oid_sha256_bytes)};

static const byte oid_sha384_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
static const vsc_data_t oid_sha384 = {oid_sha384_bytes, sizeof(oid_sha384_bytes)};

static const byte oid_sha512_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
static const vsc_data_t oid_sha512 = {oid_sha512_bytes, sizeof(oid_sha512_bytes)};

static const byte oid_kdf1_bytes[] = {0x28, 0x81, 0x8C, 0x71, 0x02, 0x05, 0x01};
static const vsc_data_t oid_kdf1 = {oid_kdf1_bytes, sizeof(oid_kdf1_bytes)};

static const byte oid_kdf2_bytes[] = {0x28, 0x81, 0x8C, 0x71, 0x02, 0x05, 0x02};
static const vsc_data_t oid_kdf2 = {oid_kdf2_bytes, sizeof(oid_kdf2_bytes)};

static const byte oid_aes256_gcm_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E};
static const vsc_data_t oid_aes256_gcm = {oid_aes256_gcm_bytes, sizeof(oid_aes256_gcm_bytes)};

static const byte oid_aes256_cbc_bytes[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A};
static const vsc_data_t oid_aes256_cbc = {oid_aes256_cbc_bytes, sizeof(oid_aes256_cbc_bytes)};

static const byte oid_cms_data_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
static const vsc_data_t oid_cms_data = {oid_cms_data_bytes, sizeof(oid_cms_data_bytes)};

static const byte oid_cms_data_enveloped_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03};
static const vsc_data_t oid_cms_enveloped_data = {oid_cms_data_enveloped_bytes, sizeof(oid_cms_data_enveloped_bytes)};

static const byte oid_pkcs5_pbkdf2_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};
static const vsc_data_t oid_pkcs5_pbkdf2 = {oid_pkcs5_pbkdf2_bytes, sizeof(oid_pkcs5_pbkdf2_bytes)};

static const byte oid_pkcs5_pbes2_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D};
static const vsc_data_t oid_pkcs5_pbes2 = {oid_pkcs5_pbes2_bytes, sizeof(oid_pkcs5_pbes2_bytes)};

static const byte oid_hmac_with_sha224_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08};
static const vsc_data_t oid_hmac_with_sha224 = {oid_hmac_with_sha224_bytes, sizeof(oid_hmac_with_sha224_bytes)};

static const byte oid_hmac_with_sha256_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09};
static const vsc_data_t oid_hmac_with_sha256 = {oid_hmac_with_sha256_bytes, sizeof(oid_hmac_with_sha256_bytes)};

static const byte oid_hmac_with_sha384_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A};
static const vsc_data_t oid_hmac_with_sha384 = {oid_hmac_with_sha384_bytes, sizeof(oid_hmac_with_sha384_bytes)};

static const byte oid_hmac_with_sha512_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B};
static const vsc_data_t oid_hmac_with_sha512 = {oid_hmac_with_sha512_bytes, sizeof(oid_hmac_with_sha512_bytes)};

static const byte oid_hkdf_with_sha256_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1C};
static const vsc_data_t oid_hkdf_with_sha256 = {oid_hkdf_with_sha256_bytes, sizeof(oid_hkdf_with_sha256_bytes)};

static const byte oid_hkdf_with_sha384_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1D};
static const vsc_data_t oid_hkdf_with_sha384 = {oid_hkdf_with_sha384_bytes, sizeof(oid_hkdf_with_sha384_bytes)};

static const byte oid_hkdf_with_sha512_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1E};
static const vsc_data_t oid_hkdf_with_sha512 = {oid_hkdf_with_sha512_bytes, sizeof(oid_hkdf_with_sha512_bytes)};

static const byte oid_ec_generic_key_bytes[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const vsc_data_t oid_ec_generic_key = {oid_ec_generic_key_bytes, sizeof(oid_ec_generic_key_bytes)};

static const byte oid_ec_domain_secp256r1_bytes[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const vsc_data_t oid_ec_domain_secp256r1 = {
        oid_ec_domain_secp256r1_bytes, sizeof(oid_ec_domain_secp256r1_bytes)};

// --------------------------------------------------------------------------
//  Managed by Virgil Security, Inc.
//
//  1.3.6.1.4.1.54811.1.1
//  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) virgil-security(54811)
//  crypto(1) compound-key(1)
//
static const byte oid_compound_key_bytes[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x01};
static const vsc_data_t oid_compound_key = {oid_compound_key_bytes, sizeof(oid_compound_key_bytes)};

//  1.3.6.1.4.1.54811.1.2
//  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) virgil-security(54811)
//  crypto(1) hybrid-key(2)
//
static const byte oid_hybrid_key_bytes[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x02};
static const vsc_data_t oid_hybrid_key = {oid_hybrid_key_bytes, sizeof(oid_hybrid_key_bytes)};

//  1.3.6.1.4.1.54811.1.3
//  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) virgil-security(54811)
//  crypto(1) random-padding(3)
//
static const byte oid_random_padding_bytes[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x03};
static const vsc_data_t oid_random_padding = {oid_random_padding_bytes, sizeof(oid_random_padding_bytes)};

//
//  1.3.6.1.4.1.54811.2.1
//  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) virgil-security(54811)
//  post-quantum-crypto(2) falcon(1)
//
static const byte oid_falcon_bytes[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x02, 0x01};
static const vsc_data_t oid_falcon = {oid_falcon_bytes, sizeof(oid_falcon_bytes)};

//
//  1.3.6.1.4.1.54811.2.2.11
//  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) virgil-security(54811)
//  post-quantum-crypto(2) round5(2) nd-5cca-5d(11)
//
static const byte oid_round5_cca_ND_5CCA_5D_bytes[] = {
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x02, 0x02, 0x0B};
static const vsc_data_t oid_round5_cca_ND_5CCA_5D = {
        oid_round5_cca_ND_5CCA_5D_bytes, sizeof(oid_round5_cca_ND_5CCA_5D_bytes)};
//
// --------------------------------------------------------------------------


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
//  Return OID for given algorithm identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_oid_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_RSA:
        return oid_rsa;

    case vscf_alg_id_ED25519:
        return oid_ed25519;

    case vscf_alg_id_CURVE25519:
        return oid_curve25519;

    case vscf_alg_id_SHA224:
        return oid_sha224;

    case vscf_alg_id_SHA256:
        return oid_sha256;

    case vscf_alg_id_SHA384:
        return oid_sha384;

    case vscf_alg_id_SHA512:
        return oid_sha512;

    case vscf_alg_id_KDF1:
        return oid_kdf1;

    case vscf_alg_id_KDF2:
        return oid_kdf2;

    case vscf_alg_id_AES256_GCM:
        return oid_aes256_gcm;

    case vscf_alg_id_AES256_CBC:
        return oid_aes256_cbc;

    case vscf_alg_id_PKCS5_PBKDF2:
        return oid_pkcs5_pbkdf2;

    case vscf_alg_id_PKCS5_PBES2:
        return oid_pkcs5_pbes2;

    case vscf_alg_id_COMPOUND_KEY:
        return oid_compound_key;

    case vscf_alg_id_HYBRID_KEY:
        return oid_hybrid_key;

    case vscf_alg_id_FALCON:
        return oid_falcon;

    case vscf_alg_id_ROUND5_ND_5CCA_5D:
        return oid_round5_cca_ND_5CCA_5D;

    case vscf_alg_id_RANDOM_PADDING:
        return oid_random_padding;

    default:
        VSCF_ASSERT(0 && "Unhandled algorithm identifier");
        return vsc_data_empty();
    }
}

//
//  Return algorithm identifier for given OID.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_oid_to_alg_id(vsc_data_t oid) {

    VSCF_ASSERT(vsc_data_is_valid(oid));

    if (vscf_oid_equal(oid, oid_rsa)) {
        return vscf_alg_id_RSA;
    }

    if (vscf_oid_equal(oid, oid_ed25519)) {
        return vscf_alg_id_ED25519;
    }

    if (vscf_oid_equal(oid, oid_curve25519)) {
        return vscf_alg_id_CURVE25519;
    }

    if (vscf_oid_equal(oid, oid_sha224)) {
        return vscf_alg_id_SHA224;
    }

    if (vscf_oid_equal(oid, oid_sha256)) {
        return vscf_alg_id_SHA256;
    }

    if (vscf_oid_equal(oid, oid_sha384)) {
        return vscf_alg_id_SHA384;
    }

    if (vscf_oid_equal(oid, oid_sha512)) {
        return vscf_alg_id_SHA512;
    }

    if (vscf_oid_equal(oid, oid_kdf1)) {
        return vscf_alg_id_KDF1;
    }

    if (vscf_oid_equal(oid, oid_kdf2)) {
        return vscf_alg_id_KDF2;
    }

    if (vscf_oid_equal(oid, oid_aes256_gcm)) {
        return vscf_alg_id_AES256_GCM;
    }

    if (vscf_oid_equal(oid, oid_aes256_cbc)) {
        return vscf_alg_id_AES256_CBC;
    }

    if (vscf_oid_equal(oid, oid_pkcs5_pbkdf2)) {
        return vscf_alg_id_PKCS5_PBKDF2;
    }

    if (vscf_oid_equal(oid, oid_pkcs5_pbes2)) {
        return vscf_alg_id_PKCS5_PBES2;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha224)) {
        return vscf_alg_id_HMAC;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha256)) {
        return vscf_alg_id_HMAC;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha384)) {
        return vscf_alg_id_HMAC;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha512)) {
        return vscf_alg_id_HMAC;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha256)) {
        return vscf_alg_id_HKDF;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha384)) {
        return vscf_alg_id_HKDF;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha512)) {
        return vscf_alg_id_HKDF;
    }

    if (vscf_oid_equal(oid, oid_compound_key)) {
        return vscf_alg_id_COMPOUND_KEY;
    }

    if (vscf_oid_equal(oid, oid_hybrid_key)) {
        return vscf_alg_id_HYBRID_KEY;
    }

    if (vscf_oid_equal(oid, oid_falcon)) {
        return vscf_alg_id_FALCON;
    }

    if (vscf_oid_equal(oid, oid_round5_cca_ND_5CCA_5D)) {
        return vscf_alg_id_ROUND5_ND_5CCA_5D;
    }

    if (vscf_oid_equal(oid, oid_random_padding)) {
        return vscf_alg_id_RANDOM_PADDING;
    }

    return vscf_alg_id_NONE;
}

//
//  Return OID for a given identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_oid_from_id(vscf_oid_id_t oid_id) {

    switch (oid_id) {

    case vscf_oid_id_RSA:
        return oid_rsa;

    case vscf_oid_id_ED25519:
        return oid_ed25519;

    case vscf_oid_id_CURVE25519:
        return oid_curve25519;

    case vscf_oid_id_SHA224:
        return oid_sha224;

    case vscf_oid_id_SHA256:
        return oid_sha256;

    case vscf_oid_id_SHA384:
        return oid_sha384;

    case vscf_oid_id_SHA512:
        return oid_sha512;

    case vscf_oid_id_KDF1:
        return oid_kdf1;

    case vscf_oid_id_KDF2:
        return oid_kdf2;

    case vscf_oid_id_AES256_GCM:
        return oid_aes256_gcm;

    case vscf_oid_id_AES256_CBC:
        return oid_aes256_cbc;

    case vscf_oid_id_PKCS5_PBKDF2:
        return oid_pkcs5_pbkdf2;

    case vscf_oid_id_PKCS5_PBES2:
        return oid_pkcs5_pbes2;

    case vscf_oid_id_CMS_DATA:
        return oid_cms_data;

    case vscf_oid_id_CMS_ENVELOPED_DATA:
        return oid_cms_enveloped_data;

    case vscf_oid_id_HMAC_WITH_SHA224:
        return oid_hmac_with_sha224;

    case vscf_oid_id_HMAC_WITH_SHA256:
        return oid_hmac_with_sha256;

    case vscf_oid_id_HMAC_WITH_SHA384:
        return oid_hmac_with_sha384;

    case vscf_oid_id_HMAC_WITH_SHA512:
        return oid_hmac_with_sha512;

    case vscf_oid_id_HKDF_WITH_SHA256:
        return oid_hkdf_with_sha256;

    case vscf_oid_id_HKDF_WITH_SHA384:
        return oid_hkdf_with_sha384;

    case vscf_oid_id_HKDF_WITH_SHA512:
        return oid_hkdf_with_sha512;

    case vscf_oid_id_EC_GENERIC_KEY:
        return oid_ec_generic_key;

    case vscf_oid_id_EC_DOMAIN_SECP256R1:
        return oid_ec_domain_secp256r1;

    case vscf_oid_id_COMPOUND_KEY:
        return oid_compound_key;

    case vscf_oid_id_HYBRID_KEY:
        return oid_hybrid_key;

    case vscf_oid_id_FALCON:
        return oid_falcon;

    case vscf_oid_id_ROUND5_ND_5CCA_5D:
        return oid_round5_cca_ND_5CCA_5D;

    case vscf_oid_id_RANDOM_PADDING:
        return oid_random_padding;

    default:
        VSCF_ASSERT(0 && "Unhandled oid identifier");
        return vsc_data_empty();
    }
}

//
//  Return identifier for a given OID.
//
VSCF_PUBLIC vscf_oid_id_t
vscf_oid_to_id(vsc_data_t oid) {

    VSCF_ASSERT(vsc_data_is_valid(oid));

    if (vscf_oid_equal(oid, oid_rsa)) {
        return vscf_oid_id_RSA;
    }

    if (vscf_oid_equal(oid, oid_ed25519)) {
        return vscf_oid_id_ED25519;
    }

    if (vscf_oid_equal(oid, oid_curve25519)) {
        return vscf_oid_id_CURVE25519;
    }

    if (vscf_oid_equal(oid, oid_sha224)) {
        return vscf_oid_id_SHA224;
    }

    if (vscf_oid_equal(oid, oid_sha256)) {
        return vscf_oid_id_SHA256;
    }

    if (vscf_oid_equal(oid, oid_sha384)) {
        return vscf_oid_id_SHA384;
    }

    if (vscf_oid_equal(oid, oid_sha512)) {
        return vscf_oid_id_SHA512;
    }

    if (vscf_oid_equal(oid, oid_kdf1)) {
        return vscf_oid_id_KDF1;
    }

    if (vscf_oid_equal(oid, oid_kdf2)) {
        return vscf_oid_id_KDF2;
    }

    if (vscf_oid_equal(oid, oid_aes256_gcm)) {
        return vscf_oid_id_AES256_GCM;
    }

    if (vscf_oid_equal(oid, oid_aes256_cbc)) {
        return vscf_oid_id_AES256_CBC;
    }

    if (vscf_oid_equal(oid, oid_pkcs5_pbkdf2)) {
        return vscf_oid_id_PKCS5_PBKDF2;
    }

    if (vscf_oid_equal(oid, oid_pkcs5_pbes2)) {
        return vscf_oid_id_PKCS5_PBES2;
    }

    if (vscf_oid_equal(oid, oid_cms_data)) {
        return vscf_oid_id_CMS_DATA;
    }

    if (vscf_oid_equal(oid, oid_cms_enveloped_data)) {
        return vscf_oid_id_CMS_ENVELOPED_DATA;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha224)) {
        return vscf_oid_id_HMAC_WITH_SHA224;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha256)) {
        return vscf_oid_id_HMAC_WITH_SHA256;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha384)) {
        return vscf_oid_id_HMAC_WITH_SHA384;
    }

    if (vscf_oid_equal(oid, oid_hmac_with_sha512)) {
        return vscf_oid_id_HMAC_WITH_SHA512;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha256)) {
        return vscf_oid_id_HKDF_WITH_SHA256;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha384)) {
        return vscf_oid_id_HKDF_WITH_SHA384;
    }

    if (vscf_oid_equal(oid, oid_hkdf_with_sha512)) {
        return vscf_oid_id_HKDF_WITH_SHA512;
    }

    if (vscf_oid_equal(oid, oid_ec_generic_key)) {
        return vscf_oid_id_EC_GENERIC_KEY;
    }

    if (vscf_oid_equal(oid, oid_ec_domain_secp256r1)) {
        return vscf_oid_id_EC_DOMAIN_SECP256R1;
    }

    if (vscf_oid_equal(oid, oid_compound_key)) {
        return vscf_oid_id_COMPOUND_KEY;
    }

    if (vscf_oid_equal(oid, oid_hybrid_key)) {
        return vscf_oid_id_HYBRID_KEY;
    }

    if (vscf_oid_equal(oid, oid_falcon)) {
        return vscf_oid_id_FALCON;
    }

    if (vscf_oid_equal(oid, oid_round5_cca_ND_5CCA_5D)) {
        return vscf_oid_id_ROUND5_ND_5CCA_5D;
    }

    if (vscf_oid_equal(oid, oid_random_padding)) {
        return vscf_oid_id_RANDOM_PADDING;
    }

    return vscf_oid_id_NONE;
}

//
//  Map oid identifier to the algorithm identifier.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_oid_id_to_alg_id(vscf_oid_id_t oid_id) {

    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    switch (oid_id) {
    case vscf_oid_id_RSA:
        return vscf_alg_id_RSA;

    case vscf_oid_id_ED25519:
        return vscf_alg_id_ED25519;

    case vscf_oid_id_CURVE25519:
        return vscf_alg_id_CURVE25519;

    case vscf_oid_id_SHA224:
        return vscf_alg_id_SHA224;

    case vscf_oid_id_SHA256:
        return vscf_alg_id_SHA256;

    case vscf_oid_id_SHA384:
        return vscf_alg_id_SHA384;

    case vscf_oid_id_SHA512:
        return vscf_alg_id_SHA512;

    case vscf_oid_id_KDF1:
        return vscf_alg_id_KDF1;

    case vscf_oid_id_KDF2:
        return vscf_alg_id_KDF2;

    case vscf_oid_id_AES256_GCM:
        return vscf_alg_id_AES256_GCM;

    case vscf_oid_id_AES256_CBC:
        return vscf_alg_id_AES256_CBC;

    case vscf_oid_id_PKCS5_PBKDF2:
        return vscf_alg_id_PKCS5_PBKDF2;

    case vscf_oid_id_PKCS5_PBES2:
        return vscf_alg_id_PKCS5_PBES2;

    case vscf_oid_id_HMAC_WITH_SHA256:
    case vscf_oid_id_HMAC_WITH_SHA384:
    case vscf_oid_id_HMAC_WITH_SHA512:
        return vscf_alg_id_HMAC;

    case vscf_oid_id_HMAC_WITH_SHA224:
    case vscf_oid_id_HKDF_WITH_SHA256:
    case vscf_oid_id_HKDF_WITH_SHA384:
    case vscf_oid_id_HKDF_WITH_SHA512:
        return vscf_alg_id_HKDF;

    case vscf_oid_id_EC_DOMAIN_SECP256R1:
        return vscf_alg_id_SECP256R1;

    case vscf_oid_id_COMPOUND_KEY:
        return vscf_alg_id_COMPOUND_KEY;

    case vscf_oid_id_FALCON:
        return vscf_alg_id_FALCON;

    case vscf_oid_id_ROUND5_ND_5CCA_5D:
        return vscf_alg_id_ROUND5_ND_5CCA_5D;

    case vscf_oid_id_RANDOM_PADDING:
        return vscf_alg_id_RANDOM_PADDING;

    case vscf_oid_id_EC_GENERIC_KEY:
    case vscf_oid_id_CMS_ENVELOPED_DATA:
    case vscf_oid_id_CMS_DATA:
    default:
        VSCF_ASSERT(0 && "Given OID identifier has no direct mapping to the algorithm identifier.");
        return vscf_alg_id_NONE;
    }
}

//
//  Return true if given OIDs are equal.
//
VSCF_PUBLIC bool
vscf_oid_equal(vsc_data_t lhs, vsc_data_t rhs) {

    VSCF_ASSERT(vsc_data_is_valid(lhs));
    VSCF_ASSERT(vsc_data_is_valid(rhs));

    if (lhs.len != rhs.len) {
        return false;
    }

    bool is_equal = memcmp(lhs.bytes, rhs.bytes, rhs.len) == 0;
    return is_equal;
}

//
//  Return string representation of the given OID.
//
VSCF_PRIVATE void
vscf_oid_to_string(vsc_data_t oid, char str[64]) {

    VSCF_ASSERT(vsc_data_is_valid(oid));
    VSCF_ASSERT_PTR(str);

    //  TODO: Implement this method.
    vscf_zeroize(str, 64);
}
