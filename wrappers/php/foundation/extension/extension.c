//
// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>
#include "vscf_assert.h"
#include "vscf_message_info.h"
#include "vscf_key_recipient_info.h"
#include "vscf_key_recipient_info_list.h"
#include "vscf_password_recipient_info.h"
#include "vscf_password_recipient_info_list.h"
#include "vscf_ecies.h"
#include "vscf_recipient_cipher.h"
#include "vscf_message_info_custom_params.h"
#include "vscf_key_provider.h"
#include "vscf_signer.h"
#include "vscf_verifier.h"
#include "vscf_brainkey_client.h"
#include "vscf_brainkey_server.h"
#include "vscf_group_session_message.h"
#include "vscf_group_session_ticket.h"
#include "vscf_group_session.h"
#include "vscf_message_info_editor.h"
#include "vscf_signer_info.h"
#include "vscf_signer_info_list.h"
#include "vscf_message_info_footer.h"
#include "vscf_signed_data_info.h"
#include "vscf_footer_info.h"
#include "vscf_sha224.h"
#include "vscf_sha256.h"
#include "vscf_sha384.h"
#include "vscf_sha512.h"
#include "vscf_aes256_gcm.h"
#include "vscf_aes256_cbc.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_rsa_public_key.h"
#include "vscf_rsa_private_key.h"
#include "vscf_rsa.h"
#include "vscf_ecc_public_key.h"
#include "vscf_ecc_private_key.h"
#include "vscf_ecc.h"
#include "vscf_entropy_accumulator.h"
#include "vscf_ctr_drbg.h"
#include "vscf_hmac.h"
#include "vscf_hkdf.h"
#include "vscf_kdf1.h"
#include "vscf_kdf2.h"
#include "vscf_fake_random.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_pkcs5_pbes2.h"
#include "vscf_seed_entropy_source.h"
#include "vscf_key_material_rng.h"
#include "vscf_raw_public_key.h"
#include "vscf_raw_private_key.h"
#include "vscf_pkcs8_serializer.h"
#include "vscf_sec1_serializer.h"
#include "vscf_key_asn1_serializer.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_ed25519.h"
#include "vscf_curve25519.h"
#include "vscf_simple_alg_info.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_ecc_alg_info.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_message_info_der_serializer.h"

#define VSCF_HANDLE_STATUS(status) do { if(status != vscf_status_SUCCESS) { vscf_handle_throw_exception(status); goto fail; } } while (false)

void
vscf_handle_throw_exception(vscf_status_t status) {
    switch(status) {

    case vscf_status_ERROR_BAD_ARGUMENTS:
        zend_throw_exception(NULL, "VSCF: This error should not be returned if assertions is enabled.", -1);
        break;
    case vscf_status_ERROR_UNINITIALIZED:
        zend_throw_exception(NULL, "VSCF: Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.", -2);
        break;
    case vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR:
        zend_throw_exception(NULL, "VSCF: Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.", -3);
        break;
    case vscf_status_ERROR_SMALL_BUFFER:
        zend_throw_exception(NULL, "VSCF: Buffer capacity is not enough to hold result.", -101);
        break;
    case vscf_status_ERROR_UNSUPPORTED_ALGORITHM:
        zend_throw_exception(NULL, "VSCF: Unsupported algorithm.", -200);
        break;
    case vscf_status_ERROR_AUTH_FAILED:
        zend_throw_exception(NULL, "VSCF: Authentication failed during decryption.", -201);
        break;
    case vscf_status_ERROR_OUT_OF_DATA:
        zend_throw_exception(NULL, "VSCF: Attempt to read data out of buffer bounds.", -202);
        break;
    case vscf_status_ERROR_BAD_ASN1:
        zend_throw_exception(NULL, "VSCF: ASN.1 encoded data is corrupted.", -203);
        break;
    case vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING:
        zend_throw_exception(NULL, "VSCF: Attempt to read ASN.1 type that is bigger then requested C type.", -204);
        break;
    case vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of PKCS#1 public key is corrupted.", -205);
        break;
    case vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of PKCS#1 private key is corrupted.", -206);
        break;
    case vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of PKCS#8 public key is corrupted.", -207);
        break;
    case vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of PKCS#8 private key is corrupted.", -208);
        break;
    case vscf_status_ERROR_BAD_ENCRYPTED_DATA:
        zend_throw_exception(NULL, "VSCF: Encrypted data is corrupted.", -209);
        break;
    case vscf_status_ERROR_RANDOM_FAILED:
        zend_throw_exception(NULL, "VSCF: Underlying random operation returns error.", -210);
        break;
    case vscf_status_ERROR_KEY_GENERATION_FAILED:
        zend_throw_exception(NULL, "VSCF: Generation of the private or secret key failed.", -211);
        break;
    case vscf_status_ERROR_ENTROPY_SOURCE_FAILED:
        zend_throw_exception(NULL, "VSCF: One of the entropy sources failed.", -212);
        break;
    case vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG:
        zend_throw_exception(NULL, "VSCF: Requested data to be generated is too big.", -213);
        break;
    case vscf_status_ERROR_BAD_BASE64:
        zend_throw_exception(NULL, "VSCF: Base64 encoded string contains invalid characters.", -214);
        break;
    case vscf_status_ERROR_BAD_PEM:
        zend_throw_exception(NULL, "VSCF: PEM data is corrupted.", -215);
        break;
    case vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED:
        zend_throw_exception(NULL, "VSCF: Exchange key return zero.", -216);
        break;
    case vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: Ed25519 public key is corrupted.", -217);
        break;
    case vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: Ed25519 private key is corrupted.", -218);
        break;
    case vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: CURVE25519 public key is corrupted.", -219);
        break;
    case vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: CURVE25519 private key is corrupted.", -220);
        break;
    case vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: Elliptic curve public key format is corrupted see RFC 5480.", -221);
        break;
    case vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: Elliptic curve public key format is corrupted see RFC 5915.", -222);
        break;
    case vscf_status_ERROR_BAD_DER_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of a public key is corrupted.", -223);
        break;
    case vscf_status_ERROR_BAD_DER_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCF: ASN.1 representation of a private key is corrupted.", -224);
        break;
    case vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM:
        zend_throw_exception(NULL, "VSCF: Key algorithm does not accept given type of public key.", -225);
        break;
    case vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM:
        zend_throw_exception(NULL, "VSCF: Key algorithm does not accept given type of private key.", -226);
        break;
    case vscf_status_ERROR_NO_MESSAGE_INFO:
        zend_throw_exception(NULL, "VSCF: Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.", -301);
        break;
    case vscf_status_ERROR_BAD_MESSAGE_INFO:
        zend_throw_exception(NULL, "VSCF: Message Info is corrupted.", -302);
        break;
    case vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
        zend_throw_exception(NULL, "VSCF: Recipient defined with id is not found within message info during data decryption.", -303);
        break;
    case vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
        zend_throw_exception(NULL, "VSCF: Content encryption key can not be decrypted with a given private key.", -304);
        break;
    case vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
        zend_throw_exception(NULL, "VSCF: Content encryption key can not be decrypted with a given password.", -305);
        break;
    case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
        zend_throw_exception(NULL, "VSCF: Custom parameter with a given key is not found within message info.", -306);
        break;
    case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
        zend_throw_exception(NULL, "VSCF: A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.", -307);
        break;
    case vscf_status_ERROR_BAD_SIGNATURE:
        zend_throw_exception(NULL, "VSCF: Signature format is corrupted.", -308);
        break;
    case vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER:
        zend_throw_exception(NULL, "VSCF: Message Info footer is corrupted.", -309);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey password length is out of range.", -401);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey number length should be 32 byte.", -402);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey point length should be 65 bytes.", -403);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey name is out of range.", -404);
        break;
    case vscf_status_ERROR_BRAINKEY_INTERNAL:
        zend_throw_exception(NULL, "VSCF: Brainkey internal error.", -405);
        break;
    case vscf_status_ERROR_BRAINKEY_INVALID_POINT:
        zend_throw_exception(NULL, "VSCF: Brainkey point is invalid.", -406);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey number buffer length capacity should be >= 32 byte.", -407);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey point buffer length capacity should be >= 32 byte.", -408);
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
        zend_throw_exception(NULL, "VSCF: Brainkey seed buffer length capacity should be >= 32 byte.", -409);
        break;
    case vscf_status_ERROR_INVALID_IDENTITY_SECRET:
        zend_throw_exception(NULL, "VSCF: Brainkey identity secret is invalid.", -410);
        break;
    case vscf_status_ERROR_INVALID_PADDING:
        zend_throw_exception(NULL, "VSCF: Invalid padding.", -501);
        break;
    case vscf_status_ERROR_PROTOBUF:
        zend_throw_exception(NULL, "VSCF: Protobuf error.", -601);
        break;
    case vscf_status_ERROR_SESSION_ID_DOESNT_MATCH:
        zend_throw_exception(NULL, "VSCF: Session id doesnt match.", -701);
        break;
    case vscf_status_ERROR_EPOCH_NOT_FOUND:
        zend_throw_exception(NULL, "VSCF: Epoch not found.", -702);
        break;
    case vscf_status_ERROR_WRONG_KEY_TYPE:
        zend_throw_exception(NULL, "VSCF: Wrong key type.", -703);
        break;
    case vscf_status_ERROR_INVALID_SIGNATURE:
        zend_throw_exception(NULL, "VSCF: Invalid signature.", -704);
        break;
    case vscf_status_ERROR_ED25519:
        zend_throw_exception(NULL, "VSCF: Ed25519 error.", -705);
        break;
    case vscf_status_ERROR_DUPLICATE_EPOCH:
        zend_throw_exception(NULL, "VSCF: Duplicate epoch.", -706);
        break;
    case vscf_status_ERROR_PLAIN_TEXT_TOO_LONG:
        zend_throw_exception(NULL, "VSCF: Plain text too long.", -707);
        break;
    }
}

//
// Constants
//
const char VSCF_FOUNDATION_PHP_VERSION[] = "0.10.4";
const char VSCF_FOUNDATION_PHP_EXTNAME[] = "vscf_foundation_php";
const char VSCF_MESSAGE_INFO_PHP_RES_NAME[] = "vscf_message_info_t";
const char VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME[] = "vscf_key_recipient_info_t";
const char VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME[] = "vscf_key_recipient_info_list_t";
const char VSCF_PASSWORD_RECIPIENT_INFO_PHP_RES_NAME[] = "vscf_password_recipient_info_t";
const char VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME[] = "vscf_password_recipient_info_list_t";
const char VSCF_ECIES_PHP_RES_NAME[] = "vscf_ecies_t";
const char VSCF_RECIPIENT_CIPHER_PHP_RES_NAME[] = "vscf_recipient_cipher_t";
const char VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME[] = "vscf_message_info_custom_params_t";
const char VSCF_KEY_PROVIDER_PHP_RES_NAME[] = "vscf_key_provider_t";
const char VSCF_SIGNER_PHP_RES_NAME[] = "vscf_signer_t";
const char VSCF_VERIFIER_PHP_RES_NAME[] = "vscf_verifier_t";
const char VSCF_BRAINKEY_CLIENT_PHP_RES_NAME[] = "vscf_brainkey_client_t";
const char VSCF_BRAINKEY_SERVER_PHP_RES_NAME[] = "vscf_brainkey_server_t";
const char VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME[] = "vscf_group_session_message_t";
const char VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME[] = "vscf_group_session_ticket_t";
const char VSCF_GROUP_SESSION_PHP_RES_NAME[] = "vscf_group_session_t";
const char VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME[] = "vscf_message_info_editor_t";
const char VSCF_SIGNER_INFO_PHP_RES_NAME[] = "vscf_signer_info_t";
const char VSCF_SIGNER_INFO_LIST_PHP_RES_NAME[] = "vscf_signer_info_list_t";
const char VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME[] = "vscf_message_info_footer_t";
const char VSCF_SIGNED_DATA_INFO_PHP_RES_NAME[] = "vscf_signed_data_info_t";
const char VSCF_FOOTER_INFO_PHP_RES_NAME[] = "vscf_footer_info_t";
const char VSCF_SHA224_PHP_RES_NAME[] = "vscf_sha224_t";
const char VSCF_SHA256_PHP_RES_NAME[] = "vscf_sha256_t";
const char VSCF_SHA384_PHP_RES_NAME[] = "vscf_sha384_t";
const char VSCF_SHA512_PHP_RES_NAME[] = "vscf_sha512_t";
const char VSCF_AES256_GCM_PHP_RES_NAME[] = "vscf_aes256_gcm_t";
const char VSCF_AES256_CBC_PHP_RES_NAME[] = "vscf_aes256_cbc_t";
const char VSCF_ASN1RD_PHP_RES_NAME[] = "vscf_asn1rd_t";
const char VSCF_ASN1WR_PHP_RES_NAME[] = "vscf_asn1wr_t";
const char VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME[] = "vscf_rsa_public_key_t";
const char VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME[] = "vscf_rsa_private_key_t";
const char VSCF_RSA_PHP_RES_NAME[] = "vscf_rsa_t";
const char VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME[] = "vscf_ecc_public_key_t";
const char VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME[] = "vscf_ecc_private_key_t";
const char VSCF_ECC_PHP_RES_NAME[] = "vscf_ecc_t";
const char VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME[] = "vscf_entropy_accumulator_t";
const char VSCF_CTR_DRBG_PHP_RES_NAME[] = "vscf_ctr_drbg_t";
const char VSCF_HMAC_PHP_RES_NAME[] = "vscf_hmac_t";
const char VSCF_HKDF_PHP_RES_NAME[] = "vscf_hkdf_t";
const char VSCF_KDF1_PHP_RES_NAME[] = "vscf_kdf1_t";
const char VSCF_KDF2_PHP_RES_NAME[] = "vscf_kdf2_t";
const char VSCF_FAKE_RANDOM_PHP_RES_NAME[] = "vscf_fake_random_t";
const char VSCF_PKCS5_PBKDF2_PHP_RES_NAME[] = "vscf_pkcs5_pbkdf2_t";
const char VSCF_PKCS5_PBES2_PHP_RES_NAME[] = "vscf_pkcs5_pbes2_t";
const char VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME[] = "vscf_seed_entropy_source_t";
const char VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME[] = "vscf_key_material_rng_t";
const char VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME[] = "vscf_raw_public_key_t";
const char VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME[] = "vscf_raw_private_key_t";
const char VSCF_PKCS8_SERIALIZER_PHP_RES_NAME[] = "vscf_pkcs8_serializer_t";
const char VSCF_SEC1_SERIALIZER_PHP_RES_NAME[] = "vscf_sec1_serializer_t";
const char VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME[] = "vscf_key_asn1_serializer_t";
const char VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME[] = "vscf_key_asn1_deserializer_t";
const char VSCF_ED25519_PHP_RES_NAME[] = "vscf_ed25519_t";
const char VSCF_CURVE25519_PHP_RES_NAME[] = "vscf_curve25519_t";
const char VSCF_SIMPLE_ALG_INFO_PHP_RES_NAME[] = "vscf_simple_alg_info_t";
const char VSCF_HASH_BASED_ALG_INFO_PHP_RES_NAME[] = "vscf_hash_based_alg_info_t";
const char VSCF_CIPHER_ALG_INFO_PHP_RES_NAME[] = "vscf_cipher_alg_info_t";
const char VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME[] = "vscf_salted_kdf_alg_info_t";
const char VSCF_PBE_ALG_INFO_PHP_RES_NAME[] = "vscf_pbe_alg_info_t";
const char VSCF_ECC_ALG_INFO_PHP_RES_NAME[] = "vscf_ecc_alg_info_t";
const char VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME[] = "vscf_alg_info_der_serializer_t";
const char VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME[] = "vscf_alg_info_der_deserializer_t";
const char VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME[] = "vscf_message_info_der_serializer_t";

//
// Registered resources
//
int le_vscf_impl_t;
int le_vscf_message_info_t;
int le_vscf_key_recipient_info_t;
int le_vscf_key_recipient_info_list_t;
int le_vscf_password_recipient_info_t;
int le_vscf_password_recipient_info_list_t;
int le_vscf_ecies_t;
int le_vscf_recipient_cipher_t;
int le_vscf_message_info_custom_params_t;
int le_vscf_key_provider_t;
int le_vscf_signer_t;
int le_vscf_verifier_t;
int le_vscf_brainkey_client_t;
int le_vscf_brainkey_server_t;
int le_vscf_group_session_message_t;
int le_vscf_group_session_ticket_t;
int le_vscf_group_session_t;
int le_vscf_message_info_editor_t;
int le_vscf_signer_info_t;
int le_vscf_signer_info_list_t;
int le_vscf_message_info_footer_t;
int le_vscf_signed_data_info_t;
int le_vscf_footer_info_t;
int le_vscf_sha224_t;
int le_vscf_sha256_t;
int le_vscf_sha384_t;
int le_vscf_sha512_t;
int le_vscf_aes256_gcm_t;
int le_vscf_aes256_cbc_t;
int le_vscf_asn1rd_t;
int le_vscf_asn1wr_t;
int le_vscf_rsa_public_key_t;
int le_vscf_rsa_private_key_t;
int le_vscf_rsa_t;
int le_vscf_ecc_public_key_t;
int le_vscf_ecc_private_key_t;
int le_vscf_ecc_t;
int le_vscf_entropy_accumulator_t;
int le_vscf_ctr_drbg_t;
int le_vscf_hmac_t;
int le_vscf_hkdf_t;
int le_vscf_kdf1_t;
int le_vscf_kdf2_t;
int le_vscf_fake_random_t;
int le_vscf_pkcs5_pbkdf2_t;
int le_vscf_pkcs5_pbes2_t;
int le_vscf_seed_entropy_source_t;
int le_vscf_key_material_rng_t;
int le_vscf_raw_public_key_t;
int le_vscf_raw_private_key_t;
int le_vscf_pkcs8_serializer_t;
int le_vscf_sec1_serializer_t;
int le_vscf_key_asn1_serializer_t;
int le_vscf_key_asn1_deserializer_t;
int le_vscf_ed25519_t;
int le_vscf_curve25519_t;
int le_vscf_simple_alg_info_t;
int le_vscf_hash_based_alg_info_t;
int le_vscf_cipher_alg_info_t;
int le_vscf_salted_kdf_alg_info_t;
int le_vscf_pbe_alg_info_t;
int le_vscf_ecc_alg_info_t;
int le_vscf_alg_info_der_serializer_t;
int le_vscf_alg_info_der_deserializer_t;
int le_vscf_message_info_der_serializer_t;

//
// Extension init functions declaration
//
PHP_MINIT_FUNCTION(vscf_foundation_php);
PHP_MSHUTDOWN_FUNCTION(vscf_foundation_php);

//
// Functions wrapping
//
//
// Wrap method: vscf_message_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_new_php) {
    vscf_message_info_t *message_info = vscf_message_info_new();
    zend_resource *message_info_res = zend_register_resource(message_info, le_vscf_message_info_t);
    RETVAL_RES(message_info_res);
}

//
// Wrap method: vscf_message_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_data_encryption_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_data_encryption_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_data_encryption_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_message_info_data_encryption_alg_info(message_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_message_info_key_recipient_info_list
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_key_recipient_info_list_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_key_recipient_info_list_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list =(vscf_key_recipient_info_list_t *)vscf_message_info_key_recipient_info_list(message_info);
    key_recipient_info_list = vscf_key_recipient_info_list_shallow_copy(key_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *key_recipient_info_list_res = zend_register_resource(key_recipient_info_list, le_vscf_key_recipient_info_list_t);
    RETVAL_RES(key_recipient_info_list_res);
}

//
// Wrap method: vscf_message_info_password_recipient_info_list
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_password_recipient_info_list_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_password_recipient_info_list_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list =(vscf_password_recipient_info_list_t *)vscf_message_info_password_recipient_info_list(message_info);
    password_recipient_info_list = vscf_password_recipient_info_list_shallow_copy(password_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *password_recipient_info_list_res = zend_register_resource(password_recipient_info_list, le_vscf_password_recipient_info_list_t);
    RETVAL_RES(password_recipient_info_list_res);
}

//
// Wrap method: vscf_message_info_has_custom_params
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_has_custom_params_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_has_custom_params_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_has_custom_params(message_info);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_message_info_custom_params
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_message_info_custom_params_t *message_info_custom_params =(vscf_message_info_custom_params_t *)vscf_message_info_custom_params(message_info);
    message_info_custom_params = vscf_message_info_custom_params_shallow_copy(message_info_custom_params);

    //
    // Write returned result
    //
    zend_resource *message_info_custom_params_res = zend_register_resource(message_info_custom_params, le_vscf_message_info_custom_params_t);
    RETVAL_RES(message_info_custom_params_res);
}

//
// Wrap method: vscf_message_info_has_cipher_kdf_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_has_cipher_kdf_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_has_cipher_kdf_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_has_cipher_kdf_alg_info(message_info);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_message_info_cipher_kdf_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_cipher_kdf_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_cipher_kdf_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_message_info_cipher_kdf_alg_info(message_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_message_info_has_footer_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_has_footer_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_has_footer_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_has_footer_info(message_info);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_message_info_footer_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_footer_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_footer_info_t *footer_info =(vscf_footer_info_t *)vscf_message_info_footer_info(message_info);
    footer_info = vscf_footer_info_shallow_copy(footer_info);

    //
    // Write returned result
    //
    zend_resource *footer_info_res = zend_register_resource(footer_info, le_vscf_footer_info_t);
    RETVAL_RES(footer_info_res);
}

//
// Wrap method: vscf_message_info_clear
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_clear_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_clear_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_PHP_RES_NAME, le_vscf_message_info_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    vscf_message_info_clear(message_info);


}

//
// Wrap method: vscf_key_recipient_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_recipient_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_new_php) {
    vscf_key_recipient_info_t *key_recipient_info = vscf_key_recipient_info_new();
    zend_resource *key_recipient_info_res = zend_register_resource(key_recipient_info, le_vscf_key_recipient_info_t);
    RETVAL_RES(key_recipient_info_res);
}

//
// Wrap method: vscf_key_recipient_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_recipient_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_recipient_info_t *key_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_key_recipient_info_t);
    VSCF_ASSERT_PTR(key_recipient_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_recipient_info_recipient_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_recipient_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_recipient_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_t *key_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_key_recipient_info_t);
    VSCF_ASSERT_PTR(key_recipient_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_key_recipient_info_recipient_id(key_recipient_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_key_recipient_info_key_encryption_algorithm
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_key_encryption_algorithm_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_key_encryption_algorithm_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_t *key_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_key_recipient_info_t);
    VSCF_ASSERT_PTR(key_recipient_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_key_recipient_info_key_encryption_algorithm(key_recipient_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_key_recipient_info_encrypted_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_encrypted_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_encrypted_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_t *key_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_key_recipient_info_t);
    VSCF_ASSERT_PTR(key_recipient_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_key_recipient_info_encrypted_key(key_recipient_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_key_recipient_info_list_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_recipient_info_list_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_new_php) {
    vscf_key_recipient_info_list_t *key_recipient_info_list = vscf_key_recipient_info_list_new();
    zend_resource *key_recipient_info_list_res = zend_register_resource(key_recipient_info_list, le_vscf_key_recipient_info_list_t);
    RETVAL_RES(key_recipient_info_list_res);
}

//
// Wrap method: vscf_key_recipient_info_list_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_recipient_info_list_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_recipient_info_list_has_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_has_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_has_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_key_recipient_info_list_has_item(key_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_key_recipient_info_list_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    vscf_key_recipient_info_t *key_recipient_info =(vscf_key_recipient_info_t *)vscf_key_recipient_info_list_item(key_recipient_info_list);
    key_recipient_info = vscf_key_recipient_info_shallow_copy(key_recipient_info);

    //
    // Write returned result
    //
    zend_resource *key_recipient_info_res = zend_register_resource(key_recipient_info, le_vscf_key_recipient_info_t);
    RETVAL_RES(key_recipient_info_res);
}

//
// Wrap method: vscf_key_recipient_info_list_has_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_has_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_has_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_key_recipient_info_list_has_next(key_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_key_recipient_info_list_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list_rs =vscf_key_recipient_info_list_next(key_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *key_recipient_info_list_res = zend_register_resource(key_recipient_info_list_rs, le_vscf_key_recipient_info_list_t);
    RETVAL_RES(key_recipient_info_list_res);
}

//
// Wrap method: vscf_key_recipient_info_list_has_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_has_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_has_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_key_recipient_info_list_has_prev(key_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_key_recipient_info_list_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list_rs =vscf_key_recipient_info_list_prev(key_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *key_recipient_info_list_res = zend_register_resource(key_recipient_info_list_rs, le_vscf_key_recipient_info_list_t);
    RETVAL_RES(key_recipient_info_list_res);
}

//
// Wrap method: vscf_key_recipient_info_list_clear
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_recipient_info_list_clear_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_recipient_info_list_clear_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_recipient_info_list_t *key_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_key_recipient_info_list_t);
    VSCF_ASSERT_PTR(key_recipient_info_list);

    //
    // Call main function
    //
    vscf_key_recipient_info_list_clear(key_recipient_info_list);


}

//
// Wrap method: vscf_password_recipient_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_password_recipient_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_new_php) {
    vscf_password_recipient_info_t *password_recipient_info = vscf_password_recipient_info_new();
    zend_resource *password_recipient_info_res = zend_register_resource(password_recipient_info, le_vscf_password_recipient_info_t);
    RETVAL_RES(password_recipient_info_res);
}

//
// Wrap method: vscf_password_recipient_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_password_recipient_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_password_recipient_info_t *password_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_password_recipient_info_t);
    VSCF_ASSERT_PTR(password_recipient_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_password_recipient_info_key_encryption_algorithm
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_key_encryption_algorithm_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_key_encryption_algorithm_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_t *password_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_password_recipient_info_t);
    VSCF_ASSERT_PTR(password_recipient_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_password_recipient_info_key_encryption_algorithm(password_recipient_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_password_recipient_info_encrypted_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_encrypted_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_encrypted_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_t *password_recipient_info = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_PHP_RES_NAME, le_vscf_password_recipient_info_t);
    VSCF_ASSERT_PTR(password_recipient_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_password_recipient_info_encrypted_key(password_recipient_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_password_recipient_info_list_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_password_recipient_info_list_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_new_php) {
    vscf_password_recipient_info_list_t *password_recipient_info_list = vscf_password_recipient_info_list_new();
    zend_resource *password_recipient_info_list_res = zend_register_resource(password_recipient_info_list, le_vscf_password_recipient_info_list_t);
    RETVAL_RES(password_recipient_info_list_res);
}

//
// Wrap method: vscf_password_recipient_info_list_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_password_recipient_info_list_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_password_recipient_info_list_has_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_has_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_has_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_password_recipient_info_list_has_item(password_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_password_recipient_info_list_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    vscf_password_recipient_info_t *password_recipient_info =(vscf_password_recipient_info_t *)vscf_password_recipient_info_list_item(password_recipient_info_list);
    password_recipient_info = vscf_password_recipient_info_shallow_copy(password_recipient_info);

    //
    // Write returned result
    //
    zend_resource *password_recipient_info_res = zend_register_resource(password_recipient_info, le_vscf_password_recipient_info_t);
    RETVAL_RES(password_recipient_info_res);
}

//
// Wrap method: vscf_password_recipient_info_list_has_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_has_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_has_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_password_recipient_info_list_has_next(password_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_password_recipient_info_list_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list_rs =vscf_password_recipient_info_list_next(password_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *password_recipient_info_list_res = zend_register_resource(password_recipient_info_list_rs, le_vscf_password_recipient_info_list_t);
    RETVAL_RES(password_recipient_info_list_res);
}

//
// Wrap method: vscf_password_recipient_info_list_has_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_has_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_has_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_password_recipient_info_list_has_prev(password_recipient_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_password_recipient_info_list_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list_rs =vscf_password_recipient_info_list_prev(password_recipient_info_list);

    //
    // Write returned result
    //
    zend_resource *password_recipient_info_list_res = zend_register_resource(password_recipient_info_list_rs, le_vscf_password_recipient_info_list_t);
    RETVAL_RES(password_recipient_info_list_res);
}

//
// Wrap method: vscf_password_recipient_info_list_clear
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_password_recipient_info_list_clear_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_password_recipient_info_list_clear_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_password_recipient_info_list_t *password_recipient_info_list = zend_fetch_resource_ex(in_ctx, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, le_vscf_password_recipient_info_list_t);
    VSCF_ASSERT_PTR(password_recipient_info_list);

    //
    // Call main function
    //
    vscf_password_recipient_info_list_clear(password_recipient_info_list);


}

//
// Wrap method: vscf_ecies_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecies_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_new_php) {
    vscf_ecies_t *ecies = vscf_ecies_new();
    zend_resource *ecies_res = zend_register_resource(ecies, le_vscf_ecies_t);
    RETVAL_RES(ecies_res);
}

//
// Wrap method: vscf_ecies_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecies_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecies_set_key_alg
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_set_key_alg_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_alg, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_set_key_alg_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key_alg = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key_alg, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    vscf_impl_t *key_alg = zend_fetch_resource_ex(in_key_alg, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(key_alg);

    //
    // Call main function
    //
    vscf_ecies_set_key_alg(ecies, key_alg);


}

//
// Wrap method: vscf_ecies_release_key_alg
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_release_key_alg_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_release_key_alg_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    //
    // Call main function
    //
    vscf_ecies_release_key_alg(ecies);


}

//
// Wrap method: vscf_ecies_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecies_setup_defaults(ecies);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecies_setup_defaults_no_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_setup_defaults_no_random_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_setup_defaults_no_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    //
    // Call main function
    //
    vscf_ecies_setup_defaults_no_random(ecies);


}

//
// Wrap method: vscf_ecies_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_encrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ecies_encrypted_len(ecies, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecies_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ecies_encrypted_len(ecies, public_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecies_encrypt(ecies, public_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ecies_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_decrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ecies_decrypted_len(ecies, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecies_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecies_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecies_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecies_t *ecies = zend_fetch_resource_ex(in_ctx, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(ecies);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECIES_PHP_RES_NAME, le_vscf_ecies_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ecies_decrypted_len(ecies, private_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecies_decrypt(ecies, private_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_recipient_cipher_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_recipient_cipher_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_new_php) {
    vscf_recipient_cipher_t *recipient_cipher = vscf_recipient_cipher_new();
    zend_resource *recipient_cipher_res = zend_register_resource(recipient_cipher, le_vscf_recipient_cipher_t);
    RETVAL_RES(recipient_cipher_res);
}

//
// Wrap method: vscf_recipient_cipher_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_recipient_cipher_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_add_key_recipient
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_add_key_recipient_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_recipient_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_add_key_recipient_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_recipient_id = NULL;
    size_t in_recipient_id_len = 0;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_recipient_id, in_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t recipient_id = vsc_data((const byte*)in_recipient_id, in_recipient_id_len);
    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    vscf_recipient_cipher_add_key_recipient(recipient_cipher, recipient_id, public_key);


}

//
// Wrap method: vscf_recipient_cipher_clear_recipients
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_clear_recipients_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_clear_recipients_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    vscf_recipient_cipher_clear_recipients(recipient_cipher);


}

//
// Wrap method: vscf_recipient_cipher_add_signer
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_add_signer_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_signer_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_add_signer_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_signer_id = NULL;
    size_t in_signer_id_len = 0;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_signer_id, in_signer_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t signer_id = vsc_data((const byte*)in_signer_id, in_signer_id_len);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_add_signer(recipient_cipher, signer_id, private_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_clear_signers
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_clear_signers_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_clear_signers_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    vscf_recipient_cipher_clear_signers(recipient_cipher);


}

//
// Wrap method: vscf_recipient_cipher_custom_params
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_custom_params_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_custom_params_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    vscf_message_info_custom_params_t *message_info_custom_params =(vscf_message_info_custom_params_t *)vscf_recipient_cipher_custom_params(recipient_cipher);
    message_info_custom_params = vscf_message_info_custom_params_shallow_copy(message_info_custom_params);

    //
    // Write returned result
    //
    zend_resource *message_info_custom_params_res = zend_register_resource(message_info_custom_params, le_vscf_message_info_custom_params_t);
    RETVAL_RES(message_info_custom_params_res);
}

//
// Wrap method: vscf_recipient_cipher_start_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_start_encryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_start_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_start_encryption(recipient_cipher);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_start_signed_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_start_signed_encryption_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_size, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_start_signed_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_size = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_size)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    size_t data_size = in_data_size;

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_start_signed_encryption(recipient_cipher, data_size);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_message_info_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_message_info_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_message_info_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    size_t res =vscf_recipient_cipher_message_info_len(recipient_cipher);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_recipient_cipher_pack_message_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_pack_message_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_pack_message_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Allocate output buffer for output 'message_info'
    //
    zend_string *out_message_info = zend_string_alloc(vscf_recipient_cipher_message_info_len(recipient_cipher), 0);
    vsc_buffer_t *message_info = vsc_buffer_new();
    vsc_buffer_use(message_info, (byte *)ZSTR_VAL(out_message_info), ZSTR_LEN(out_message_info));

    //
    // Call main function
    //
    vscf_recipient_cipher_pack_message_info(recipient_cipher, message_info);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_message_info) = vsc_buffer_len(message_info);

    //
    // Write returned result
    //
    RETVAL_STR(out_message_info);
}

//
// Wrap method: vscf_recipient_cipher_encryption_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_encryption_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_encryption_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_recipient_cipher_encryption_out_len(recipient_cipher, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_recipient_cipher_process_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_process_encryption_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_process_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_recipient_cipher_encryption_out_len(recipient_cipher, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_process_encryption(recipient_cipher, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_recipient_cipher_finish_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_finish_encryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_finish_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_recipient_cipher_encryption_out_len(recipient_cipher, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_finish_encryption(recipient_cipher, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_recipient_cipher_start_decryption_with_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_start_decryption_with_key_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_recipient_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_start_decryption_with_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_recipient_id = NULL;
    size_t in_recipient_id_len = 0;
    zval *in_private_key = NULL;
    char *in_message_info = NULL;
    size_t in_message_info_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_recipient_id, in_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_message_info, in_message_info_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t recipient_id = vsc_data((const byte*)in_recipient_id, in_recipient_id_len);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t message_info = vsc_data((const byte*)in_message_info, in_message_info_len);

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_start_decryption_with_key(recipient_cipher, recipient_id, private_key, message_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_start_verified_decryption_with_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_start_verified_decryption_with_key_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_recipient_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info_footer, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_start_verified_decryption_with_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_recipient_id = NULL;
    size_t in_recipient_id_len = 0;
    zval *in_private_key = NULL;
    char *in_message_info = NULL;
    size_t in_message_info_len = 0;
    char *in_message_info_footer = NULL;
    size_t in_message_info_footer_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_recipient_id, in_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_message_info, in_message_info_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_message_info_footer, in_message_info_footer_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t recipient_id = vsc_data((const byte*)in_recipient_id, in_recipient_id_len);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t message_info = vsc_data((const byte*)in_message_info, in_message_info_len);
    vsc_data_t message_info_footer = vsc_data((const byte*)in_message_info_footer, in_message_info_footer_len);

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher, recipient_id, private_key, message_info, message_info_footer);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_recipient_cipher_decryption_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_decryption_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_decryption_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_recipient_cipher_decryption_out_len(recipient_cipher, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_recipient_cipher_process_decryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_process_decryption_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_process_decryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_recipient_cipher_decryption_out_len(recipient_cipher, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_process_decryption(recipient_cipher, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_recipient_cipher_finish_decryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_finish_decryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_finish_decryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_recipient_cipher_decryption_out_len(recipient_cipher, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_finish_decryption(recipient_cipher, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_recipient_cipher_is_data_signed
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_is_data_signed_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_is_data_signed_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    zend_bool res =vscf_recipient_cipher_is_data_signed(recipient_cipher);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_recipient_cipher_signer_infos
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_signer_infos_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_signer_infos_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    vscf_signer_info_list_t *signer_info_list =(vscf_signer_info_list_t *)vscf_recipient_cipher_signer_infos(recipient_cipher);
    signer_info_list = vscf_signer_info_list_shallow_copy(signer_info_list);

    //
    // Write returned result
    //
    zend_resource *signer_info_list_res = zend_register_resource(signer_info_list, le_vscf_signer_info_list_t);
    RETVAL_RES(signer_info_list_res);
}

//
// Wrap method: vscf_recipient_cipher_verify_signer_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_verify_signer_info_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_signer_info, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_verify_signer_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_signer_info = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_signer_info, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    vscf_signer_info_t *signer_info = zend_fetch_resource_ex(in_signer_info, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(signer_info);
    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_recipient_cipher_verify_signer_info(recipient_cipher, signer_info, public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_recipient_cipher_message_info_footer_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_message_info_footer_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_message_info_footer_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Call main function
    //
    size_t res =vscf_recipient_cipher_message_info_footer_len(recipient_cipher);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_recipient_cipher_pack_message_info_footer
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_recipient_cipher_pack_message_info_footer_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_recipient_cipher_pack_message_info_footer_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_recipient_cipher_t *recipient_cipher = zend_fetch_resource_ex(in_ctx, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, le_vscf_recipient_cipher_t);
    VSCF_ASSERT_PTR(recipient_cipher);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_recipient_cipher_message_info_footer_len(recipient_cipher), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_recipient_cipher_pack_message_info_footer(recipient_cipher, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_message_info_custom_params_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_custom_params_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_new_php) {
    vscf_message_info_custom_params_t *message_info_custom_params = vscf_message_info_custom_params_new();
    zend_resource *message_info_custom_params_res = zend_register_resource(message_info_custom_params, le_vscf_message_info_custom_params_t);
    RETVAL_RES(message_info_custom_params_res);
}

//
// Wrap method: vscf_message_info_custom_params_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_custom_params_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_custom_params_add_int
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_add_int_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_add_int_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);

    int value = in_value;//
    // Call main function
    //
    vscf_message_info_custom_params_add_int(message_info_custom_params, key, value);


}

//
// Wrap method: vscf_message_info_custom_params_add_string
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_add_string_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_add_string_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    vscf_message_info_custom_params_add_string(message_info_custom_params, key, value);


}

//
// Wrap method: vscf_message_info_custom_params_add_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_add_data_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_add_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    vscf_message_info_custom_params_add_data(message_info_custom_params, key, value);


}

//
// Wrap method: vscf_message_info_custom_params_clear
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_clear_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_clear_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    //
    // Call main function
    //
    vscf_message_info_custom_params_clear(message_info_custom_params);


}

//
// Wrap method: vscf_message_info_custom_params_find_int
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_find_int_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_find_int_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    int res =vscf_message_info_custom_params_find_int(message_info_custom_params, key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_message_info_custom_params_find_string
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_find_string_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_find_string_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_message_info_custom_params_find_string(message_info_custom_params, key, &error);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_message_info_custom_params_find_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_find_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_find_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_message_info_custom_params_find_data(message_info_custom_params, key, &error);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_message_info_custom_params_has_params
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_custom_params_has_params_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_custom_params_has_params_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_custom_params_t *message_info_custom_params = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, le_vscf_message_info_custom_params_t);
    VSCF_ASSERT_PTR(message_info_custom_params);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_custom_params_has_params(message_info_custom_params);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_key_provider_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_provider_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_new_php) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    zend_resource *key_provider_res = zend_register_resource(key_provider, le_vscf_key_provider_t);
    RETVAL_RES(key_provider_res);
}

//
// Wrap method: vscf_key_provider_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_provider_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_provider_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_provider_setup_defaults(key_provider);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_provider_set_rsa_params
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_set_rsa_params_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_bitlen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_set_rsa_params_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_bitlen = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_bitlen)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    size_t bitlen = in_bitlen;

    //
    // Call main function
    //
    vscf_key_provider_set_rsa_params(key_provider, bitlen);


}

//
// Wrap method: vscf_key_provider_generate_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_generate_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_generate_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_alg_id = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_alg_id)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_alg_id_t alg_id = (vscf_alg_id_t)in_alg_id;//
    // Call main function
    //
    vscf_impl_t *private_key =vscf_key_provider_generate_private_key(key_provider, alg_id, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_key_provider_import_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_import_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_import_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key_data = NULL;
    size_t in_key_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key_data, in_key_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vsc_data_t key_data = vsc_data((const byte*)in_key_data, in_key_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_key_provider_import_private_key(key_provider, key_data, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_key_provider_import_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_import_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_import_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key_data = NULL;
    size_t in_key_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key_data, in_key_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vsc_data_t key_data = vsc_data((const byte*)in_key_data, in_key_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_key_provider_import_public_key(key_provider, key_data, &error);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_key_provider_exported_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_exported_public_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_exported_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    size_t res =vscf_key_provider_exported_public_key_len(key_provider, public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_provider_export_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_export_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_export_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_key_provider_exported_public_key_len(key_provider, public_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_provider_export_public_key(key_provider, public_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_key_provider_exported_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_exported_private_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_exported_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    size_t res =vscf_key_provider_exported_private_key_len(key_provider, private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_provider_export_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_provider_export_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_provider_export_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_ctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(key_provider);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_key_provider_exported_private_key_len(key_provider, private_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_provider_export_private_key(key_provider, private_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_signer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_new_php) {
    vscf_signer_t *signer = vscf_signer_new();
    zend_resource *signer_res = zend_register_resource(signer, le_vscf_signer_t);
    RETVAL_RES(signer_res);
}

//
// Wrap method: vscf_signer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_signer_t *signer = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(signer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_signer_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_reset_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_t *signer = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(signer);

    //
    // Call main function
    //
    vscf_signer_reset(signer);


}

//
// Wrap method: vscf_signer_append_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_append_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_append_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_t *signer = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(signer);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_signer_append_data(signer, data);


}

//
// Wrap method: vscf_signer_signature_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_signature_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_signature_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_t *signer = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(signer);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    size_t res =vscf_signer_signature_len(signer, private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_signer_sign
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_sign_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_sign_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_t *signer = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(signer);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_SIGNER_PHP_RES_NAME, le_vscf_signer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'signature'
    //
    zend_string *out_signature = zend_string_alloc(vscf_signer_signature_len(signer, private_key), 0);
    vsc_buffer_t *signature = vsc_buffer_new();
    vsc_buffer_use(signature, (byte *)ZSTR_VAL(out_signature), ZSTR_LEN(out_signature));

    //
    // Call main function
    //
    vscf_status_t status =vscf_signer_sign(signer, private_key, signature);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_signature) = vsc_buffer_len(signature);

    //
    // Write returned result
    //
    RETVAL_STR(out_signature);

    goto success;

fail:
    zend_string_free(out_signature);
success:
    vsc_buffer_destroy(&signature);
}

//
// Wrap method: vscf_verifier_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_verifier_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_verifier_new_php) {
    vscf_verifier_t *verifier = vscf_verifier_new();
    zend_resource *verifier_res = zend_register_resource(verifier, le_vscf_verifier_t);
    RETVAL_RES(verifier_res);
}

//
// Wrap method: vscf_verifier_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_verifier_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_verifier_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_verifier_t *verifier = zend_fetch_resource_ex(in_ctx, VSCF_VERIFIER_PHP_RES_NAME, le_vscf_verifier_t);
    VSCF_ASSERT_PTR(verifier);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_verifier_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_verifier_reset_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_signature, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_verifier_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_signature = NULL;
    size_t in_signature_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_signature, in_signature_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_verifier_t *verifier = zend_fetch_resource_ex(in_ctx, VSCF_VERIFIER_PHP_RES_NAME, le_vscf_verifier_t);
    VSCF_ASSERT_PTR(verifier);

    vsc_data_t signature = vsc_data((const byte*)in_signature, in_signature_len);

    //
    // Call main function
    //
    vscf_status_t status =vscf_verifier_reset(verifier, signature);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_verifier_append_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_verifier_append_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_verifier_append_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_verifier_t *verifier = zend_fetch_resource_ex(in_ctx, VSCF_VERIFIER_PHP_RES_NAME, le_vscf_verifier_t);
    VSCF_ASSERT_PTR(verifier);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_verifier_append_data(verifier, data);


}

//
// Wrap method: vscf_verifier_verify
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_verifier_verify_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_verifier_verify_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_verifier_t *verifier = zend_fetch_resource_ex(in_ctx, VSCF_VERIFIER_PHP_RES_NAME, le_vscf_verifier_t);
    VSCF_ASSERT_PTR(verifier);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_VERIFIER_PHP_RES_NAME, le_vscf_verifier_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_verifier_verify(verifier, public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_brainkey_client_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_brainkey_client_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_client_new_php) {
    vscf_brainkey_client_t *brainkey_client = vscf_brainkey_client_new();
    zend_resource *brainkey_client_res = zend_register_resource(brainkey_client, le_vscf_brainkey_client_t);
    RETVAL_RES(brainkey_client_res);
}

//
// Wrap method: vscf_brainkey_client_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_brainkey_client_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_client_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_brainkey_client_t *brainkey_client = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_CLIENT_PHP_RES_NAME, le_vscf_brainkey_client_t);
    VSCF_ASSERT_PTR(brainkey_client);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_brainkey_client_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_client_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_client_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_client_t *brainkey_client = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_CLIENT_PHP_RES_NAME, le_vscf_brainkey_client_t);
    VSCF_ASSERT_PTR(brainkey_client);

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_client_setup_defaults(brainkey_client);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_brainkey_client_blind
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_client_blind_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_client_blind_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_client_t *brainkey_client = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_CLIENT_PHP_RES_NAME, le_vscf_brainkey_client_t);
    VSCF_ASSERT_PTR(brainkey_client);

    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);

    //
    // Allocate output buffer for output 'deblind_factor'
    //
    zend_string *out_deblind_factor = zend_string_alloc(vscf_brainkey_client_MPI_LEN, 0);
    vsc_buffer_t *deblind_factor = vsc_buffer_new();
    vsc_buffer_use(deblind_factor, (byte *)ZSTR_VAL(out_deblind_factor), ZSTR_LEN(out_deblind_factor));

    //
    // Allocate output buffer for output 'blinded_point'
    //
    zend_string *out_blinded_point = zend_string_alloc(vscf_brainkey_client_POINT_LEN, 0);
    vsc_buffer_t *blinded_point = vsc_buffer_new();
    vsc_buffer_use(blinded_point, (byte *)ZSTR_VAL(out_blinded_point), ZSTR_LEN(out_blinded_point));

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_client_blind(brainkey_client, password, deblind_factor, blinded_point);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_deblind_factor) = vsc_buffer_len(deblind_factor);
    ZSTR_LEN(out_blinded_point) = vsc_buffer_len(blinded_point);

    //
    // Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_deblind_factor);
    add_next_index_str(return_value, out_blinded_point);

    goto success;

fail:
    zend_string_free(out_deblind_factor);
    zend_string_free(out_blinded_point);
success:
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&blinded_point);
}

//
// Wrap method: vscf_brainkey_client_deblind
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_client_deblind_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_password, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_hardened_point, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_deblind_factor, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_client_deblind_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_password = NULL;
    size_t in_password_len = 0;
    char *in_hardened_point = NULL;
    size_t in_hardened_point_len = 0;
    char *in_deblind_factor = NULL;
    size_t in_deblind_factor_len = 0;
    char *in_key_name = NULL;
    size_t in_key_name_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_password, in_password_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_hardened_point, in_hardened_point_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_deblind_factor, in_deblind_factor_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_key_name, in_key_name_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_client_t *brainkey_client = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_CLIENT_PHP_RES_NAME, le_vscf_brainkey_client_t);
    VSCF_ASSERT_PTR(brainkey_client);

    vsc_data_t password = vsc_data((const byte*)in_password, in_password_len);
    vsc_data_t hardened_point = vsc_data((const byte*)in_hardened_point, in_hardened_point_len);
    vsc_data_t deblind_factor = vsc_data((const byte*)in_deblind_factor, in_deblind_factor_len);
    vsc_data_t key_name = vsc_data((const byte*)in_key_name, in_key_name_len);

    //
    // Allocate output buffer for output 'seed'
    //
    zend_string *out_seed = zend_string_alloc(vscf_brainkey_client_POINT_LEN, 0);
    vsc_buffer_t *seed = vsc_buffer_new();
    vsc_buffer_use(seed, (byte *)ZSTR_VAL(out_seed), ZSTR_LEN(out_seed));

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_client_deblind(brainkey_client, password, hardened_point, deblind_factor, key_name, seed);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_seed) = vsc_buffer_len(seed);

    //
    // Write returned result
    //
    RETVAL_STR(out_seed);

    goto success;

fail:
    zend_string_free(out_seed);
success:
    vsc_buffer_destroy(&seed);
}

//
// Wrap method: vscf_brainkey_server_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_brainkey_server_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_server_new_php) {
    vscf_brainkey_server_t *brainkey_server = vscf_brainkey_server_new();
    zend_resource *brainkey_server_res = zend_register_resource(brainkey_server, le_vscf_brainkey_server_t);
    RETVAL_RES(brainkey_server_res);
}

//
// Wrap method: vscf_brainkey_server_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_brainkey_server_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_server_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_brainkey_server_t *brainkey_server = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_SERVER_PHP_RES_NAME, le_vscf_brainkey_server_t);
    VSCF_ASSERT_PTR(brainkey_server);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_brainkey_server_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_server_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_server_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_server_t *brainkey_server = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_SERVER_PHP_RES_NAME, le_vscf_brainkey_server_t);
    VSCF_ASSERT_PTR(brainkey_server);

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_server_setup_defaults(brainkey_server);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_brainkey_server_generate_identity_secret
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_server_generate_identity_secret_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_server_generate_identity_secret_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_server_t *brainkey_server = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_SERVER_PHP_RES_NAME, le_vscf_brainkey_server_t);
    VSCF_ASSERT_PTR(brainkey_server);

    //
    // Allocate output buffer for output 'identity_secret'
    //
    zend_string *out_identity_secret = zend_string_alloc(vscf_brainkey_server_MPI_LEN, 0);
    vsc_buffer_t *identity_secret = vsc_buffer_new();
    vsc_buffer_use(identity_secret, (byte *)ZSTR_VAL(out_identity_secret), ZSTR_LEN(out_identity_secret));

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_server_generate_identity_secret(brainkey_server, identity_secret);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_identity_secret) = vsc_buffer_len(identity_secret);

    //
    // Write returned result
    //
    RETVAL_STR(out_identity_secret);

    goto success;

fail:
    zend_string_free(out_identity_secret);
success:
    vsc_buffer_destroy(&identity_secret);
}

//
// Wrap method: vscf_brainkey_server_harden
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_brainkey_server_harden_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_identity_secret, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_blinded_point, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_brainkey_server_harden_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_identity_secret = NULL;
    size_t in_identity_secret_len = 0;
    char *in_blinded_point = NULL;
    size_t in_blinded_point_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_identity_secret, in_identity_secret_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_blinded_point, in_blinded_point_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_brainkey_server_t *brainkey_server = zend_fetch_resource_ex(in_ctx, VSCF_BRAINKEY_SERVER_PHP_RES_NAME, le_vscf_brainkey_server_t);
    VSCF_ASSERT_PTR(brainkey_server);

    vsc_data_t identity_secret = vsc_data((const byte*)in_identity_secret, in_identity_secret_len);
    vsc_data_t blinded_point = vsc_data((const byte*)in_blinded_point, in_blinded_point_len);

    //
    // Allocate output buffer for output 'hardened_point'
    //
    zend_string *out_hardened_point = zend_string_alloc(vscf_brainkey_server_POINT_LEN, 0);
    vsc_buffer_t *hardened_point = vsc_buffer_new();
    vsc_buffer_use(hardened_point, (byte *)ZSTR_VAL(out_hardened_point), ZSTR_LEN(out_hardened_point));

    //
    // Call main function
    //
    vscf_status_t status =vscf_brainkey_server_harden(brainkey_server, identity_secret, blinded_point, hardened_point);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_hardened_point) = vsc_buffer_len(hardened_point);

    //
    // Write returned result
    //
    RETVAL_STR(out_hardened_point);

    goto success;

fail:
    zend_string_free(out_hardened_point);
success:
    vsc_buffer_destroy(&hardened_point);
}

//
// Wrap method: vscf_group_session_message_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_message_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_new_php) {
    vscf_group_session_message_t *group_session_message = vscf_group_session_message_new();
    zend_resource *group_session_message_res = zend_register_resource(group_session_message, le_vscf_group_session_message_t);
    RETVAL_RES(group_session_message_res);
}

//
// Wrap method: vscf_group_session_message_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_message_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_message_get_type
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_get_type_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_get_type_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    //
    // Call main function
    //
    int group_msg_type =vscf_group_session_message_get_type(group_session_message);

    //
    // Write returned result
    //
    RETVAL_LONG(group_msg_type);
}

//
// Wrap method: vscf_group_session_message_get_session_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_get_session_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_get_session_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_group_session_message_get_session_id(group_session_message);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_group_session_message_get_epoch
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_get_epoch_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_get_epoch_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    //
    // Call main function
    //
    int res =vscf_group_session_message_get_epoch(group_session_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_group_session_message_serialize_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_serialize_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_serialize_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    //
    // Call main function
    //
    size_t res =vscf_group_session_message_serialize_len(group_session_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_group_session_message_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_serialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    //
    // Allocate output buffer for output 'output'
    //
    zend_string *out_output = zend_string_alloc(vscf_group_session_message_serialize_len(group_session_message), 0);
    vsc_buffer_t *output = vsc_buffer_new();
    vsc_buffer_use(output, (byte *)ZSTR_VAL(out_output), ZSTR_LEN(out_output));

    //
    // Call main function
    //
    vscf_group_session_message_serialize(group_session_message, output);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_output) = vsc_buffer_len(output);

    //
    // Write returned result
    //
    RETVAL_STR(out_output);
}

//
// Wrap method: vscf_group_session_message_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_message_deserialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_input, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_message_deserialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_input = NULL;
    size_t in_input_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_input, in_input_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_message_t *group_session_message = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, le_vscf_group_session_message_t);
    VSCF_ASSERT_PTR(group_session_message);

    vsc_data_t input = vsc_data((const byte*)in_input, in_input_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_group_session_message_t *group_session_message_rs =vscf_group_session_message_deserialize(input, &error);

    //
    // Write returned result
    //
    zend_resource *group_session_message_res = zend_register_resource(group_session_message_rs, le_vscf_group_session_message_t);
    RETVAL_RES(group_session_message_res);
}

//
// Wrap method: vscf_group_session_ticket_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_ticket_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_ticket_new_php) {
    vscf_group_session_ticket_t *group_session_ticket = vscf_group_session_ticket_new();
    zend_resource *group_session_ticket_res = zend_register_resource(group_session_ticket, le_vscf_group_session_ticket_t);
    RETVAL_RES(group_session_ticket_res);
}

//
// Wrap method: vscf_group_session_ticket_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_ticket_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_ticket_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_group_session_ticket_t *group_session_ticket = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME, le_vscf_group_session_ticket_t);
    VSCF_ASSERT_PTR(group_session_ticket);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_ticket_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_ticket_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_ticket_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_ticket_t *group_session_ticket = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME, le_vscf_group_session_ticket_t);
    VSCF_ASSERT_PTR(group_session_ticket);

    //
    // Call main function
    //
    vscf_status_t status =vscf_group_session_ticket_setup_defaults(group_session_ticket);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_ticket_setup_ticket_as_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_ticket_setup_ticket_as_new_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_session_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_ticket_setup_ticket_as_new_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_session_id = NULL;
    size_t in_session_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_session_id, in_session_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_ticket_t *group_session_ticket = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME, le_vscf_group_session_ticket_t);
    VSCF_ASSERT_PTR(group_session_ticket);

    vsc_data_t session_id = vsc_data((const byte*)in_session_id, in_session_id_len);

    //
    // Call main function
    //
    vscf_status_t status =vscf_group_session_ticket_setup_ticket_as_new(group_session_ticket, session_id);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_ticket_get_ticket_message
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_ticket_get_ticket_message_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_ticket_get_ticket_message_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_ticket_t *group_session_ticket = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME, le_vscf_group_session_ticket_t);
    VSCF_ASSERT_PTR(group_session_ticket);

    //
    // Call main function
    //
    vscf_group_session_message_t *group_session_message =(vscf_group_session_message_t *)vscf_group_session_ticket_get_ticket_message(group_session_ticket);
    group_session_message = vscf_group_session_message_shallow_copy(group_session_message);

    //
    // Write returned result
    //
    zend_resource *group_session_message_res = zend_register_resource(group_session_message, le_vscf_group_session_message_t);
    RETVAL_RES(group_session_message_res);
}

//
// Wrap method: vscf_group_session_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_new_php) {
    vscf_group_session_t *group_session = vscf_group_session_new();
    zend_resource *group_session_res = zend_register_resource(group_session, le_vscf_group_session_t);
    RETVAL_RES(group_session_res);
}

//
// Wrap method: vscf_group_session_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_group_session_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_get_current_epoch
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_get_current_epoch_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_get_current_epoch_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    //
    // Call main function
    //
    int res =vscf_group_session_get_current_epoch(group_session);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_group_session_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    //
    // Call main function
    //
    vscf_status_t status =vscf_group_session_setup_defaults(group_session);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_get_session_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_get_session_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_get_session_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_group_session_get_session_id(group_session);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_group_session_add_epoch
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_add_epoch_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_add_epoch_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    vscf_group_session_message_t *message = zend_fetch_resource_ex(in_message, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(message);

    //
    // Call main function
    //
    vscf_status_t status =vscf_group_session_add_epoch(group_session, message);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_group_session_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_plain_text = NULL;
    size_t in_plain_text_len = 0;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_plain_text, in_plain_text_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    vsc_data_t plain_text = vsc_data((const byte*)in_plain_text, in_plain_text_len);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_group_session_message_t *group_session_message =vscf_group_session_encrypt(group_session, plain_text, private_key, &error);

    //
    // Write returned result
    //
    zend_resource *group_session_message_res = zend_register_resource(group_session_message, le_vscf_group_session_message_t);
    RETVAL_RES(group_session_message_res);
}

//
// Wrap method: vscf_group_session_decrypt_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_decrypt_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_decrypt_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    vscf_group_session_message_t *message = zend_fetch_resource_ex(in_message, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(message);

    //
    // Call main function
    //
    size_t res =vscf_group_session_decrypt_len(group_session, message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_group_session_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    vscf_group_session_message_t *message = zend_fetch_resource_ex(in_message, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(message);
    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Allocate output buffer for output 'plain_text'
    //
    zend_string *out_plain_text = zend_string_alloc(vscf_group_session_decrypt_len(group_session, message), 0);
    vsc_buffer_t *plain_text = vsc_buffer_new();
    vsc_buffer_use(plain_text, (byte *)ZSTR_VAL(out_plain_text), ZSTR_LEN(out_plain_text));

    //
    // Call main function
    //
    vscf_status_t status =vscf_group_session_decrypt(group_session, message, public_key, plain_text);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_plain_text) = vsc_buffer_len(plain_text);

    //
    // Write returned result
    //
    RETVAL_STR(out_plain_text);

    goto success;

fail:
    zend_string_free(out_plain_text);
success:
    vsc_buffer_destroy(&plain_text);
}

//
// Wrap method: vscf_group_session_create_group_ticket
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_group_session_create_group_ticket_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_group_session_create_group_ticket_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_group_session_t *group_session = zend_fetch_resource_ex(in_ctx, VSCF_GROUP_SESSION_PHP_RES_NAME, le_vscf_group_session_t);
    VSCF_ASSERT_PTR(group_session);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_group_session_ticket_t *group_session_ticket =vscf_group_session_create_group_ticket(group_session, &error);

    //
    // Write returned result
    //
    zend_resource *group_session_ticket_res = zend_register_resource(group_session_ticket, le_vscf_group_session_ticket_t);
    RETVAL_RES(group_session_ticket_res);
}

//
// Wrap method: vscf_message_info_editor_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_editor_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_new_php) {
    vscf_message_info_editor_t *message_info_editor = vscf_message_info_editor_new();
    zend_resource *message_info_editor_res = zend_register_resource(message_info_editor, le_vscf_message_info_editor_t);
    RETVAL_RES(message_info_editor_res);
}

//
// Wrap method: vscf_message_info_editor_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_editor_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_editor_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    //
    // Call main function
    //
    vscf_status_t status =vscf_message_info_editor_setup_defaults(message_info_editor);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_editor_unpack
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_unpack_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_unpack_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_message_info_data = NULL;
    size_t in_message_info_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_message_info_data, in_message_info_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    vsc_data_t message_info_data = vsc_data((const byte*)in_message_info_data, in_message_info_data_len);

    //
    // Call main function
    //
    vscf_status_t status =vscf_message_info_editor_unpack(message_info_editor, message_info_data);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_editor_unlock
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_unlock_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_owner_recipient_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_owner_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_unlock_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_owner_recipient_id = NULL;
    size_t in_owner_recipient_id_len = 0;
    zval *in_owner_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_owner_recipient_id, in_owner_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_owner_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    vsc_data_t owner_recipient_id = vsc_data((const byte*)in_owner_recipient_id, in_owner_recipient_id_len);
    vscf_impl_t *owner_private_key = zend_fetch_resource_ex(in_owner_private_key, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(owner_private_key);

    //
    // Call main function
    //
    vscf_status_t status =vscf_message_info_editor_unlock(message_info_editor, owner_recipient_id, owner_private_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_editor_add_key_recipient
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_add_key_recipient_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_recipient_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_add_key_recipient_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_recipient_id = NULL;
    size_t in_recipient_id_len = 0;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_recipient_id, in_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    vsc_data_t recipient_id = vsc_data((const byte*)in_recipient_id, in_recipient_id_len);
    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    vscf_status_t status =vscf_message_info_editor_add_key_recipient(message_info_editor, recipient_id, public_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_editor_remove_key_recipient
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_remove_key_recipient_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_recipient_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_remove_key_recipient_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_recipient_id = NULL;
    size_t in_recipient_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_recipient_id, in_recipient_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    vsc_data_t recipient_id = vsc_data((const byte*)in_recipient_id, in_recipient_id_len);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_editor_remove_key_recipient(message_info_editor, recipient_id);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_message_info_editor_remove_all
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_remove_all_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_remove_all_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    //
    // Call main function
    //
    vscf_message_info_editor_remove_all(message_info_editor);


}

//
// Wrap method: vscf_message_info_editor_packed_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_packed_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_packed_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    //
    // Call main function
    //
    size_t res =vscf_message_info_editor_packed_len(message_info_editor);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_message_info_editor_pack
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_editor_pack_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_editor_pack_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_editor_t *message_info_editor = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, le_vscf_message_info_editor_t);
    VSCF_ASSERT_PTR(message_info_editor);

    //
    // Allocate output buffer for output 'message_info'
    //
    zend_string *out_message_info = zend_string_alloc(vscf_message_info_editor_packed_len(message_info_editor), 0);
    vsc_buffer_t *message_info = vsc_buffer_new();
    vsc_buffer_use(message_info, (byte *)ZSTR_VAL(out_message_info), ZSTR_LEN(out_message_info));

    //
    // Call main function
    //
    vscf_message_info_editor_pack(message_info_editor, message_info);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_message_info) = vsc_buffer_len(message_info);

    //
    // Write returned result
    //
    RETVAL_STR(out_message_info);
}

//
// Wrap method: vscf_signer_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_new_php) {
    vscf_signer_info_t *signer_info = vscf_signer_info_new();
    zend_resource *signer_info_res = zend_register_resource(signer_info, le_vscf_signer_info_t);
    RETVAL_RES(signer_info_res);
}

//
// Wrap method: vscf_signer_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_signer_info_t *signer_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_PHP_RES_NAME, le_vscf_signer_info_t);
    VSCF_ASSERT_PTR(signer_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_signer_info_signer_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_signer_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_signer_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_t *signer_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_PHP_RES_NAME, le_vscf_signer_info_t);
    VSCF_ASSERT_PTR(signer_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_signer_info_signer_id(signer_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_signer_info_signer_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_signer_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_signer_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_t *signer_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_PHP_RES_NAME, le_vscf_signer_info_t);
    VSCF_ASSERT_PTR(signer_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_signer_info_signer_alg_info(signer_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_signer_info_signature
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_signature_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_signature_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_t *signer_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_PHP_RES_NAME, le_vscf_signer_info_t);
    VSCF_ASSERT_PTR(signer_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_signer_info_signature(signer_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_signer_info_list_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_info_list_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_new_php) {
    vscf_signer_info_list_t *signer_info_list = vscf_signer_info_list_new();
    zend_resource *signer_info_list_res = zend_register_resource(signer_info_list, le_vscf_signer_info_list_t);
    RETVAL_RES(signer_info_list_res);
}

//
// Wrap method: vscf_signer_info_list_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signer_info_list_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_signer_info_list_has_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_has_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_has_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_signer_info_list_has_item(signer_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_signer_info_list_item
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_item_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_item_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    vscf_signer_info_t *signer_info =(vscf_signer_info_t *)vscf_signer_info_list_item(signer_info_list);
    signer_info = vscf_signer_info_shallow_copy(signer_info);

    //
    // Write returned result
    //
    zend_resource *signer_info_res = zend_register_resource(signer_info, le_vscf_signer_info_t);
    RETVAL_RES(signer_info_res);
}

//
// Wrap method: vscf_signer_info_list_has_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_has_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_has_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_signer_info_list_has_next(signer_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_signer_info_list_next
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_next_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_next_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    vscf_signer_info_list_t *signer_info_list_rs =vscf_signer_info_list_next(signer_info_list);

    //
    // Write returned result
    //
    zend_resource *signer_info_list_res = zend_register_resource(signer_info_list_rs, le_vscf_signer_info_list_t);
    RETVAL_RES(signer_info_list_res);
}

//
// Wrap method: vscf_signer_info_list_has_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_has_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_has_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    zend_bool res =vscf_signer_info_list_has_prev(signer_info_list);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_signer_info_list_prev
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_prev_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_prev_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    vscf_signer_info_list_t *signer_info_list_rs =vscf_signer_info_list_prev(signer_info_list);

    //
    // Write returned result
    //
    zend_resource *signer_info_list_res = zend_register_resource(signer_info_list_rs, le_vscf_signer_info_list_t);
    RETVAL_RES(signer_info_list_res);
}

//
// Wrap method: vscf_signer_info_list_clear
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signer_info_list_clear_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signer_info_list_clear_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signer_info_list_t *signer_info_list = zend_fetch_resource_ex(in_ctx, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, le_vscf_signer_info_list_t);
    VSCF_ASSERT_PTR(signer_info_list);

    //
    // Call main function
    //
    vscf_signer_info_list_clear(signer_info_list);


}

//
// Wrap method: vscf_message_info_footer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_footer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_new_php) {
    vscf_message_info_footer_t *message_info_footer = vscf_message_info_footer_new();
    zend_resource *message_info_footer_res = zend_register_resource(message_info_footer, le_vscf_message_info_footer_t);
    RETVAL_RES(message_info_footer_res);
}

//
// Wrap method: vscf_message_info_footer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_footer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, le_vscf_message_info_footer_t);
    VSCF_ASSERT_PTR(message_info_footer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_footer_has_signer_infos
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_footer_has_signer_infos_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_has_signer_infos_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, le_vscf_message_info_footer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Call main function
    //
    zend_bool res =vscf_message_info_footer_has_signer_infos(message_info_footer);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_message_info_footer_signer_infos
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_footer_signer_infos_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_signer_infos_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, le_vscf_message_info_footer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Call main function
    //
    vscf_signer_info_list_t *signer_info_list =(vscf_signer_info_list_t *)vscf_message_info_footer_signer_infos(message_info_footer);
    signer_info_list = vscf_signer_info_list_shallow_copy(signer_info_list);

    //
    // Write returned result
    //
    zend_resource *signer_info_list_res = zend_register_resource(signer_info_list, le_vscf_signer_info_list_t);
    RETVAL_RES(signer_info_list_res);
}

//
// Wrap method: vscf_message_info_footer_signer_hash_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_footer_signer_hash_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_signer_hash_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, le_vscf_message_info_footer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_message_info_footer_signer_hash_alg_info(message_info_footer);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_message_info_footer_signer_digest
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_footer_signer_digest_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_footer_signer_digest_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, le_vscf_message_info_footer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_message_info_footer_signer_digest(message_info_footer);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_signed_data_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signed_data_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signed_data_info_new_php) {
    vscf_signed_data_info_t *signed_data_info = vscf_signed_data_info_new();
    zend_resource *signed_data_info_res = zend_register_resource(signed_data_info, le_vscf_signed_data_info_t);
    RETVAL_RES(signed_data_info_res);
}

//
// Wrap method: vscf_signed_data_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_signed_data_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signed_data_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_signed_data_info_t *signed_data_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNED_DATA_INFO_PHP_RES_NAME, le_vscf_signed_data_info_t);
    VSCF_ASSERT_PTR(signed_data_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_signed_data_info_set_hash_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signed_data_info_set_hash_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signed_data_info_set_hash_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_hash_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_hash_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signed_data_info_t *signed_data_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNED_DATA_INFO_PHP_RES_NAME, le_vscf_signed_data_info_t);
    VSCF_ASSERT_PTR(signed_data_info);

    vscf_impl_t *hash_alg_info = zend_fetch_resource_ex(in_hash_alg_info, VSCF_SIGNED_DATA_INFO_PHP_RES_NAME, le_vscf_signed_data_info_t);
    VSCF_ASSERT_PTR(hash_alg_info);

    vscf_impl_t *hash_alg_info_tmp = vscf_impl_shallow_copy(hash_alg_info);//
    // Call main function
    //
    vscf_signed_data_info_set_hash_alg_info(signed_data_info, &hash_alg_info_tmp);


}

//
// Wrap method: vscf_signed_data_info_hash_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_signed_data_info_hash_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_signed_data_info_hash_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_signed_data_info_t *signed_data_info = zend_fetch_resource_ex(in_ctx, VSCF_SIGNED_DATA_INFO_PHP_RES_NAME, le_vscf_signed_data_info_t);
    VSCF_ASSERT_PTR(signed_data_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_signed_data_info_hash_alg_info(signed_data_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_footer_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_footer_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_new_php) {
    vscf_footer_info_t *footer_info = vscf_footer_info_new();
    zend_resource *footer_info_res = zend_register_resource(footer_info, le_vscf_footer_info_t);
    RETVAL_RES(footer_info_res);
}

//
// Wrap method: vscf_footer_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_footer_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_footer_info_t *footer_info = zend_fetch_resource_ex(in_ctx, VSCF_FOOTER_INFO_PHP_RES_NAME, le_vscf_footer_info_t);
    VSCF_ASSERT_PTR(footer_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_footer_info_has_signed_data_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_footer_info_has_signed_data_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_has_signed_data_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_footer_info_t *footer_info = zend_fetch_resource_ex(in_ctx, VSCF_FOOTER_INFO_PHP_RES_NAME, le_vscf_footer_info_t);
    VSCF_ASSERT_PTR(footer_info);

    //
    // Call main function
    //
    zend_bool res =vscf_footer_info_has_signed_data_info(footer_info);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_footer_info_signed_data_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_footer_info_signed_data_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_signed_data_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_footer_info_t *footer_info = zend_fetch_resource_ex(in_ctx, VSCF_FOOTER_INFO_PHP_RES_NAME, le_vscf_footer_info_t);
    VSCF_ASSERT_PTR(footer_info);

    //
    // Call main function
    //
    vscf_signed_data_info_t *signed_data_info =(vscf_signed_data_info_t *)vscf_footer_info_signed_data_info(footer_info);
    signed_data_info = vscf_signed_data_info_shallow_copy(signed_data_info);

    //
    // Write returned result
    //
    zend_resource *signed_data_info_res = zend_register_resource(signed_data_info, le_vscf_signed_data_info_t);
    RETVAL_RES(signed_data_info_res);
}

//
// Wrap method: vscf_footer_info_set_data_size
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_footer_info_set_data_size_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_size, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_set_data_size_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_size = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_size)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_footer_info_t *footer_info = zend_fetch_resource_ex(in_ctx, VSCF_FOOTER_INFO_PHP_RES_NAME, le_vscf_footer_info_t);
    VSCF_ASSERT_PTR(footer_info);

    size_t data_size = in_data_size;

    //
    // Call main function
    //
    vscf_footer_info_set_data_size(footer_info, data_size);


}

//
// Wrap method: vscf_footer_info_data_size
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_footer_info_data_size_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_footer_info_data_size_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_footer_info_t *footer_info = zend_fetch_resource_ex(in_ctx, VSCF_FOOTER_INFO_PHP_RES_NAME, le_vscf_footer_info_t);
    VSCF_ASSERT_PTR(footer_info);

    //
    // Call main function
    //
    size_t res =vscf_footer_info_data_size(footer_info);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_sha224_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha224_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_new_php) {
    vscf_sha224_t *sha224 = vscf_sha224_new();
    zend_resource *sha224_res = zend_register_resource(sha224, le_vscf_sha224_t);
    RETVAL_RES(sha224_res);
}

//
// Wrap method: vscf_sha224_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha224_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha224_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    //
    // Call main function
    //
    int alg_id =vscf_sha224_alg_id(sha224);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_sha224_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_sha224_produce_alg_info(sha224);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_sha224_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_sha224_restore_alg_info(sha224, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha224_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_hash_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha224_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha224_hash(data, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha224_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_start_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_start_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    //
    // Call main function
    //
    vscf_sha224_start(sha224);


}

//
// Wrap method: vscf_sha224_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_sha224_update(sha224, data);


}

//
// Wrap method: vscf_sha224_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha224_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha224_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha224_t *sha224 = zend_fetch_resource_ex(in_ctx, VSCF_SHA224_PHP_RES_NAME, le_vscf_sha224_t);
    VSCF_ASSERT_PTR(sha224);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha224_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha224_finish(sha224, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha256_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_new_php) {
    vscf_sha256_t *sha256 = vscf_sha256_new();
    zend_resource *sha256_res = zend_register_resource(sha256, le_vscf_sha256_t);
    RETVAL_RES(sha256_res);
}

//
// Wrap method: vscf_sha256_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha256_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    //
    // Call main function
    //
    int alg_id =vscf_sha256_alg_id(sha256);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_sha256_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_sha256_produce_alg_info(sha256);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_sha256_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_sha256_restore_alg_info(sha256, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha256_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_hash_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha256_hash(data, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha256_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_start_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_start_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    //
    // Call main function
    //
    vscf_sha256_start(sha256);


}

//
// Wrap method: vscf_sha256_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_sha256_update(sha256, data);


}

//
// Wrap method: vscf_sha256_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha256_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha256_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_ctx, VSCF_SHA256_PHP_RES_NAME, le_vscf_sha256_t);
    VSCF_ASSERT_PTR(sha256);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha256_finish(sha256, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha384_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha384_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_new_php) {
    vscf_sha384_t *sha384 = vscf_sha384_new();
    zend_resource *sha384_res = zend_register_resource(sha384, le_vscf_sha384_t);
    RETVAL_RES(sha384_res);
}

//
// Wrap method: vscf_sha384_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha384_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha384_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    //
    // Call main function
    //
    int alg_id =vscf_sha384_alg_id(sha384);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_sha384_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_sha384_produce_alg_info(sha384);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_sha384_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_sha384_restore_alg_info(sha384, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha384_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_hash_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha384_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha384_hash(data, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha384_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_start_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_start_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    //
    // Call main function
    //
    vscf_sha384_start(sha384);


}

//
// Wrap method: vscf_sha384_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_sha384_update(sha384, data);


}

//
// Wrap method: vscf_sha384_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha384_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha384_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha384_t *sha384 = zend_fetch_resource_ex(in_ctx, VSCF_SHA384_PHP_RES_NAME, le_vscf_sha384_t);
    VSCF_ASSERT_PTR(sha384);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha384_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha384_finish(sha384, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha512_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha512_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_new_php) {
    vscf_sha512_t *sha512 = vscf_sha512_new();
    zend_resource *sha512_res = zend_register_resource(sha512, le_vscf_sha512_t);
    RETVAL_RES(sha512_res);
}

//
// Wrap method: vscf_sha512_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha512_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha512_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    //
    // Call main function
    //
    int alg_id =vscf_sha512_alg_id(sha512);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_sha512_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_sha512_produce_alg_info(sha512);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_sha512_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_sha512_restore_alg_info(sha512, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_sha512_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_hash_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha512_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha512_hash(data, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_sha512_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_start_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_start_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    //
    // Call main function
    //
    vscf_sha512_start(sha512);


}

//
// Wrap method: vscf_sha512_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_sha512_update(sha512, data);


}

//
// Wrap method: vscf_sha512_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sha512_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sha512_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sha512_t *sha512 = zend_fetch_resource_ex(in_ctx, VSCF_SHA512_PHP_RES_NAME, le_vscf_sha512_t);
    VSCF_ASSERT_PTR(sha512);

    //
    // Allocate output buffer for output 'digest'
    //
    zend_string *out_digest = zend_string_alloc(vscf_sha512_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    //
    // Call main function
    //
    vscf_sha512_finish(sha512, digest);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    // Write returned result
    //
    RETVAL_STR(out_digest);
}

//
// Wrap method: vscf_aes256_gcm_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_aes256_gcm_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_new_php) {
    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();
    zend_resource *aes256_gcm_res = zend_register_resource(aes256_gcm, le_vscf_aes256_gcm_t);
    RETVAL_RES(aes256_gcm_res);
}

//
// Wrap method: vscf_aes256_gcm_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_aes256_gcm_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_aes256_gcm_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Call main function
    //
    int alg_id =vscf_aes256_gcm_alg_id(aes256_gcm);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_aes256_gcm_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_aes256_gcm_produce_alg_info(aes256_gcm);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_aes256_gcm_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_restore_alg_info(aes256_gcm, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_aes256_gcm_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_encrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_encrypted_len(aes256_gcm, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_encrypt(aes256_gcm, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_gcm_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_encrypted_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_precise_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_precise_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_precise_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_precise_encrypted_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_decrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_decrypted_len(aes256_gcm, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_decrypt(aes256_gcm, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_gcm_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_decrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_decrypted_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_set_nonce
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_set_nonce_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_nonce, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_set_nonce_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_nonce = NULL;
    size_t in_nonce_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_nonce, in_nonce_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t nonce = vsc_data((const byte*)in_nonce, in_nonce_len);

    //
    // Call main function
    //
    vscf_aes256_gcm_set_nonce(aes256_gcm, nonce);


}

//
// Wrap method: vscf_aes256_gcm_set_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_set_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_set_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);

    //
    // Call main function
    //
    vscf_aes256_gcm_set_key(aes256_gcm, key);


}

//
// Wrap method: vscf_aes256_gcm_start_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_start_encryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_start_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Call main function
    //
    vscf_aes256_gcm_start_encryption(aes256_gcm);


}

//
// Wrap method: vscf_aes256_gcm_start_decryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_start_decryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_start_decryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Call main function
    //
    vscf_aes256_gcm_start_decryption(aes256_gcm);


}

//
// Wrap method: vscf_aes256_gcm_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_out_len(aes256_gcm, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_aes256_gcm_update(aes256_gcm, data, out);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);
}

//
// Wrap method: vscf_aes256_gcm_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_out_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_encrypted_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_encrypted_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_encrypted_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_encrypted_out_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_decrypted_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_decrypted_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_decrypted_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_decrypted_out_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_out_len(aes256_gcm, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_finish(aes256_gcm, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_gcm_auth_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_auth_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_auth_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_auth_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    char *in_auth_data = NULL;
    size_t in_auth_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_auth_data, in_auth_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    vsc_data_t auth_data = vsc_data((const byte*)in_auth_data, in_auth_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Allocate output buffer for output 'tag'
    //
    zend_string *out_tag = zend_string_alloc(vscf_aes256_gcm_AUTH_TAG_LEN, 0);
    vsc_buffer_t *tag = vsc_buffer_new();
    vsc_buffer_use(tag, (byte *)ZSTR_VAL(out_tag), ZSTR_LEN(out_tag));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_auth_encrypt(aes256_gcm, data, auth_data, out, tag);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);
    ZSTR_LEN(out_tag) = vsc_buffer_len(tag);

    //
    // Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_out);
    add_next_index_str(return_value, out_tag);

    goto success;

fail:
    zend_string_free(out_out);
    zend_string_free(out_tag);
success:
    vsc_buffer_destroy(&out);
    vsc_buffer_destroy(&tag);
}

//
// Wrap method: vscf_aes256_gcm_auth_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_auth_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_auth_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_auth_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_auth_decrypt_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_auth_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_auth_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    char *in_auth_data = NULL;
    size_t in_auth_data_len = 0;
    char *in_tag = NULL;
    size_t in_tag_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_auth_data, in_auth_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_tag, in_tag_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    vsc_data_t auth_data = vsc_data((const byte*)in_auth_data, in_auth_data_len);
    vsc_data_t tag = vsc_data((const byte*)in_tag, in_tag_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_auth_decrypt(aes256_gcm, data, auth_data, tag, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_gcm_auth_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_auth_decrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_auth_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_gcm_set_auth_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_set_auth_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_auth_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_set_auth_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_auth_data = NULL;
    size_t in_auth_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_auth_data, in_auth_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t auth_data = vsc_data((const byte*)in_auth_data, in_auth_data_len);

    //
    // Call main function
    //
    vscf_aes256_gcm_set_auth_data(aes256_gcm, auth_data);


}

//
// Wrap method: vscf_aes256_gcm_finish_auth_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_finish_auth_encryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_ARRAY /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_finish_auth_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_out_len(aes256_gcm, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Allocate output buffer for output 'tag'
    //
    zend_string *out_tag = zend_string_alloc(vscf_aes256_gcm_AUTH_TAG_LEN, 0);
    vsc_buffer_t *tag = vsc_buffer_new();
    vsc_buffer_use(tag, (byte *)ZSTR_VAL(out_tag), ZSTR_LEN(out_tag));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_finish_auth_encryption(aes256_gcm, out, tag);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);
    ZSTR_LEN(out_tag) = vsc_buffer_len(tag);

    //
    // Write returned result
    //
    array_init(return_value);
    add_next_index_str(return_value, out_out);
    add_next_index_str(return_value, out_tag);

    goto success;

fail:
    zend_string_free(out_out);
    zend_string_free(out_tag);
success:
    vsc_buffer_destroy(&out);
    vsc_buffer_destroy(&tag);
}

//
// Wrap method: vscf_aes256_gcm_finish_auth_decryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_gcm_finish_auth_decryption_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_gcm_finish_auth_decryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_tag = NULL;
    size_t in_tag_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_tag, in_tag_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_gcm_t *aes256_gcm = zend_fetch_resource_ex(in_ctx, VSCF_AES256_GCM_PHP_RES_NAME, le_vscf_aes256_gcm_t);
    VSCF_ASSERT_PTR(aes256_gcm);

    vsc_data_t tag = vsc_data((const byte*)in_tag, in_tag_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_gcm_out_len(aes256_gcm, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_gcm_finish_auth_decryption(aes256_gcm, tag, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_cbc_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_aes256_cbc_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_new_php) {
    vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();
    zend_resource *aes256_cbc_res = zend_register_resource(aes256_cbc, le_vscf_aes256_cbc_t);
    RETVAL_RES(aes256_cbc_res);
}

//
// Wrap method: vscf_aes256_cbc_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_aes256_cbc_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_aes256_cbc_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    //
    // Call main function
    //
    int alg_id =vscf_aes256_cbc_alg_id(aes256_cbc);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_aes256_cbc_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_aes256_cbc_produce_alg_info(aes256_cbc);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_aes256_cbc_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_cbc_restore_alg_info(aes256_cbc, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_aes256_cbc_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_encrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_cbc_encrypted_len(aes256_cbc, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_cbc_encrypt(aes256_cbc, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_cbc_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_encrypted_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_precise_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_precise_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_precise_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_precise_encrypted_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_decrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_cbc_decrypted_len(aes256_cbc, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_cbc_decrypt(aes256_cbc, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_aes256_cbc_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_decrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_decrypted_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_set_nonce
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_set_nonce_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_nonce, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_set_nonce_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_nonce = NULL;
    size_t in_nonce_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_nonce, in_nonce_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vsc_data_t nonce = vsc_data((const byte*)in_nonce, in_nonce_len);

    //
    // Call main function
    //
    vscf_aes256_cbc_set_nonce(aes256_cbc, nonce);


}

//
// Wrap method: vscf_aes256_cbc_set_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_set_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_set_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);

    //
    // Call main function
    //
    vscf_aes256_cbc_set_key(aes256_cbc, key);


}

//
// Wrap method: vscf_aes256_cbc_start_encryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_start_encryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_start_encryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    //
    // Call main function
    //
    vscf_aes256_cbc_start_encryption(aes256_cbc);


}

//
// Wrap method: vscf_aes256_cbc_start_decryption
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_start_decryption_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_start_decryption_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    //
    // Call main function
    //
    vscf_aes256_cbc_start_decryption(aes256_cbc);


}

//
// Wrap method: vscf_aes256_cbc_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_cbc_out_len(aes256_cbc, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_aes256_cbc_update(aes256_cbc, data, out);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);
}

//
// Wrap method: vscf_aes256_cbc_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_out_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_encrypted_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_encrypted_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_encrypted_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_encrypted_out_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_decrypted_out_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_decrypted_out_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_decrypted_out_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_aes256_cbc_decrypted_out_len(aes256_cbc, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_aes256_cbc_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_aes256_cbc_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_aes256_cbc_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_aes256_cbc_t *aes256_cbc = zend_fetch_resource_ex(in_ctx, VSCF_AES256_CBC_PHP_RES_NAME, le_vscf_aes256_cbc_t);
    VSCF_ASSERT_PTR(aes256_cbc);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_aes256_cbc_out_len(aes256_cbc, 0), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_aes256_cbc_finish(aes256_cbc, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_asn1rd_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_asn1rd_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_new_php) {
    vscf_asn1rd_t *asn1rd = vscf_asn1rd_new();
    zend_resource *asn1rd_res = zend_register_resource(asn1rd, le_vscf_asn1rd_t);
    RETVAL_RES(asn1rd_res);
}

//
// Wrap method: vscf_asn1rd_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_asn1rd_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_asn1rd_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_reset_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_asn1rd_reset(asn1rd, data);


}

//
// Wrap method: vscf_asn1rd_left_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_left_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_left_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    size_t res =vscf_asn1rd_left_len(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_has_error
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_has_error_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_has_error_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    zend_bool res =vscf_asn1rd_has_error(asn1rd);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_asn1rd_status
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_status_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_status_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vscf_status_t status =vscf_asn1rd_status(asn1rd);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_asn1rd_get_tag
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_get_tag_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_get_tag_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_get_tag(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_get_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_get_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_get_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    size_t res =vscf_asn1rd_get_len(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_get_data_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_get_data_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_get_data_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    size_t res =vscf_asn1rd_get_data_len(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_tag
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_tag_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_tag_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_tag = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_tag)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    int tag = in_tag;//
    // Call main function
    //
    size_t res =vscf_asn1rd_read_tag(asn1rd, tag);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_context_tag
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_context_tag_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_context_tag_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_tag = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_tag)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    int tag = in_tag;//
    // Call main function
    //
    size_t res =vscf_asn1rd_read_context_tag(asn1rd, tag);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_int
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_int_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_int_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_int(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_int8
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_int8_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_int8_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_int8(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_int16
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_int16_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_int16_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_int16(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_int32
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_int32_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_int32_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_int32(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_int64
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_int64_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_int64_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_int64(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_uint
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_uint_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_uint_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_uint(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_uint8
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_uint8_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_uint8_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_uint8(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_uint16
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_uint16_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_uint16_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_uint16(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_uint32
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_uint32_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_uint32_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_uint32(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_uint64
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_uint64_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_uint64_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    int res =vscf_asn1rd_read_uint64(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_bool
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_bool_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_bool_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    zend_bool res =vscf_asn1rd_read_bool(asn1rd);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_asn1rd_read_null
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_null_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_null_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vscf_asn1rd_read_null(asn1rd);


}

//
// Wrap method: vscf_asn1rd_read_null_optional
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_null_optional_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_null_optional_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vscf_asn1rd_read_null_optional(asn1rd);


}

//
// Wrap method: vscf_asn1rd_read_octet_str
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_octet_str_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_octet_str_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_asn1rd_read_octet_str(asn1rd);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_asn1rd_read_bitstring_as_octet_str
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_bitstring_as_octet_str_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_bitstring_as_octet_str_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_asn1rd_read_bitstring_as_octet_str(asn1rd);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_asn1rd_read_utf8_str
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_utf8_str_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_utf8_str_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_asn1rd_read_utf8_str(asn1rd);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_asn1rd_read_oid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_oid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_oid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_asn1rd_read_oid(asn1rd);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_asn1rd_read_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    size_t len = in_len;

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_asn1rd_read_data(asn1rd, len);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_asn1rd_read_sequence
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_sequence_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_sequence_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    size_t res =vscf_asn1rd_read_sequence(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1rd_read_set
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1rd_read_set_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1rd_read_set_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1rd_t *asn1rd = zend_fetch_resource_ex(in_ctx, VSCF_ASN1RD_PHP_RES_NAME, le_vscf_asn1rd_t);
    VSCF_ASSERT_PTR(asn1rd);

    //
    // Call main function
    //
    size_t res =vscf_asn1rd_read_set(asn1rd);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_asn1wr_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_new_php) {
    vscf_asn1wr_t *asn1wr = vscf_asn1wr_new();
    zend_resource *asn1wr_res = zend_register_resource(asn1wr, le_vscf_asn1wr_t);
    RETVAL_RES(asn1wr_res);
}

//
// Wrap method: vscf_asn1wr_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_asn1wr_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_asn1wr_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_reset_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_out, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_out_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_out = 0;
    zend_long in_out_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_out)
        Z_PARAM_LONG(in_out_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t out_len = in_out_len;

    byte out = in_out;//
    // Call main function
    //
    vscf_asn1wr_reset(asn1wr, out, out_len);


}

//
// Wrap method: vscf_asn1wr_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_finish_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_do_not_adjust, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_bool *in_do_not_adjust;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_BOOL(in_do_not_adjust)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    bool do_not_adjust = (bool)in_do_not_adjust;//
    // Call main function
    //
    size_t res =vscf_asn1wr_finish(asn1wr, do_not_adjust);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_bytes
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_bytes_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_bytes_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    int *res =vscf_asn1wr_bytes(asn1wr);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_len(asn1wr);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_written_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_written_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_written_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_written_len(asn1wr);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_unwritten_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_unwritten_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_unwritten_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_unwritten_len(asn1wr);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_has_error
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_has_error_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_has_error_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    zend_bool res =vscf_asn1wr_has_error(asn1wr);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_asn1wr_status
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_status_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_status_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    vscf_status_t status =vscf_asn1wr_status(asn1wr);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_asn1wr_reserve
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_reserve_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_reserve_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t len = in_len;

    //
    // Call main function
    //
    int *res =vscf_asn1wr_reserve(asn1wr, len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_tag
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_tag_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_tag_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_tag = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_tag)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int tag = in_tag;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_tag(asn1wr, tag);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_context_tag
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_context_tag_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_tag, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_context_tag_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_tag = 0;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_tag)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t len = in_len;

    int tag = in_tag;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_context_tag(asn1wr, tag, len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t len = in_len;

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_len(asn1wr, len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_int
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_int_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_int_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_int(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_int8
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_int8_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_int8_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int8_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_int8(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_int16
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_int16_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_int16_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int16_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_int16(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_int32
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_int32_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_int32_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int32_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_int32(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_int64
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_int64_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_int64_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    int64_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_int64(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_uint
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_uint_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_uint_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    unsigned int value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_uint(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_uint8
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_uint8_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_uint8_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    uint8_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_uint8(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_uint16
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_uint16_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_uint16_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    uint16_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_uint16(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_uint32
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_uint32_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_uint32_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    uint32_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_uint32(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_uint64
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_uint64_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_uint64_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_value = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    uint64_t value = in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_uint64(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_bool
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_bool_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_bool_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_bool *in_value;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_BOOL(in_value)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    bool value = (bool)in_value;//
    // Call main function
    //
    size_t res =vscf_asn1wr_write_bool(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_null
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_null_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_null_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_null(asn1wr);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_octet_str
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_octet_str_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_octet_str_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_octet_str(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_octet_str_as_bitstring
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_octet_str_as_bitstring_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_octet_str_as_bitstring_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_octet_str_as_bitstring(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_data(asn1wr, data);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_utf8_str
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_utf8_str_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_utf8_str_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_utf8_str(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_oid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_oid_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_value, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_oid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_value = NULL;
    size_t in_value_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_value, in_value_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    vsc_data_t value = vsc_data((const byte*)in_value, in_value_len);

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_oid(asn1wr, value);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_sequence
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_sequence_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_sequence_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t len = in_len;

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_sequence(asn1wr, len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_asn1wr_write_set
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_asn1wr_write_set_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_asn1wr_write_set_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_asn1wr_t *asn1wr = zend_fetch_resource_ex(in_ctx, VSCF_ASN1WR_PHP_RES_NAME, le_vscf_asn1wr_t);
    VSCF_ASSERT_PTR(asn1wr);

    size_t len = in_len;

    //
    // Call main function
    //
    size_t res =vscf_asn1wr_write_set(asn1wr, len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_public_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_public_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_new_php) {
    vscf_rsa_public_key_t *rsa_public_key = vscf_rsa_public_key_new();
    zend_resource *rsa_public_key_res = zend_register_resource(rsa_public_key, le_vscf_rsa_public_key_t);
    RETVAL_RES(rsa_public_key_res);
}

//
// Wrap method: vscf_rsa_public_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_public_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_rsa_public_key_key_exponent
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_key_exponent_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_key_exponent_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_public_key_key_exponent(rsa_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_public_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    int alg_id =vscf_rsa_public_key_alg_id(rsa_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_rsa_public_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_rsa_public_key_alg_info(rsa_public_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_rsa_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_public_key_len(rsa_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_public_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_public_key_bitlen(rsa_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_public_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_public_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_public_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_public_key_t *rsa_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, le_vscf_rsa_public_key_t);
    VSCF_ASSERT_PTR(rsa_public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_public_key_is_valid(rsa_public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_private_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_private_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_new_php) {
    vscf_rsa_private_key_t *rsa_private_key = vscf_rsa_private_key_new();
    zend_resource *rsa_private_key_res = zend_register_resource(rsa_private_key, le_vscf_rsa_private_key_t);
    RETVAL_RES(rsa_private_key_res);
}

//
// Wrap method: vscf_rsa_private_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_private_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_rsa_private_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    int alg_id =vscf_rsa_private_key_alg_id(rsa_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_rsa_private_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_rsa_private_key_alg_info(rsa_private_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_rsa_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_private_key_len(rsa_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_private_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_private_key_bitlen(rsa_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_private_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_private_key_is_valid(rsa_private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_private_key_extract_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_private_key_extract_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_private_key_extract_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_private_key_t *rsa_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, le_vscf_rsa_private_key_t);
    VSCF_ASSERT_PTR(rsa_private_key);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_rsa_private_key_extract_public_key(rsa_private_key);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_rsa_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_new_php) {
    vscf_rsa_t *rsa = vscf_rsa_new();
    zend_resource *rsa_res = zend_register_resource(rsa, le_vscf_rsa_t);
    RETVAL_RES(rsa_res);
}

//
// Wrap method: vscf_rsa_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_rsa_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_rsa_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    //
    // Call main function
    //
    vscf_status_t status =vscf_rsa_setup_defaults(rsa);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_rsa_generate_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_generate_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_bitlen, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_generate_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_bitlen = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_bitlen)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    size_t bitlen = in_bitlen;
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_rsa_generate_key(rsa, bitlen, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_rsa_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    //
    // Call main function
    //
    int alg_id =vscf_rsa_alg_id(rsa);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_rsa_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_rsa_produce_alg_info(rsa);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_rsa_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_rsa_restore_alg_info(rsa, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_rsa_generate_ephemeral_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_generate_ephemeral_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_generate_ephemeral_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_rsa_generate_ephemeral_key(rsa, key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_rsa_import_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_import_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_import_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_raw_public_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_rsa_import_public_key(rsa, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_rsa_export_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_export_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_export_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_rsa_export_public_key(rsa, public_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_rsa_import_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_import_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_import_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_raw_private_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_rsa_import_private_key(rsa, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_rsa_export_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_export_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_export_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_rsa_export_private_key(rsa, private_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_rsa_can_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_can_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_can_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_can_encrypt(rsa, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_encrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_rsa_encrypted_len(rsa, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_rsa_encrypted_len(rsa, public_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_rsa_encrypt(rsa, public_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_rsa_can_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_can_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_can_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_can_decrypt(rsa, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_decrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_rsa_decrypted_len(rsa, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_rsa_decrypted_len(rsa, private_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_rsa_decrypt(rsa, private_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_rsa_can_sign
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_can_sign_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_can_sign_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_can_sign(rsa, private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_signature_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_signature_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_signature_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_rsa_signature_len(rsa, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_rsa_sign_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_sign_hash_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_sign_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);

    //
    // Allocate output buffer for output 'signature'
    //
    zend_string *out_signature = zend_string_alloc(vscf_rsa_signature_len(rsa, private_key), 0);
    vsc_buffer_t *signature = vsc_buffer_new();
    vsc_buffer_use(signature, (byte *)ZSTR_VAL(out_signature), ZSTR_LEN(out_signature));

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    vscf_status_t status =vscf_rsa_sign_hash(rsa, private_key, hash_id, digest, signature);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_signature) = vsc_buffer_len(signature);

    //
    // Write returned result
    //
    RETVAL_STR(out_signature);

    goto success;

fail:
    zend_string_free(out_signature);
success:
    vsc_buffer_destroy(&signature);
}

//
// Wrap method: vscf_rsa_can_verify
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_can_verify_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_can_verify_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_rsa_can_verify(rsa, public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_rsa_verify_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_rsa_verify_hash_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_signature, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_rsa_verify_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;
    char *in_signature = NULL;
    size_t in_signature_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_signature, in_signature_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_rsa_t *rsa = zend_fetch_resource_ex(in_ctx, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(rsa);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_RSA_PHP_RES_NAME, le_vscf_rsa_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);
    vsc_data_t signature = vsc_data((const byte*)in_signature, in_signature_len);

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    zend_bool res =vscf_rsa_verify_hash(rsa, public_key, hash_id, digest, signature);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_public_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_public_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_new_php) {
    vscf_ecc_public_key_t *ecc_public_key = vscf_ecc_public_key_new();
    zend_resource *ecc_public_key_res = zend_register_resource(ecc_public_key, le_vscf_ecc_public_key_t);
    RETVAL_RES(ecc_public_key_res);
}

//
// Wrap method: vscf_ecc_public_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_public_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_public_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_public_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);

    //
    // Call main function
    //
    int alg_id =vscf_ecc_public_key_alg_id(ecc_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_ecc_public_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_public_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_ecc_public_key_alg_info(ecc_public_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_ecc_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_public_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_public_key_len(ecc_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_public_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_public_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_public_key_bitlen(ecc_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_public_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_public_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_public_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_public_key_t *ecc_public_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, le_vscf_ecc_public_key_t);
    VSCF_ASSERT_PTR(ecc_public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_public_key_is_valid(ecc_public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_private_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_private_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_new_php) {
    vscf_ecc_private_key_t *ecc_private_key = vscf_ecc_private_key_new();
    zend_resource *ecc_private_key_res = zend_register_resource(ecc_private_key, le_vscf_ecc_private_key_t);
    RETVAL_RES(ecc_private_key_res);
}

//
// Wrap method: vscf_ecc_private_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_private_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_private_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    int alg_id =vscf_ecc_private_key_alg_id(ecc_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_ecc_private_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_ecc_private_key_alg_info(ecc_private_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_ecc_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_private_key_len(ecc_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_private_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_private_key_bitlen(ecc_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_private_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_private_key_is_valid(ecc_private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_private_key_extract_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_private_key_extract_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_private_key_extract_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_private_key_t *ecc_private_key = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, le_vscf_ecc_private_key_t);
    VSCF_ASSERT_PTR(ecc_private_key);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_ecc_private_key_extract_public_key(ecc_private_key);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_ecc_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_new_php) {
    vscf_ecc_t *ecc = vscf_ecc_new();
    zend_resource *ecc_res = zend_register_resource(ecc, le_vscf_ecc_t);
    RETVAL_RES(ecc_res);
}

//
// Wrap method: vscf_ecc_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecc_setup_defaults(ecc);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_generate_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_generate_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_generate_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_alg_id = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_alg_id)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_alg_id_t alg_id = (vscf_alg_id_t)in_alg_id;//
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ecc_generate_key(ecc, alg_id, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ecc_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    //
    // Call main function
    //
    int alg_id =vscf_ecc_alg_id(ecc);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_ecc_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_ecc_produce_alg_info(ecc);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_ecc_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecc_restore_alg_info(ecc, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_generate_ephemeral_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_generate_ephemeral_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_generate_ephemeral_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ecc_generate_ephemeral_key(ecc, key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ecc_import_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_import_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_import_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_raw_public_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_ecc_import_public_key(ecc, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_ecc_export_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_export_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_export_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_ecc_export_public_key(ecc, public_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_ecc_import_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_import_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_import_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_raw_private_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ecc_import_private_key(ecc, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ecc_export_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_export_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_export_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_ecc_export_private_key(ecc, private_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_ecc_can_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_can_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_can_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_can_encrypt(ecc, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_encrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ecc_encrypted_len(ecc, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ecc_encrypted_len(ecc, public_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecc_encrypt(ecc, public_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ecc_can_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_can_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_can_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_can_decrypt(ecc, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_decrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ecc_decrypted_len(ecc, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ecc_decrypted_len(ecc, private_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecc_decrypt(ecc, private_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ecc_can_sign
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_can_sign_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_can_sign_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_can_sign(ecc, private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_signature_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_signature_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_signature_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_signature_len(ecc, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ecc_sign_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_sign_hash_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_sign_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);

    //
    // Allocate output buffer for output 'signature'
    //
    zend_string *out_signature = zend_string_alloc(vscf_ecc_signature_len(ecc, private_key), 0);
    vsc_buffer_t *signature = vsc_buffer_new();
    vsc_buffer_use(signature, (byte *)ZSTR_VAL(out_signature), ZSTR_LEN(out_signature));

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    vscf_status_t status =vscf_ecc_sign_hash(ecc, private_key, hash_id, digest, signature);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_signature) = vsc_buffer_len(signature);

    //
    // Write returned result
    //
    RETVAL_STR(out_signature);

    goto success;

fail:
    zend_string_free(out_signature);
success:
    vsc_buffer_destroy(&signature);
}

//
// Wrap method: vscf_ecc_can_verify
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_can_verify_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_can_verify_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ecc_can_verify(ecc, public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_verify_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_verify_hash_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_signature, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_verify_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;
    char *in_signature = NULL;
    size_t in_signature_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_signature, in_signature_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);
    vsc_data_t signature = vsc_data((const byte*)in_signature, in_signature_len);

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    zend_bool res =vscf_ecc_verify_hash(ecc, public_key, hash_id, digest, signature);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ecc_compute_shared_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_compute_shared_key_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_compute_shared_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'shared_key'
    //
    zend_string *out_shared_key = zend_string_alloc(vscf_ecc_shared_key_len(ecc, private_key), 0);
    vsc_buffer_t *shared_key = vsc_buffer_new();
    vsc_buffer_use(shared_key, (byte *)ZSTR_VAL(out_shared_key), ZSTR_LEN(out_shared_key));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ecc_compute_shared_key(ecc, public_key, private_key, shared_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_shared_key) = vsc_buffer_len(shared_key);

    //
    // Write returned result
    //
    RETVAL_STR(out_shared_key);

    goto success;

fail:
    zend_string_free(out_shared_key);
success:
    vsc_buffer_destroy(&shared_key);
}

//
// Wrap method: vscf_ecc_shared_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_shared_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_shared_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_t *ecc = zend_fetch_resource_ex(in_ctx, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(ecc);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ECC_PHP_RES_NAME, le_vscf_ecc_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_ecc_shared_key_len(ecc, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_entropy_accumulator_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_entropy_accumulator_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_new_php) {
    vscf_entropy_accumulator_t *entropy_accumulator = vscf_entropy_accumulator_new();
    zend_resource *entropy_accumulator_res = zend_register_resource(entropy_accumulator, le_vscf_entropy_accumulator_t);
    RETVAL_RES(entropy_accumulator_res);
}

//
// Wrap method: vscf_entropy_accumulator_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_entropy_accumulator_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_entropy_accumulator_t *entropy_accumulator = zend_fetch_resource_ex(in_ctx, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(entropy_accumulator);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_entropy_accumulator_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_entropy_accumulator_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_entropy_accumulator_t *entropy_accumulator = zend_fetch_resource_ex(in_ctx, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(entropy_accumulator);

    //
    // Call main function
    //
    vscf_entropy_accumulator_setup_defaults(entropy_accumulator);


}

//
// Wrap method: vscf_entropy_accumulator_add_source
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_entropy_accumulator_add_source_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_source, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_add_source_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_source = NULL;
    zend_long in_threshold = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_source, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_threshold)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_entropy_accumulator_t *entropy_accumulator = zend_fetch_resource_ex(in_ctx, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(entropy_accumulator);

    vscf_impl_t *source = zend_fetch_resource_ex(in_source, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(source);
    size_t threshold = in_threshold;

    //
    // Call main function
    //
    vscf_entropy_accumulator_add_source(entropy_accumulator, source, threshold);


}

//
// Wrap method: vscf_entropy_accumulator_is_strong
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_entropy_accumulator_is_strong_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_is_strong_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_entropy_accumulator_t *entropy_accumulator = zend_fetch_resource_ex(in_ctx, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(entropy_accumulator);

    //
    // Call main function
    //
    zend_bool res =vscf_entropy_accumulator_is_strong(entropy_accumulator);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_entropy_accumulator_gather
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_entropy_accumulator_gather_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_entropy_accumulator_gather_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_entropy_accumulator_t *entropy_accumulator = zend_fetch_resource_ex(in_ctx, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, le_vscf_entropy_accumulator_t);
    VSCF_ASSERT_PTR(entropy_accumulator);

    size_t len = in_len;

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(len, 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_entropy_accumulator_gather(entropy_accumulator, len, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ctr_drbg_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ctr_drbg_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_new_php) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    zend_resource *ctr_drbg_res = zend_register_resource(ctr_drbg, le_vscf_ctr_drbg_t);
    RETVAL_RES(ctr_drbg_res);
}

//
// Wrap method: vscf_ctr_drbg_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ctr_drbg_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ctr_drbg_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ctr_drbg_setup_defaults(ctr_drbg);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ctr_drbg_enable_prediction_resistance
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_enable_prediction_resistance_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_enable_prediction_resistance_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    //
    // Call main function
    //
    vscf_ctr_drbg_enable_prediction_resistance(ctr_drbg);


}

//
// Wrap method: vscf_ctr_drbg_set_reseed_interval
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_set_reseed_interval_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_interval, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_set_reseed_interval_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_interval = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_interval)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    size_t interval = in_interval;

    //
    // Call main function
    //
    vscf_ctr_drbg_set_reseed_interval(ctr_drbg, interval);


}

//
// Wrap method: vscf_ctr_drbg_set_entropy_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_set_entropy_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_set_entropy_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    size_t len = in_len;

    //
    // Call main function
    //
    vscf_ctr_drbg_set_entropy_len(ctr_drbg, len);


}

//
// Wrap method: vscf_ctr_drbg_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    size_t data_len = in_data_len;

    //
    // Allocate output buffer for output 'data'
    //
    zend_string *out_data = zend_string_alloc(data_len, 0);
    vsc_buffer_t *data = vsc_buffer_new();
    vsc_buffer_use(data, (byte *)ZSTR_VAL(out_data), ZSTR_LEN(out_data));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ctr_drbg_random(ctr_drbg, data_len, data);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_data) = vsc_buffer_len(data);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);

    goto success;

fail:
    zend_string_free(out_data);
success:
    vsc_buffer_destroy(&data);
}

//
// Wrap method: vscf_ctr_drbg_reseed
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ctr_drbg_reseed_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ctr_drbg_reseed_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ctr_drbg_t *ctr_drbg = zend_fetch_resource_ex(in_ctx, VSCF_CTR_DRBG_PHP_RES_NAME, le_vscf_ctr_drbg_t);
    VSCF_ASSERT_PTR(ctr_drbg);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ctr_drbg_reseed(ctr_drbg);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_hmac_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hmac_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_new_php) {
    vscf_hmac_t *hmac = vscf_hmac_new();
    zend_resource *hmac_res = zend_register_resource(hmac, le_vscf_hmac_t);
    RETVAL_RES(hmac_res);
}

//
// Wrap method: vscf_hmac_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hmac_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_hmac_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    //
    // Call main function
    //
    int alg_id =vscf_hmac_alg_id(hmac);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_hmac_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_hmac_produce_alg_info(hmac);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_hmac_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_hmac_restore_alg_info(hmac, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_hmac_digest_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_digest_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_digest_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    //
    // Call main function
    //
    size_t res =vscf_hmac_digest_len(hmac);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_hmac_mac
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_mac_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_mac_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'mac'
    //
    zend_string *out_mac = zend_string_alloc(vscf_hmac_digest_len(hmac), 0);
    vsc_buffer_t *mac = vsc_buffer_new();
    vsc_buffer_use(mac, (byte *)ZSTR_VAL(out_mac), ZSTR_LEN(out_mac));

    //
    // Call main function
    //
    vscf_hmac_mac(hmac, key, data, mac);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_mac) = vsc_buffer_len(mac);

    //
    // Write returned result
    //
    RETVAL_STR(out_mac);
}

//
// Wrap method: vscf_hmac_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_start_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_start_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key = NULL;
    size_t in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key, in_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    vsc_data_t key = vsc_data((const byte*)in_key, in_key_len);

    //
    // Call main function
    //
    vscf_hmac_start(hmac, key);


}

//
// Wrap method: vscf_hmac_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_update_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_update_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    vscf_hmac_update(hmac, data);


}

//
// Wrap method: vscf_hmac_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_finish_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_finish_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    //
    // Allocate output buffer for output 'mac'
    //
    zend_string *out_mac = zend_string_alloc(vscf_hmac_digest_len(hmac), 0);
    vsc_buffer_t *mac = vsc_buffer_new();
    vsc_buffer_use(mac, (byte *)ZSTR_VAL(out_mac), ZSTR_LEN(out_mac));

    //
    // Call main function
    //
    vscf_hmac_finish(hmac, mac);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_mac) = vsc_buffer_len(mac);

    //
    // Write returned result
    //
    RETVAL_STR(out_mac);
}

//
// Wrap method: vscf_hmac_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hmac_reset_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hmac_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hmac_t *hmac = zend_fetch_resource_ex(in_ctx, VSCF_HMAC_PHP_RES_NAME, le_vscf_hmac_t);
    VSCF_ASSERT_PTR(hmac);

    //
    // Call main function
    //
    vscf_hmac_reset(hmac);


}

//
// Wrap method: vscf_hkdf_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hkdf_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_new_php) {
    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    zend_resource *hkdf_res = zend_register_resource(hkdf, le_vscf_hkdf_t);
    RETVAL_RES(hkdf_res);
}

//
// Wrap method: vscf_hkdf_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hkdf_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_hkdf_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    //
    // Call main function
    //
    int alg_id =vscf_hkdf_alg_id(hkdf);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_hkdf_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_hkdf_produce_alg_info(hkdf);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_hkdf_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_hkdf_restore_alg_info(hkdf, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_hkdf_derive
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_derive_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_derive_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    zend_long in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_key_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    size_t key_len = in_key_len;

    //
    // Allocate output buffer for output 'key'
    //
    zend_string *out_key = zend_string_alloc(key_len, 0);
    vsc_buffer_t *key = vsc_buffer_new();
    vsc_buffer_use(key, (byte *)ZSTR_VAL(out_key), ZSTR_LEN(out_key));

    //
    // Call main function
    //
    vscf_hkdf_derive(hkdf, data, key_len, key);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_key) = vsc_buffer_len(key);

    //
    // Write returned result
    //
    RETVAL_STR(out_key);
}

//
// Wrap method: vscf_hkdf_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_reset_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_salt, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_iteration_count, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_salt = NULL;
    size_t in_salt_len = 0;
    zend_long in_iteration_count = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_salt, in_salt_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_iteration_count)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    vsc_data_t salt = vsc_data((const byte*)in_salt, in_salt_len);
    size_t iteration_count = in_iteration_count;

    //
    // Call main function
    //
    vscf_hkdf_reset(hkdf, salt, iteration_count);


}

//
// Wrap method: vscf_hkdf_set_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hkdf_set_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_info, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hkdf_set_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_info = NULL;
    size_t in_info_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_info, in_info_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hkdf_t *hkdf = zend_fetch_resource_ex(in_ctx, VSCF_HKDF_PHP_RES_NAME, le_vscf_hkdf_t);
    VSCF_ASSERT_PTR(hkdf);

    vsc_data_t info = vsc_data((const byte*)in_info, in_info_len);

    //
    // Call main function
    //
    vscf_hkdf_set_info(hkdf, info);


}

//
// Wrap method: vscf_kdf1_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_new_php) {
    vscf_kdf1_t *kdf1 = vscf_kdf1_new();
    zend_resource *kdf1_res = zend_register_resource(kdf1, le_vscf_kdf1_t);
    RETVAL_RES(kdf1_res);
}

//
// Wrap method: vscf_kdf1_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_ctx, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(kdf1);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_kdf1_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf1_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_ctx, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(kdf1);

    //
    // Call main function
    //
    int alg_id =vscf_kdf1_alg_id(kdf1);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_kdf1_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf1_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_ctx, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(kdf1);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_kdf1_produce_alg_info(kdf1);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_kdf1_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf1_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_ctx, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(kdf1);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_kdf1_restore_alg_info(kdf1, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_kdf1_derive
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf1_derive_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf1_derive_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    zend_long in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_key_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_ctx, VSCF_KDF1_PHP_RES_NAME, le_vscf_kdf1_t);
    VSCF_ASSERT_PTR(kdf1);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    size_t key_len = in_key_len;

    //
    // Allocate output buffer for output 'key'
    //
    zend_string *out_key = zend_string_alloc(key_len, 0);
    vsc_buffer_t *key = vsc_buffer_new();
    vsc_buffer_use(key, (byte *)ZSTR_VAL(out_key), ZSTR_LEN(out_key));

    //
    // Call main function
    //
    vscf_kdf1_derive(kdf1, data, key_len, key);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_key) = vsc_buffer_len(key);

    //
    // Write returned result
    //
    RETVAL_STR(out_key);
}

//
// Wrap method: vscf_kdf2_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf2_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_new_php) {
    vscf_kdf2_t *kdf2 = vscf_kdf2_new();
    zend_resource *kdf2_res = zend_register_resource(kdf2, le_vscf_kdf2_t);
    RETVAL_RES(kdf2_res);
}

//
// Wrap method: vscf_kdf2_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf2_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_kdf2_t *kdf2 = zend_fetch_resource_ex(in_ctx, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(kdf2);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_kdf2_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf2_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf2_t *kdf2 = zend_fetch_resource_ex(in_ctx, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(kdf2);

    //
    // Call main function
    //
    int alg_id =vscf_kdf2_alg_id(kdf2);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_kdf2_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf2_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf2_t *kdf2 = zend_fetch_resource_ex(in_ctx, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(kdf2);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_kdf2_produce_alg_info(kdf2);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_kdf2_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf2_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf2_t *kdf2 = zend_fetch_resource_ex(in_ctx, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(kdf2);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_kdf2_restore_alg_info(kdf2, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_kdf2_derive
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_kdf2_derive_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_kdf2_derive_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    zend_long in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_key_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_kdf2_t *kdf2 = zend_fetch_resource_ex(in_ctx, VSCF_KDF2_PHP_RES_NAME, le_vscf_kdf2_t);
    VSCF_ASSERT_PTR(kdf2);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    size_t key_len = in_key_len;

    //
    // Allocate output buffer for output 'key'
    //
    zend_string *out_key = zend_string_alloc(key_len, 0);
    vsc_buffer_t *key = vsc_buffer_new();
    vsc_buffer_use(key, (byte *)ZSTR_VAL(out_key), ZSTR_LEN(out_key));

    //
    // Call main function
    //
    vscf_kdf2_derive(kdf2, data, key_len, key);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_key) = vsc_buffer_len(key);

    //
    // Write returned result
    //
    RETVAL_STR(out_key);
}

//
// Wrap method: vscf_fake_random_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_fake_random_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_new_php) {
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    zend_resource *fake_random_res = zend_register_resource(fake_random, le_vscf_fake_random_t);
    RETVAL_RES(fake_random_res);
}

//
// Wrap method: vscf_fake_random_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_fake_random_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_fake_random_setup_source_byte
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_setup_source_byte_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_byte_source, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_setup_source_byte_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_byte_source = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_byte_source)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    byte byte_source = in_byte_source;//
    // Call main function
    //
    vscf_fake_random_setup_source_byte(fake_random, byte_source);


}

//
// Wrap method: vscf_fake_random_setup_source_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_setup_source_data_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_source, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_setup_source_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data_source = NULL;
    size_t in_data_source_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data_source, in_data_source_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    vsc_data_t data_source = vsc_data((const byte*)in_data_source, in_data_source_len);

    //
    // Call main function
    //
    vscf_fake_random_setup_source_data(fake_random, data_source);


}

//
// Wrap method: vscf_fake_random_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    size_t data_len = in_data_len;

    //
    // Allocate output buffer for output 'data'
    //
    zend_string *out_data = zend_string_alloc(data_len, 0);
    vsc_buffer_t *data = vsc_buffer_new();
    vsc_buffer_use(data, (byte *)ZSTR_VAL(out_data), ZSTR_LEN(out_data));

    //
    // Call main function
    //
    vscf_status_t status =vscf_fake_random_random(fake_random, data_len, data);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_data) = vsc_buffer_len(data);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);

    goto success;

fail:
    zend_string_free(out_data);
success:
    vsc_buffer_destroy(&data);
}

//
// Wrap method: vscf_fake_random_reseed
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_reseed_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_reseed_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    //
    // Call main function
    //
    vscf_status_t status =vscf_fake_random_reseed(fake_random);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_fake_random_is_strong
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_is_strong_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_is_strong_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    //
    // Call main function
    //
    zend_bool res =vscf_fake_random_is_strong(fake_random);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_fake_random_gather
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_fake_random_gather_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_fake_random_gather_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_fake_random_t *fake_random = zend_fetch_resource_ex(in_ctx, VSCF_FAKE_RANDOM_PHP_RES_NAME, le_vscf_fake_random_t);
    VSCF_ASSERT_PTR(fake_random);

    size_t len = in_len;

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(len, 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_fake_random_gather(fake_random, len, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_pkcs5_pbkdf2_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs5_pbkdf2_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_new_php) {
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = vscf_pkcs5_pbkdf2_new();
    zend_resource *pkcs5_pbkdf2_res = zend_register_resource(pkcs5_pbkdf2, le_vscf_pkcs5_pbkdf2_t);
    RETVAL_RES(pkcs5_pbkdf2_res);
}

//
// Wrap method: vscf_pkcs5_pbkdf2_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs5_pbkdf2_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_pkcs5_pbkdf2_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    //
    // Call main function
    //
    vscf_pkcs5_pbkdf2_setup_defaults(pkcs5_pbkdf2);


}

//
// Wrap method: vscf_pkcs5_pbkdf2_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    //
    // Call main function
    //
    int alg_id =vscf_pkcs5_pbkdf2_alg_id(pkcs5_pbkdf2);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_pkcs5_pbkdf2_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_pkcs5_pbkdf2_produce_alg_info(pkcs5_pbkdf2);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_pkcs5_pbkdf2_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs5_pbkdf2_restore_alg_info(pkcs5_pbkdf2, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_pkcs5_pbkdf2_derive
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_derive_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_derive_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    zend_long in_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_key_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    size_t key_len = in_key_len;

    //
    // Allocate output buffer for output 'key'
    //
    zend_string *out_key = zend_string_alloc(key_len, 0);
    vsc_buffer_t *key = vsc_buffer_new();
    vsc_buffer_use(key, (byte *)ZSTR_VAL(out_key), ZSTR_LEN(out_key));

    //
    // Call main function
    //
    vscf_pkcs5_pbkdf2_derive(pkcs5_pbkdf2, data, key_len, key);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_key) = vsc_buffer_len(key);

    //
    // Write returned result
    //
    RETVAL_STR(out_key);
}

//
// Wrap method: vscf_pkcs5_pbkdf2_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_reset_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_salt, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_iteration_count, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_salt = NULL;
    size_t in_salt_len = 0;
    zend_long in_iteration_count = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_salt, in_salt_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_iteration_count)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vsc_data_t salt = vsc_data((const byte*)in_salt, in_salt_len);
    size_t iteration_count = in_iteration_count;

    //
    // Call main function
    //
    vscf_pkcs5_pbkdf2_reset(pkcs5_pbkdf2, salt, iteration_count);


}

//
// Wrap method: vscf_pkcs5_pbkdf2_set_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbkdf2_set_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_info, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbkdf2_set_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_info = NULL;
    size_t in_info_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_info, in_info_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, le_vscf_pkcs5_pbkdf2_t);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vsc_data_t info = vsc_data((const byte*)in_info, in_info_len);

    //
    // Call main function
    //
    vscf_pkcs5_pbkdf2_set_info(pkcs5_pbkdf2, info);


}

//
// Wrap method: vscf_pkcs5_pbes2_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs5_pbes2_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_new_php) {
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = vscf_pkcs5_pbes2_new();
    zend_resource *pkcs5_pbes2_res = zend_register_resource(pkcs5_pbes2, le_vscf_pkcs5_pbes2_t);
    RETVAL_RES(pkcs5_pbes2_res);
}

//
// Wrap method: vscf_pkcs5_pbes2_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs5_pbes2_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_pkcs5_pbes2_reset
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_reset_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_pwd, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_reset_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_pwd = NULL;
    size_t in_pwd_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_pwd, in_pwd_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vsc_data_t pwd = vsc_data((const byte*)in_pwd, in_pwd_len);

    //
    // Call main function
    //
    vscf_pkcs5_pbes2_reset(pkcs5_pbes2, pwd);


}

//
// Wrap method: vscf_pkcs5_pbes2_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    //
    // Call main function
    //
    int alg_id =vscf_pkcs5_pbes2_alg_id(pkcs5_pbes2);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_pkcs5_pbes2_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_pkcs5_pbes2_produce_alg_info(pkcs5_pbes2);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_pkcs5_pbes2_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs5_pbes2_restore_alg_info(pkcs5_pbes2, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_pkcs5_pbes2_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_encrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs5_pbes2_encrypt(pkcs5_pbes2, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_pkcs5_pbes2_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs5_pbes2_precise_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_precise_encrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_precise_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_pkcs5_pbes2_precise_encrypted_len(pkcs5_pbes2, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs5_pbes2_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_decrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs5_pbes2_decrypt(pkcs5_pbes2, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_pkcs5_pbes2_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs5_pbes2_decrypted_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs5_pbes2_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs5_pbes2_t *pkcs5_pbes2 = zend_fetch_resource_ex(in_ctx, VSCF_PKCS5_PBES2_PHP_RES_NAME, le_vscf_pkcs5_pbes2_t);
    VSCF_ASSERT_PTR(pkcs5_pbes2);

    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_seed_entropy_source_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_seed_entropy_source_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_seed_entropy_source_new_php) {
    vscf_seed_entropy_source_t *seed_entropy_source = vscf_seed_entropy_source_new();
    zend_resource *seed_entropy_source_res = zend_register_resource(seed_entropy_source, le_vscf_seed_entropy_source_t);
    RETVAL_RES(seed_entropy_source_res);
}

//
// Wrap method: vscf_seed_entropy_source_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_seed_entropy_source_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_seed_entropy_source_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_seed_entropy_source_t *seed_entropy_source = zend_fetch_resource_ex(in_ctx, VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME, le_vscf_seed_entropy_source_t);
    VSCF_ASSERT_PTR(seed_entropy_source);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_seed_entropy_source_reset_seed
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_seed_entropy_source_reset_seed_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_seed, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_seed_entropy_source_reset_seed_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_seed = NULL;
    size_t in_seed_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_seed, in_seed_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_seed_entropy_source_t *seed_entropy_source = zend_fetch_resource_ex(in_ctx, VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME, le_vscf_seed_entropy_source_t);
    VSCF_ASSERT_PTR(seed_entropy_source);

    vsc_data_t seed = vsc_data((const byte*)in_seed, in_seed_len);

    //
    // Call main function
    //
    vscf_seed_entropy_source_reset_seed(seed_entropy_source, seed);


}

//
// Wrap method: vscf_seed_entropy_source_is_strong
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_seed_entropy_source_is_strong_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_seed_entropy_source_is_strong_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_seed_entropy_source_t *seed_entropy_source = zend_fetch_resource_ex(in_ctx, VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME, le_vscf_seed_entropy_source_t);
    VSCF_ASSERT_PTR(seed_entropy_source);

    //
    // Call main function
    //
    zend_bool res =vscf_seed_entropy_source_is_strong(seed_entropy_source);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_seed_entropy_source_gather
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_seed_entropy_source_gather_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_seed_entropy_source_gather_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_seed_entropy_source_t *seed_entropy_source = zend_fetch_resource_ex(in_ctx, VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME, le_vscf_seed_entropy_source_t);
    VSCF_ASSERT_PTR(seed_entropy_source);

    size_t len = in_len;

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(len, 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_seed_entropy_source_gather(seed_entropy_source, len, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_key_material_rng_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_material_rng_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_material_rng_new_php) {
    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    zend_resource *key_material_rng_res = zend_register_resource(key_material_rng, le_vscf_key_material_rng_t);
    RETVAL_RES(key_material_rng_res);
}

//
// Wrap method: vscf_key_material_rng_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_material_rng_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_material_rng_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_material_rng_t *key_material_rng = zend_fetch_resource_ex(in_ctx, VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME, le_vscf_key_material_rng_t);
    VSCF_ASSERT_PTR(key_material_rng);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_material_rng_reset_key_material
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_material_rng_reset_key_material_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key_material, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_material_rng_reset_key_material_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_key_material = NULL;
    size_t in_key_material_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_key_material, in_key_material_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_material_rng_t *key_material_rng = zend_fetch_resource_ex(in_ctx, VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME, le_vscf_key_material_rng_t);
    VSCF_ASSERT_PTR(key_material_rng);

    vsc_data_t key_material = vsc_data((const byte*)in_key_material, in_key_material_len);

    //
    // Call main function
    //
    vscf_key_material_rng_reset_key_material(key_material_rng, key_material);


}

//
// Wrap method: vscf_key_material_rng_random
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_material_rng_random_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_material_rng_random_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_material_rng_t *key_material_rng = zend_fetch_resource_ex(in_ctx, VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME, le_vscf_key_material_rng_t);
    VSCF_ASSERT_PTR(key_material_rng);

    size_t data_len = in_data_len;

    //
    // Allocate output buffer for output 'data'
    //
    zend_string *out_data = zend_string_alloc(data_len, 0);
    vsc_buffer_t *data = vsc_buffer_new();
    vsc_buffer_use(data, (byte *)ZSTR_VAL(out_data), ZSTR_LEN(out_data));

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_material_rng_random(key_material_rng, data_len, data);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_data) = vsc_buffer_len(data);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);

    goto success;

fail:
    zend_string_free(out_data);
success:
    vsc_buffer_destroy(&data);
}

//
// Wrap method: vscf_key_material_rng_reseed
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_material_rng_reseed_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_material_rng_reseed_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_material_rng_t *key_material_rng = zend_fetch_resource_ex(in_ctx, VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME, le_vscf_key_material_rng_t);
    VSCF_ASSERT_PTR(key_material_rng);

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_material_rng_reseed(key_material_rng);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_raw_public_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_raw_public_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_new_php) {
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new();
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_raw_public_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_raw_public_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_raw_public_key_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_data_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_raw_public_key_data(raw_public_key);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_raw_public_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    int alg_id =vscf_raw_public_key_alg_id(raw_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_raw_public_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_raw_public_key_alg_info(raw_public_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_raw_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    size_t res =vscf_raw_public_key_len(raw_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_raw_public_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    size_t res =vscf_raw_public_key_bitlen(raw_public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_raw_public_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_public_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_public_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, le_vscf_raw_public_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_raw_public_key_is_valid(raw_public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_raw_private_key_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_raw_private_key_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_new_php) {
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new();
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_raw_private_key_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_raw_private_key_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_raw_private_key_data
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_data_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_data_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_raw_private_key_data(raw_private_key);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_raw_private_key_has_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_has_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_has_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_raw_private_key_has_public_key(raw_private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_raw_private_key_set_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_set_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_set_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    vscf_raw_public_key_t *raw_public_key = zend_fetch_resource_ex(in_raw_public_key, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_public_key);

    vscf_raw_public_key_t *raw_public_key_tmp = vscf_raw_public_key_shallow_copy(raw_public_key);//
    // Call main function
    //
    vscf_raw_private_key_set_public_key(raw_private_key, raw_public_key);


}

//
// Wrap method: vscf_raw_private_key_get_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_get_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_get_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =(vscf_raw_public_key_t *)vscf_raw_private_key_get_public_key(raw_private_key);
    raw_public_key = vscf_raw_public_key_shallow_copy(raw_public_key);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_raw_private_key_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    int alg_id =vscf_raw_private_key_alg_id(raw_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_raw_private_key_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_raw_private_key_alg_info(raw_private_key);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_raw_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    size_t res =vscf_raw_private_key_len(raw_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_raw_private_key_bitlen
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_bitlen_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_bitlen_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    size_t res =vscf_raw_private_key_bitlen(raw_private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_raw_private_key_is_valid
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_is_valid_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_is_valid_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_raw_private_key_is_valid(raw_private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_raw_private_key_extract_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_raw_private_key_extract_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_raw_private_key_extract_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_raw_private_key_t *raw_private_key = zend_fetch_resource_ex(in_ctx, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, le_vscf_raw_private_key_t);
    VSCF_ASSERT_PTR(raw_private_key);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_raw_private_key_extract_public_key(raw_private_key);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_pkcs8_serializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs8_serializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_new_php) {
    vscf_pkcs8_serializer_t *pkcs8_serializer = vscf_pkcs8_serializer_new();
    zend_resource *pkcs8_serializer_res = zend_register_resource(pkcs8_serializer, le_vscf_pkcs8_serializer_t);
    RETVAL_RES(pkcs8_serializer_res);
}

//
// Wrap method: vscf_pkcs8_serializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pkcs8_serializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_pkcs8_serializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    //
    // Call main function
    //
    vscf_pkcs8_serializer_setup_defaults(pkcs8_serializer);


}

//
// Wrap method: vscf_pkcs8_serializer_serialize_public_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialize_public_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialize_public_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_pkcs8_serializer_serialize_public_key_inplace(pkcs8_serializer, public_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs8_serializer_serialize_private_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialize_private_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialize_private_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_pkcs8_serializer_serialize_private_key_inplace(pkcs8_serializer, private_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs8_serializer_serialized_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialized_public_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialized_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    size_t res =vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer, public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs8_serializer_serialize_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialize_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialize_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer, public_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs8_serializer_serialize_public_key(pkcs8_serializer, public_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_pkcs8_serializer_serialized_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialized_private_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialized_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    size_t res =vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer, private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_pkcs8_serializer_serialize_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pkcs8_serializer_serialize_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pkcs8_serializer_serialize_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pkcs8_serializer_t *pkcs8_serializer = zend_fetch_resource_ex(in_ctx, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(pkcs8_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, le_vscf_pkcs8_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer, private_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_pkcs8_serializer_serialize_private_key(pkcs8_serializer, private_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_sec1_serializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sec1_serializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_new_php) {
    vscf_sec1_serializer_t *sec1_serializer = vscf_sec1_serializer_new();
    zend_resource *sec1_serializer_res = zend_register_resource(sec1_serializer, le_vscf_sec1_serializer_t);
    RETVAL_RES(sec1_serializer_res);
}

//
// Wrap method: vscf_sec1_serializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sec1_serializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_sec1_serializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    //
    // Call main function
    //
    vscf_sec1_serializer_setup_defaults(sec1_serializer);


}

//
// Wrap method: vscf_sec1_serializer_serialize_public_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialize_public_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialize_public_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_sec1_serializer_serialize_public_key_inplace(sec1_serializer, public_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_sec1_serializer_serialize_private_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialize_private_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialize_private_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_sec1_serializer_serialize_private_key_inplace(sec1_serializer, private_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_sec1_serializer_serialized_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialized_public_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialized_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    size_t res =vscf_sec1_serializer_serialized_public_key_len(sec1_serializer, public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_sec1_serializer_serialize_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialize_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialize_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_sec1_serializer_serialized_public_key_len(sec1_serializer, public_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_sec1_serializer_serialize_public_key(sec1_serializer, public_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_sec1_serializer_serialized_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialized_private_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialized_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    size_t res =vscf_sec1_serializer_serialized_private_key_len(sec1_serializer, private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_sec1_serializer_serialize_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_sec1_serializer_serialize_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_sec1_serializer_serialize_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_sec1_serializer_t *sec1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(sec1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, le_vscf_sec1_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_sec1_serializer_serialized_private_key_len(sec1_serializer, private_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_sec1_serializer_serialize_private_key(sec1_serializer, private_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_key_asn1_serializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_serializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_new_php) {
    vscf_key_asn1_serializer_t *key_asn1_serializer = vscf_key_asn1_serializer_new();
    zend_resource *key_asn1_serializer_res = zend_register_resource(key_asn1_serializer, le_vscf_key_asn1_serializer_t);
    RETVAL_RES(key_asn1_serializer_res);
}

//
// Wrap method: vscf_key_asn1_serializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_serializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_asn1_serializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    //
    // Call main function
    //
    vscf_key_asn1_serializer_setup_defaults(key_asn1_serializer);


}

//
// Wrap method: vscf_key_asn1_serializer_serialize_public_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialize_public_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialize_public_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_key_asn1_serializer_serialize_public_key_inplace(key_asn1_serializer, public_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_asn1_serializer_serialize_private_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialize_private_key_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialize_private_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    size_t res =vscf_key_asn1_serializer_serialize_private_key_inplace(key_asn1_serializer, private_key, &error);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_asn1_serializer_serialized_public_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialized_public_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialized_public_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    size_t res =vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer, public_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_asn1_serializer_serialize_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialize_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialize_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_public_key_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer, public_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_asn1_serializer_serialize_public_key(key_asn1_serializer, public_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_key_asn1_serializer_serialized_private_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialized_private_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialized_private_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    size_t res =vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer, private_key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_key_asn1_serializer_serialize_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_serializer_serialize_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_serializer_serialize_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_serializer_t *key_asn1_serializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(key_asn1_serializer);

    vscf_raw_private_key_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_serializer_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer, private_key), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_key_asn1_serializer_serialize_private_key(key_asn1_serializer, private_key, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_key_asn1_deserializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_new_php) {
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    zend_resource *key_asn1_deserializer_res = zend_register_resource(key_asn1_deserializer, le_vscf_key_asn1_deserializer_t);
    RETVAL_RES(key_asn1_deserializer_res);
}

//
// Wrap method: vscf_key_asn1_deserializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_key_asn1_deserializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_deserializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    //
    // Call main function
    //
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);


}

//
// Wrap method: vscf_key_asn1_deserializer_deserialize_public_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_deserializer_deserialize_public_key_inplace_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_public_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_key_asn1_deserializer_deserialize_public_key_inplace(key_asn1_deserializer, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_key_asn1_deserializer_deserialize_private_key_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_deserializer_deserialize_private_key_inplace_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_private_key_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_key_asn1_deserializer_deserialize_private_key_inplace(key_asn1_deserializer, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_key_asn1_deserializer_deserialize_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_deserializer_deserialize_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_public_key_data = NULL;
    size_t in_public_key_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_public_key_data, in_public_key_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vsc_data_t public_key_data = vsc_data((const byte*)in_public_key_data, in_public_key_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_key_asn1_deserializer_deserialize_public_key(key_asn1_deserializer, public_key_data, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_key_asn1_deserializer_deserialize_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_key_asn1_deserializer_deserialize_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_private_key_data = NULL;
    size_t in_private_key_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_private_key_data, in_private_key_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer_t);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vsc_data_t private_key_data = vsc_data((const byte*)in_private_key_data, in_private_key_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_key_asn1_deserializer_deserialize_private_key(key_asn1_deserializer, private_key_data, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_ed25519_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ed25519_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_new_php) {
    vscf_ed25519_t *ed25519 = vscf_ed25519_new();
    zend_resource *ed25519_res = zend_register_resource(ed25519, le_vscf_ed25519_t);
    RETVAL_RES(ed25519_res);
}

//
// Wrap method: vscf_ed25519_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ed25519_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ed25519_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_setup_defaults(ed25519);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ed25519_generate_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_generate_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_generate_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ed25519_generate_key(ed25519, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ed25519_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    //
    // Call main function
    //
    int alg_id =vscf_ed25519_alg_id(ed25519);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_ed25519_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_ed25519_produce_alg_info(ed25519);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_ed25519_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_restore_alg_info(ed25519, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_ed25519_generate_ephemeral_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_generate_ephemeral_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_generate_ephemeral_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ed25519_generate_ephemeral_key(ed25519, key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ed25519_import_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_import_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_import_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_raw_public_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_ed25519_import_public_key(ed25519, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_ed25519_export_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_export_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_export_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_ed25519_export_public_key(ed25519, public_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_ed25519_import_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_import_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_import_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_raw_private_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_ed25519_import_private_key(ed25519, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_ed25519_export_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_export_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_export_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_ed25519_export_private_key(ed25519, private_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_ed25519_can_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_can_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_can_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_ed25519_can_encrypt(ed25519, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ed25519_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_encrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ed25519_encrypted_len(ed25519, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ed25519_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ed25519_encrypted_len(ed25519, public_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_encrypt(ed25519, public_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ed25519_can_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_can_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_can_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_ed25519_can_decrypt(ed25519, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ed25519_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_decrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_ed25519_decrypted_len(ed25519, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ed25519_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_ed25519_decrypted_len(ed25519, private_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_decrypt(ed25519, private_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_ed25519_can_sign
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_can_sign_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_can_sign_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ed25519_can_sign(ed25519, private_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ed25519_signature_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_signature_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_signature_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_ed25519_signature_len(ed25519, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_ed25519_sign_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_sign_hash_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_sign_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);

    //
    // Allocate output buffer for output 'signature'
    //
    zend_string *out_signature = zend_string_alloc(vscf_ed25519_signature_len(ed25519, private_key), 0);
    vsc_buffer_t *signature = vsc_buffer_new();
    vsc_buffer_use(signature, (byte *)ZSTR_VAL(out_signature), ZSTR_LEN(out_signature));

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_sign_hash(ed25519, private_key, hash_id, digest, signature);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_signature) = vsc_buffer_len(signature);

    //
    // Write returned result
    //
    RETVAL_STR(out_signature);

    goto success;

fail:
    zend_string_free(out_signature);
success:
    vsc_buffer_destroy(&signature);
}

//
// Wrap method: vscf_ed25519_can_verify
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_can_verify_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_can_verify_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);

    //
    // Call main function
    //
    zend_bool res =vscf_ed25519_can_verify(ed25519, public_key);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ed25519_verify_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_verify_hash_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_hash_id, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, in_digest, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_signature, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_verify_hash_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_hash_id = 0;
    char *in_digest = NULL;
    size_t in_digest_len = 0;
    char *in_signature = NULL;
    size_t in_signature_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_hash_id)
        Z_PARAM_STRING_EX(in_digest, in_digest_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_signature, in_signature_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t digest = vsc_data((const byte*)in_digest, in_digest_len);
    vsc_data_t signature = vsc_data((const byte*)in_signature, in_signature_len);

    vscf_alg_id_t hash_id = (vscf_alg_id_t)in_hash_id;//
    // Call main function
    //
    zend_bool res =vscf_ed25519_verify_hash(ed25519, public_key, hash_id, digest, signature);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_ed25519_compute_shared_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_compute_shared_key_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_compute_shared_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'shared_key'
    //
    zend_string *out_shared_key = zend_string_alloc(vscf_ed25519_shared_key_len(ed25519, private_key), 0);
    vsc_buffer_t *shared_key = vsc_buffer_new();
    vsc_buffer_use(shared_key, (byte *)ZSTR_VAL(out_shared_key), ZSTR_LEN(out_shared_key));

    //
    // Call main function
    //
    vscf_status_t status =vscf_ed25519_compute_shared_key(ed25519, public_key, private_key, shared_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_shared_key) = vsc_buffer_len(shared_key);

    //
    // Write returned result
    //
    RETVAL_STR(out_shared_key);

    goto success;

fail:
    zend_string_free(out_shared_key);
success:
    vsc_buffer_destroy(&shared_key);
}

//
// Wrap method: vscf_ed25519_shared_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ed25519_shared_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ed25519_shared_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ed25519_t *ed25519 = zend_fetch_resource_ex(in_ctx, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(ed25519);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_ED25519_PHP_RES_NAME, le_vscf_ed25519_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_ed25519_shared_key_len(ed25519, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_curve25519_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_curve25519_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_new_php) {
    vscf_curve25519_t *curve25519 = vscf_curve25519_new();
    zend_resource *curve25519_res = zend_register_resource(curve25519, le_vscf_curve25519_t);
    RETVAL_RES(curve25519_res);
}

//
// Wrap method: vscf_curve25519_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_curve25519_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_curve25519_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    //
    // Call main function
    //
    vscf_status_t status =vscf_curve25519_setup_defaults(curve25519);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_curve25519_generate_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_generate_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_generate_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_curve25519_generate_key(curve25519, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_curve25519_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    //
    // Call main function
    //
    int alg_id =vscf_curve25519_alg_id(curve25519);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_curve25519_produce_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_produce_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_produce_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_curve25519_produce_alg_info(curve25519);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_curve25519_restore_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_restore_alg_info_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_restore_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    vscf_status_t status =vscf_curve25519_restore_alg_info(curve25519, alg_info);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);



    goto success;

fail:
    RETURN_FALSE;
success:
    RETURN_TRUE;
}

//
// Wrap method: vscf_curve25519_generate_ephemeral_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_generate_ephemeral_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_generate_ephemeral_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_curve25519_generate_ephemeral_key(curve25519, key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_curve25519_import_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_import_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_import_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_raw_public_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *public_key =vscf_curve25519_import_public_key(curve25519, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *public_key_res = zend_register_resource(public_key, le_vscf_impl_t);
    RETVAL_RES(public_key_res);
}

//
// Wrap method: vscf_curve25519_export_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_export_public_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_export_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_public_key_t *raw_public_key =vscf_curve25519_export_public_key(curve25519, public_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_public_key_res = zend_register_resource(raw_public_key, le_vscf_raw_public_key_t);
    RETVAL_RES(raw_public_key_res);
}

//
// Wrap method: vscf_curve25519_import_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_import_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_raw_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_import_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_raw_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_raw_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_raw_private_key_t *raw_key = zend_fetch_resource_ex(in_raw_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(raw_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *private_key =vscf_curve25519_import_private_key(curve25519, raw_key, &error);

    //
    // Write returned result
    //
    zend_resource *private_key_res = zend_register_resource(private_key, le_vscf_impl_t);
    RETVAL_RES(private_key_res);
}

//
// Wrap method: vscf_curve25519_export_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_export_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_export_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(private_key);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_raw_private_key_t *raw_private_key =vscf_curve25519_export_private_key(curve25519, private_key, &error);

    //
    // Write returned result
    //
    zend_resource *raw_private_key_res = zend_register_resource(raw_private_key, le_vscf_raw_private_key_t);
    RETVAL_RES(raw_private_key_res);
}

//
// Wrap method: vscf_curve25519_can_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_can_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_can_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_curve25519_can_encrypt(curve25519, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_curve25519_encrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_encrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_encrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(public_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_curve25519_encrypted_len(curve25519, public_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_curve25519_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_encrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(public_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_curve25519_encrypted_len(curve25519, public_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_curve25519_encrypt(curve25519, public_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_curve25519_can_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_can_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_can_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    zend_bool res =vscf_curve25519_can_decrypt(curve25519, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscf_curve25519_decrypted_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_decrypted_len_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data_len, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_decrypted_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    zend_long in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_LONG(in_data_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(private_key);
    size_t data_len = in_data_len;

    //
    // Call main function
    //
    size_t res =vscf_curve25519_decrypted_len(curve25519, private_key, data_len);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_curve25519_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_private_key = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(private_key);
    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_curve25519_decrypted_len(curve25519, private_key, data.len), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_status_t status =vscf_curve25519_decrypt(curve25519, private_key, data, out);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);

    goto success;

fail:
    zend_string_free(out_out);
success:
    vsc_buffer_destroy(&out);
}

//
// Wrap method: vscf_curve25519_compute_shared_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_compute_shared_key_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_private_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_compute_shared_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_public_key = NULL;
    zval *in_private_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_public_key, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_private_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *public_key = zend_fetch_resource_ex(in_public_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(public_key);
    vscf_impl_t *private_key = zend_fetch_resource_ex(in_private_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(private_key);

    //
    // Allocate output buffer for output 'shared_key'
    //
    zend_string *out_shared_key = zend_string_alloc(vscf_curve25519_shared_key_len(curve25519, private_key), 0);
    vsc_buffer_t *shared_key = vsc_buffer_new();
    vsc_buffer_use(shared_key, (byte *)ZSTR_VAL(out_shared_key), ZSTR_LEN(out_shared_key));

    //
    // Call main function
    //
    vscf_status_t status =vscf_curve25519_compute_shared_key(curve25519, public_key, private_key, shared_key);

    //
    // Handle error
    //
    VSCF_HANDLE_STATUS (status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_shared_key) = vsc_buffer_len(shared_key);

    //
    // Write returned result
    //
    RETVAL_STR(out_shared_key);

    goto success;

fail:
    zend_string_free(out_shared_key);
success:
    vsc_buffer_destroy(&shared_key);
}

//
// Wrap method: vscf_curve25519_shared_key_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_curve25519_shared_key_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_key, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_curve25519_shared_key_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_key = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_key, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_curve25519_t *curve25519 = zend_fetch_resource_ex(in_ctx, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(curve25519);

    vscf_impl_t *key = zend_fetch_resource_ex(in_key, VSCF_CURVE25519_PHP_RES_NAME, le_vscf_curve25519_t);
    VSCF_ASSERT_PTR(key);

    //
    // Call main function
    //
    size_t res =vscf_curve25519_shared_key_len(curve25519, key);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_simple_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_simple_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_simple_alg_info_new_php) {
    vscf_simple_alg_info_t *simple_alg_info = vscf_simple_alg_info_new();
    zend_resource *simple_alg_info_res = zend_register_resource(simple_alg_info, le_vscf_simple_alg_info_t);
    RETVAL_RES(simple_alg_info_res);
}

//
// Wrap method: vscf_simple_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_simple_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_simple_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_simple_alg_info_t *simple_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SIMPLE_ALG_INFO_PHP_RES_NAME, le_vscf_simple_alg_info_t);
    VSCF_ASSERT_PTR(simple_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_simple_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_simple_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_simple_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_simple_alg_info_t *simple_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SIMPLE_ALG_INFO_PHP_RES_NAME, le_vscf_simple_alg_info_t);
    VSCF_ASSERT_PTR(simple_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_simple_alg_info_alg_id(simple_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_hash_based_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hash_based_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hash_based_alg_info_new_php) {
    vscf_hash_based_alg_info_t *hash_based_alg_info = vscf_hash_based_alg_info_new();
    zend_resource *hash_based_alg_info_res = zend_register_resource(hash_based_alg_info, le_vscf_hash_based_alg_info_t);
    RETVAL_RES(hash_based_alg_info_res);
}

//
// Wrap method: vscf_hash_based_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_hash_based_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hash_based_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_hash_based_alg_info_t *hash_based_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_HASH_BASED_ALG_INFO_PHP_RES_NAME, le_vscf_hash_based_alg_info_t);
    VSCF_ASSERT_PTR(hash_based_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_hash_based_alg_info_hash_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hash_based_alg_info_hash_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hash_based_alg_info_hash_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hash_based_alg_info_t *hash_based_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_HASH_BASED_ALG_INFO_PHP_RES_NAME, le_vscf_hash_based_alg_info_t);
    VSCF_ASSERT_PTR(hash_based_alg_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_hash_based_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_hash_based_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_hash_based_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_hash_based_alg_info_t *hash_based_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_HASH_BASED_ALG_INFO_PHP_RES_NAME, le_vscf_hash_based_alg_info_t);
    VSCF_ASSERT_PTR(hash_based_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_hash_based_alg_info_alg_id(hash_based_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_cipher_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_cipher_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_cipher_alg_info_new_php) {
    vscf_cipher_alg_info_t *cipher_alg_info = vscf_cipher_alg_info_new();
    zend_resource *cipher_alg_info_res = zend_register_resource(cipher_alg_info, le_vscf_cipher_alg_info_t);
    RETVAL_RES(cipher_alg_info_res);
}

//
// Wrap method: vscf_cipher_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_cipher_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_cipher_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_cipher_alg_info_t *cipher_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_CIPHER_ALG_INFO_PHP_RES_NAME, le_vscf_cipher_alg_info_t);
    VSCF_ASSERT_PTR(cipher_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_cipher_alg_info_nonce
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_cipher_alg_info_nonce_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_cipher_alg_info_nonce_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_cipher_alg_info_t *cipher_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_CIPHER_ALG_INFO_PHP_RES_NAME, le_vscf_cipher_alg_info_t);
    VSCF_ASSERT_PTR(cipher_alg_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_cipher_alg_info_nonce(cipher_alg_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_cipher_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_cipher_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_cipher_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_cipher_alg_info_t *cipher_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_CIPHER_ALG_INFO_PHP_RES_NAME, le_vscf_cipher_alg_info_t);
    VSCF_ASSERT_PTR(cipher_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_cipher_alg_info_alg_id(cipher_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_salted_kdf_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_salted_kdf_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_new_php) {
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = vscf_salted_kdf_alg_info_new();
    zend_resource *salted_kdf_alg_info_res = zend_register_resource(salted_kdf_alg_info, le_vscf_salted_kdf_alg_info_t);
    RETVAL_RES(salted_kdf_alg_info_res);
}

//
// Wrap method: vscf_salted_kdf_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_salted_kdf_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, le_vscf_salted_kdf_alg_info_t);
    VSCF_ASSERT_PTR(salted_kdf_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_salted_kdf_alg_info_hash_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_salted_kdf_alg_info_hash_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_hash_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, le_vscf_salted_kdf_alg_info_t);
    VSCF_ASSERT_PTR(salted_kdf_alg_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_salted_kdf_alg_info_salt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_salted_kdf_alg_info_salt_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_salt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, le_vscf_salted_kdf_alg_info_t);
    VSCF_ASSERT_PTR(salted_kdf_alg_info);

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscf_salted_kdf_alg_info_iteration_count
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_salted_kdf_alg_info_iteration_count_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_iteration_count_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, le_vscf_salted_kdf_alg_info_t);
    VSCF_ASSERT_PTR(salted_kdf_alg_info);

    //
    // Call main function
    //
    size_t res =vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_salted_kdf_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_salted_kdf_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_salted_kdf_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, le_vscf_salted_kdf_alg_info_t);
    VSCF_ASSERT_PTR(salted_kdf_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_salted_kdf_alg_info_alg_id(salted_kdf_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_pbe_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pbe_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pbe_alg_info_new_php) {
    vscf_pbe_alg_info_t *pbe_alg_info = vscf_pbe_alg_info_new();
    zend_resource *pbe_alg_info_res = zend_register_resource(pbe_alg_info, le_vscf_pbe_alg_info_t);
    RETVAL_RES(pbe_alg_info_res);
}

//
// Wrap method: vscf_pbe_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_pbe_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pbe_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_pbe_alg_info_t *pbe_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_PBE_ALG_INFO_PHP_RES_NAME, le_vscf_pbe_alg_info_t);
    VSCF_ASSERT_PTR(pbe_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_pbe_alg_info_kdf_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pbe_alg_info_kdf_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pbe_alg_info_kdf_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pbe_alg_info_t *pbe_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_PBE_ALG_INFO_PHP_RES_NAME, le_vscf_pbe_alg_info_t);
    VSCF_ASSERT_PTR(pbe_alg_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_pbe_alg_info_cipher_alg_info
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pbe_alg_info_cipher_alg_info_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pbe_alg_info_cipher_alg_info_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pbe_alg_info_t *pbe_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_PBE_ALG_INFO_PHP_RES_NAME, le_vscf_pbe_alg_info_t);
    VSCF_ASSERT_PTR(pbe_alg_info);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =(vscf_impl_t *)vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info);
    alg_info = vscf_impl_shallow_copy(alg_info);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_pbe_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_pbe_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_pbe_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_pbe_alg_info_t *pbe_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_PBE_ALG_INFO_PHP_RES_NAME, le_vscf_pbe_alg_info_t);
    VSCF_ASSERT_PTR(pbe_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_pbe_alg_info_alg_id(pbe_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_ecc_alg_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_alg_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_info_new_php) {
    vscf_ecc_alg_info_t *ecc_alg_info = vscf_ecc_alg_info_new();
    zend_resource *ecc_alg_info_res = zend_register_resource(ecc_alg_info, le_vscf_ecc_alg_info_t);
    RETVAL_RES(ecc_alg_info_res);
}

//
// Wrap method: vscf_ecc_alg_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_ecc_alg_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_ecc_alg_info_t *ecc_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_ECC_ALG_INFO_PHP_RES_NAME, le_vscf_ecc_alg_info_t);
    VSCF_ASSERT_PTR(ecc_alg_info);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_ecc_alg_info_key_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_alg_info_key_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_info_key_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_alg_info_t *ecc_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_ECC_ALG_INFO_PHP_RES_NAME, le_vscf_ecc_alg_info_t);
    VSCF_ASSERT_PTR(ecc_alg_info);

    //
    // Call main function
    //
    int oid_id =vscf_ecc_alg_info_key_id(ecc_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(oid_id);
}

//
// Wrap method: vscf_ecc_alg_info_domain_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_alg_info_domain_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_info_domain_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_alg_info_t *ecc_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_ECC_ALG_INFO_PHP_RES_NAME, le_vscf_ecc_alg_info_t);
    VSCF_ASSERT_PTR(ecc_alg_info);

    //
    // Call main function
    //
    int oid_id =vscf_ecc_alg_info_domain_id(ecc_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(oid_id);
}

//
// Wrap method: vscf_ecc_alg_info_alg_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_ecc_alg_info_alg_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_ecc_alg_info_alg_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_ecc_alg_info_t *ecc_alg_info = zend_fetch_resource_ex(in_ctx, VSCF_ECC_ALG_INFO_PHP_RES_NAME, le_vscf_ecc_alg_info_t);
    VSCF_ASSERT_PTR(ecc_alg_info);

    //
    // Call main function
    //
    int alg_id =vscf_ecc_alg_info_alg_id(ecc_alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(alg_id);
}

//
// Wrap method: vscf_alg_info_der_serializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_alg_info_der_serializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_new_php) {
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = vscf_alg_info_der_serializer_new();
    zend_resource *alg_info_der_serializer_res = zend_register_resource(alg_info_der_serializer, le_vscf_alg_info_der_serializer_t);
    RETVAL_RES(alg_info_der_serializer_res);
}

//
// Wrap method: vscf_alg_info_der_serializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_alg_info_der_serializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info_der_serializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_alg_info_der_serializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_serializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info_der_serializer);

    //
    // Call main function
    //
    vscf_alg_info_der_serializer_setup_defaults(alg_info_der_serializer);


}

//
// Wrap method: vscf_alg_info_der_serializer_serialize_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_serializer_serialize_inplace_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_serialize_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info_der_serializer);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    size_t res =vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer, alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_alg_info_der_serializer_serialized_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_serializer_serialized_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_serialized_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info_der_serializer);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Call main function
    //
    size_t res =vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer, alg_info);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_alg_info_der_serializer_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_serializer_serialize_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_alg_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_serializer_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_alg_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_alg_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info_der_serializer);

    vscf_impl_t *alg_info = zend_fetch_resource_ex(in_alg_info, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_serializer_t);
    VSCF_ASSERT_PTR(alg_info);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer, alg_info), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_alg_info_der_serializer_serialize(alg_info_der_serializer, alg_info, out);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);
}

//
// Wrap method: vscf_alg_info_der_deserializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_alg_info_der_deserializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_deserializer_new_php) {
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    zend_resource *alg_info_der_deserializer_res = zend_register_resource(alg_info_der_deserializer, le_vscf_alg_info_der_deserializer_t);
    RETVAL_RES(alg_info_der_deserializer_res);
}

//
// Wrap method: vscf_alg_info_der_deserializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_alg_info_der_deserializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_deserializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_deserializer_t);
    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_alg_info_der_deserializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_deserializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_deserializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_deserializer_t);
    VSCF_ASSERT_PTR(alg_info_der_deserializer);

    //
    // Call main function
    //
    vscf_alg_info_der_deserializer_setup_defaults(alg_info_der_deserializer);


}

//
// Wrap method: vscf_alg_info_der_deserializer_deserialize_inplace
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_deserializer_deserialize_inplace_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_deserializer_deserialize_inplace_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_deserializer_t);
    VSCF_ASSERT_PTR(alg_info_der_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer, &error);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_alg_info_der_deserializer_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_alg_info_der_deserializer_deserialize_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_alg_info_der_deserializer_deserialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = zend_fetch_resource_ex(in_ctx, VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME, le_vscf_alg_info_der_deserializer_t);
    VSCF_ASSERT_PTR(alg_info_der_deserializer);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_impl_t *alg_info =vscf_alg_info_der_deserializer_deserialize(alg_info_der_deserializer, data, &error);

    //
    // Write returned result
    //
    zend_resource *alg_info_res = zend_register_resource(alg_info, le_vscf_impl_t);
    RETVAL_RES(alg_info_res);
}

//
// Wrap method: vscf_message_info_der_serializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_der_serializer_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_new_php) {
    vscf_message_info_der_serializer_t *message_info_der_serializer = vscf_message_info_der_serializer_new();
    zend_resource *message_info_der_serializer_res = zend_register_resource(message_info_der_serializer, le_vscf_message_info_der_serializer_t);
    RETVAL_RES(message_info_der_serializer_res);
}

//
// Wrap method: vscf_message_info_der_serializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_message_info_der_serializer_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscf_message_info_der_serializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    //
    // Call main function
    //
    vscf_message_info_der_serializer_setup_defaults(message_info_der_serializer);


}

//
// Wrap method: vscf_message_info_der_serializer_serialized_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_serialized_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_serialized_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_message_info, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Call main function
    //
    size_t res =vscf_message_info_der_serializer_serialized_len(message_info_der_serializer, message_info);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_message_info_der_serializer_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_serialize_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message_info = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message_info, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_message_info_t *message_info = zend_fetch_resource_ex(in_message_info, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_message_info_der_serializer_serialized_len(message_info_der_serializer, message_info), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_message_info_der_serializer_serialize(message_info_der_serializer, message_info, out);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);
}

//
// Wrap method: vscf_message_info_der_serializer_read_prefix
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_read_prefix_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_read_prefix_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //
    // Call main function
    //
    size_t res =vscf_message_info_der_serializer_read_prefix(message_info_der_serializer, data);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_message_info_der_serializer_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_deserialize_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_deserialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_message_info_t *message_info =vscf_message_info_der_serializer_deserialize(message_info_der_serializer, data, &error);

    //
    // Write returned result
    //
    zend_resource *message_info_res = zend_register_resource(message_info, le_vscf_message_info_t);
    RETVAL_RES(message_info_res);
}

//
// Wrap method: vscf_message_info_der_serializer_serialized_footer_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_serialized_footer_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info_footer, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_serialized_footer_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message_info_footer = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message_info_footer, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_message_info_footer, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Call main function
    //
    size_t res =vscf_message_info_der_serializer_serialized_footer_len(message_info_der_serializer, message_info_footer);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscf_message_info_der_serializer_serialize_footer
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_serialize_footer_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message_info_footer, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_serialize_footer_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message_info_footer = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message_info_footer, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_message_info_footer_t *message_info_footer = zend_fetch_resource_ex(in_message_info_footer, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_footer);

    //
    // Allocate output buffer for output 'out'
    //
    zend_string *out_out = zend_string_alloc(vscf_message_info_der_serializer_serialized_footer_len(message_info_der_serializer, message_info_footer), 0);
    vsc_buffer_t *out = vsc_buffer_new();
    vsc_buffer_use(out, (byte *)ZSTR_VAL(out_out), ZSTR_LEN(out_out));

    //
    // Call main function
    //
    vscf_message_info_der_serializer_serialize_footer(message_info_der_serializer, message_info_footer, out);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_out) = vsc_buffer_len(out);

    //
    // Write returned result
    //
    RETVAL_STR(out_out);
}

//
// Wrap method: vscf_message_info_der_serializer_deserialize_footer
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscf_message_info_der_serializer_deserialize_footer_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_data, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscf_message_info_der_serializer_deserialize_footer_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscf_message_info_der_serializer_t *message_info_der_serializer = zend_fetch_resource_ex(in_ctx, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, le_vscf_message_info_der_serializer_t);
    VSCF_ASSERT_PTR(message_info_der_serializer);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Call main function
    //
    vscf_message_info_footer_t *message_info_footer =vscf_message_info_der_serializer_deserialize_footer(message_info_der_serializer, data, &error);

    //
    // Write returned result
    //
    zend_resource *message_info_footer_res = zend_register_resource(message_info_footer, le_vscf_message_info_footer_t);
    RETVAL_RES(message_info_footer_res);
}

//
// Define all function entries
//
static zend_function_entry vscf_foundation_php_functions[] = {
    PHP_FE(vscf_message_info_new_php, arginfo_vscf_message_info_new_php)
    PHP_FE(vscf_message_info_delete_php, arginfo_vscf_message_info_delete_php)
    PHP_FE(vscf_message_info_data_encryption_alg_info_php, arginfo_vscf_message_info_data_encryption_alg_info_php)
    PHP_FE(vscf_message_info_key_recipient_info_list_php, arginfo_vscf_message_info_key_recipient_info_list_php)
    PHP_FE(vscf_message_info_password_recipient_info_list_php, arginfo_vscf_message_info_password_recipient_info_list_php)
    PHP_FE(vscf_message_info_has_custom_params_php, arginfo_vscf_message_info_has_custom_params_php)
    PHP_FE(vscf_message_info_custom_params_php, arginfo_vscf_message_info_custom_params_php)
    PHP_FE(vscf_message_info_has_cipher_kdf_alg_info_php, arginfo_vscf_message_info_has_cipher_kdf_alg_info_php)
    PHP_FE(vscf_message_info_cipher_kdf_alg_info_php, arginfo_vscf_message_info_cipher_kdf_alg_info_php)
    PHP_FE(vscf_message_info_has_footer_info_php, arginfo_vscf_message_info_has_footer_info_php)
    PHP_FE(vscf_message_info_footer_info_php, arginfo_vscf_message_info_footer_info_php)
    PHP_FE(vscf_message_info_clear_php, arginfo_vscf_message_info_clear_php)
    PHP_FE(vscf_key_recipient_info_new_php, arginfo_vscf_key_recipient_info_new_php)
    PHP_FE(vscf_key_recipient_info_delete_php, arginfo_vscf_key_recipient_info_delete_php)
    PHP_FE(vscf_key_recipient_info_recipient_id_php, arginfo_vscf_key_recipient_info_recipient_id_php)
    PHP_FE(vscf_key_recipient_info_key_encryption_algorithm_php, arginfo_vscf_key_recipient_info_key_encryption_algorithm_php)
    PHP_FE(vscf_key_recipient_info_encrypted_key_php, arginfo_vscf_key_recipient_info_encrypted_key_php)
    PHP_FE(vscf_key_recipient_info_list_new_php, arginfo_vscf_key_recipient_info_list_new_php)
    PHP_FE(vscf_key_recipient_info_list_delete_php, arginfo_vscf_key_recipient_info_list_delete_php)
    PHP_FE(vscf_key_recipient_info_list_has_item_php, arginfo_vscf_key_recipient_info_list_has_item_php)
    PHP_FE(vscf_key_recipient_info_list_item_php, arginfo_vscf_key_recipient_info_list_item_php)
    PHP_FE(vscf_key_recipient_info_list_has_next_php, arginfo_vscf_key_recipient_info_list_has_next_php)
    PHP_FE(vscf_key_recipient_info_list_next_php, arginfo_vscf_key_recipient_info_list_next_php)
    PHP_FE(vscf_key_recipient_info_list_has_prev_php, arginfo_vscf_key_recipient_info_list_has_prev_php)
    PHP_FE(vscf_key_recipient_info_list_prev_php, arginfo_vscf_key_recipient_info_list_prev_php)
    PHP_FE(vscf_key_recipient_info_list_clear_php, arginfo_vscf_key_recipient_info_list_clear_php)
    PHP_FE(vscf_password_recipient_info_new_php, arginfo_vscf_password_recipient_info_new_php)
    PHP_FE(vscf_password_recipient_info_delete_php, arginfo_vscf_password_recipient_info_delete_php)
    PHP_FE(vscf_password_recipient_info_key_encryption_algorithm_php, arginfo_vscf_password_recipient_info_key_encryption_algorithm_php)
    PHP_FE(vscf_password_recipient_info_encrypted_key_php, arginfo_vscf_password_recipient_info_encrypted_key_php)
    PHP_FE(vscf_password_recipient_info_list_new_php, arginfo_vscf_password_recipient_info_list_new_php)
    PHP_FE(vscf_password_recipient_info_list_delete_php, arginfo_vscf_password_recipient_info_list_delete_php)
    PHP_FE(vscf_password_recipient_info_list_has_item_php, arginfo_vscf_password_recipient_info_list_has_item_php)
    PHP_FE(vscf_password_recipient_info_list_item_php, arginfo_vscf_password_recipient_info_list_item_php)
    PHP_FE(vscf_password_recipient_info_list_has_next_php, arginfo_vscf_password_recipient_info_list_has_next_php)
    PHP_FE(vscf_password_recipient_info_list_next_php, arginfo_vscf_password_recipient_info_list_next_php)
    PHP_FE(vscf_password_recipient_info_list_has_prev_php, arginfo_vscf_password_recipient_info_list_has_prev_php)
    PHP_FE(vscf_password_recipient_info_list_prev_php, arginfo_vscf_password_recipient_info_list_prev_php)
    PHP_FE(vscf_password_recipient_info_list_clear_php, arginfo_vscf_password_recipient_info_list_clear_php)
    PHP_FE(vscf_ecies_new_php, arginfo_vscf_ecies_new_php)
    PHP_FE(vscf_ecies_delete_php, arginfo_vscf_ecies_delete_php)
    PHP_FE(vscf_ecies_set_key_alg_php, arginfo_vscf_ecies_set_key_alg_php)
    PHP_FE(vscf_ecies_release_key_alg_php, arginfo_vscf_ecies_release_key_alg_php)
    PHP_FE(vscf_ecies_setup_defaults_php, arginfo_vscf_ecies_setup_defaults_php)
    PHP_FE(vscf_ecies_setup_defaults_no_random_php, arginfo_vscf_ecies_setup_defaults_no_random_php)
    PHP_FE(vscf_ecies_encrypted_len_php, arginfo_vscf_ecies_encrypted_len_php)
    PHP_FE(vscf_ecies_encrypt_php, arginfo_vscf_ecies_encrypt_php)
    PHP_FE(vscf_ecies_decrypted_len_php, arginfo_vscf_ecies_decrypted_len_php)
    PHP_FE(vscf_ecies_decrypt_php, arginfo_vscf_ecies_decrypt_php)
    PHP_FE(vscf_recipient_cipher_new_php, arginfo_vscf_recipient_cipher_new_php)
    PHP_FE(vscf_recipient_cipher_delete_php, arginfo_vscf_recipient_cipher_delete_php)
    PHP_FE(vscf_recipient_cipher_add_key_recipient_php, arginfo_vscf_recipient_cipher_add_key_recipient_php)
    PHP_FE(vscf_recipient_cipher_clear_recipients_php, arginfo_vscf_recipient_cipher_clear_recipients_php)
    PHP_FE(vscf_recipient_cipher_add_signer_php, arginfo_vscf_recipient_cipher_add_signer_php)
    PHP_FE(vscf_recipient_cipher_clear_signers_php, arginfo_vscf_recipient_cipher_clear_signers_php)
    PHP_FE(vscf_recipient_cipher_custom_params_php, arginfo_vscf_recipient_cipher_custom_params_php)
    PHP_FE(vscf_recipient_cipher_start_encryption_php, arginfo_vscf_recipient_cipher_start_encryption_php)
    PHP_FE(vscf_recipient_cipher_start_signed_encryption_php, arginfo_vscf_recipient_cipher_start_signed_encryption_php)
    PHP_FE(vscf_recipient_cipher_message_info_len_php, arginfo_vscf_recipient_cipher_message_info_len_php)
    PHP_FE(vscf_recipient_cipher_pack_message_info_php, arginfo_vscf_recipient_cipher_pack_message_info_php)
    PHP_FE(vscf_recipient_cipher_encryption_out_len_php, arginfo_vscf_recipient_cipher_encryption_out_len_php)
    PHP_FE(vscf_recipient_cipher_process_encryption_php, arginfo_vscf_recipient_cipher_process_encryption_php)
    PHP_FE(vscf_recipient_cipher_finish_encryption_php, arginfo_vscf_recipient_cipher_finish_encryption_php)
    PHP_FE(vscf_recipient_cipher_start_decryption_with_key_php, arginfo_vscf_recipient_cipher_start_decryption_with_key_php)
    PHP_FE(vscf_recipient_cipher_start_verified_decryption_with_key_php, arginfo_vscf_recipient_cipher_start_verified_decryption_with_key_php)
    PHP_FE(vscf_recipient_cipher_decryption_out_len_php, arginfo_vscf_recipient_cipher_decryption_out_len_php)
    PHP_FE(vscf_recipient_cipher_process_decryption_php, arginfo_vscf_recipient_cipher_process_decryption_php)
    PHP_FE(vscf_recipient_cipher_finish_decryption_php, arginfo_vscf_recipient_cipher_finish_decryption_php)
    PHP_FE(vscf_recipient_cipher_is_data_signed_php, arginfo_vscf_recipient_cipher_is_data_signed_php)
    PHP_FE(vscf_recipient_cipher_signer_infos_php, arginfo_vscf_recipient_cipher_signer_infos_php)
    PHP_FE(vscf_recipient_cipher_verify_signer_info_php, arginfo_vscf_recipient_cipher_verify_signer_info_php)
    PHP_FE(vscf_recipient_cipher_message_info_footer_len_php, arginfo_vscf_recipient_cipher_message_info_footer_len_php)
    PHP_FE(vscf_recipient_cipher_pack_message_info_footer_php, arginfo_vscf_recipient_cipher_pack_message_info_footer_php)
    PHP_FE(vscf_message_info_custom_params_new_php, arginfo_vscf_message_info_custom_params_new_php)
    PHP_FE(vscf_message_info_custom_params_delete_php, arginfo_vscf_message_info_custom_params_delete_php)
    PHP_FE(vscf_message_info_custom_params_add_int_php, arginfo_vscf_message_info_custom_params_add_int_php)
    PHP_FE(vscf_message_info_custom_params_add_string_php, arginfo_vscf_message_info_custom_params_add_string_php)
    PHP_FE(vscf_message_info_custom_params_add_data_php, arginfo_vscf_message_info_custom_params_add_data_php)
    PHP_FE(vscf_message_info_custom_params_clear_php, arginfo_vscf_message_info_custom_params_clear_php)
    PHP_FE(vscf_message_info_custom_params_find_int_php, arginfo_vscf_message_info_custom_params_find_int_php)
    PHP_FE(vscf_message_info_custom_params_find_string_php, arginfo_vscf_message_info_custom_params_find_string_php)
    PHP_FE(vscf_message_info_custom_params_find_data_php, arginfo_vscf_message_info_custom_params_find_data_php)
    PHP_FE(vscf_message_info_custom_params_has_params_php, arginfo_vscf_message_info_custom_params_has_params_php)
    PHP_FE(vscf_key_provider_new_php, arginfo_vscf_key_provider_new_php)
    PHP_FE(vscf_key_provider_delete_php, arginfo_vscf_key_provider_delete_php)
    PHP_FE(vscf_key_provider_setup_defaults_php, arginfo_vscf_key_provider_setup_defaults_php)
    PHP_FE(vscf_key_provider_set_rsa_params_php, arginfo_vscf_key_provider_set_rsa_params_php)
    PHP_FE(vscf_key_provider_generate_private_key_php, arginfo_vscf_key_provider_generate_private_key_php)
    PHP_FE(vscf_key_provider_import_private_key_php, arginfo_vscf_key_provider_import_private_key_php)
    PHP_FE(vscf_key_provider_import_public_key_php, arginfo_vscf_key_provider_import_public_key_php)
    PHP_FE(vscf_key_provider_exported_public_key_len_php, arginfo_vscf_key_provider_exported_public_key_len_php)
    PHP_FE(vscf_key_provider_export_public_key_php, arginfo_vscf_key_provider_export_public_key_php)
    PHP_FE(vscf_key_provider_exported_private_key_len_php, arginfo_vscf_key_provider_exported_private_key_len_php)
    PHP_FE(vscf_key_provider_export_private_key_php, arginfo_vscf_key_provider_export_private_key_php)
    PHP_FE(vscf_signer_new_php, arginfo_vscf_signer_new_php)
    PHP_FE(vscf_signer_delete_php, arginfo_vscf_signer_delete_php)
    PHP_FE(vscf_signer_reset_php, arginfo_vscf_signer_reset_php)
    PHP_FE(vscf_signer_append_data_php, arginfo_vscf_signer_append_data_php)
    PHP_FE(vscf_signer_signature_len_php, arginfo_vscf_signer_signature_len_php)
    PHP_FE(vscf_signer_sign_php, arginfo_vscf_signer_sign_php)
    PHP_FE(vscf_verifier_new_php, arginfo_vscf_verifier_new_php)
    PHP_FE(vscf_verifier_delete_php, arginfo_vscf_verifier_delete_php)
    PHP_FE(vscf_verifier_reset_php, arginfo_vscf_verifier_reset_php)
    PHP_FE(vscf_verifier_append_data_php, arginfo_vscf_verifier_append_data_php)
    PHP_FE(vscf_verifier_verify_php, arginfo_vscf_verifier_verify_php)
    PHP_FE(vscf_brainkey_client_new_php, arginfo_vscf_brainkey_client_new_php)
    PHP_FE(vscf_brainkey_client_delete_php, arginfo_vscf_brainkey_client_delete_php)
    PHP_FE(vscf_brainkey_client_setup_defaults_php, arginfo_vscf_brainkey_client_setup_defaults_php)
    PHP_FE(vscf_brainkey_client_blind_php, arginfo_vscf_brainkey_client_blind_php)
    PHP_FE(vscf_brainkey_client_deblind_php, arginfo_vscf_brainkey_client_deblind_php)
    PHP_FE(vscf_brainkey_server_new_php, arginfo_vscf_brainkey_server_new_php)
    PHP_FE(vscf_brainkey_server_delete_php, arginfo_vscf_brainkey_server_delete_php)
    PHP_FE(vscf_brainkey_server_setup_defaults_php, arginfo_vscf_brainkey_server_setup_defaults_php)
    PHP_FE(vscf_brainkey_server_generate_identity_secret_php, arginfo_vscf_brainkey_server_generate_identity_secret_php)
    PHP_FE(vscf_brainkey_server_harden_php, arginfo_vscf_brainkey_server_harden_php)
    PHP_FE(vscf_group_session_message_new_php, arginfo_vscf_group_session_message_new_php)
    PHP_FE(vscf_group_session_message_delete_php, arginfo_vscf_group_session_message_delete_php)
    PHP_FE(vscf_group_session_message_get_type_php, arginfo_vscf_group_session_message_get_type_php)
    PHP_FE(vscf_group_session_message_get_session_id_php, arginfo_vscf_group_session_message_get_session_id_php)
    PHP_FE(vscf_group_session_message_get_epoch_php, arginfo_vscf_group_session_message_get_epoch_php)
    PHP_FE(vscf_group_session_message_serialize_len_php, arginfo_vscf_group_session_message_serialize_len_php)
    PHP_FE(vscf_group_session_message_serialize_php, arginfo_vscf_group_session_message_serialize_php)
    PHP_FE(vscf_group_session_message_deserialize_php, arginfo_vscf_group_session_message_deserialize_php)
    PHP_FE(vscf_group_session_ticket_new_php, arginfo_vscf_group_session_ticket_new_php)
    PHP_FE(vscf_group_session_ticket_delete_php, arginfo_vscf_group_session_ticket_delete_php)
    PHP_FE(vscf_group_session_ticket_setup_defaults_php, arginfo_vscf_group_session_ticket_setup_defaults_php)
    PHP_FE(vscf_group_session_ticket_setup_ticket_as_new_php, arginfo_vscf_group_session_ticket_setup_ticket_as_new_php)
    PHP_FE(vscf_group_session_ticket_get_ticket_message_php, arginfo_vscf_group_session_ticket_get_ticket_message_php)
    PHP_FE(vscf_group_session_new_php, arginfo_vscf_group_session_new_php)
    PHP_FE(vscf_group_session_delete_php, arginfo_vscf_group_session_delete_php)
    PHP_FE(vscf_group_session_get_current_epoch_php, arginfo_vscf_group_session_get_current_epoch_php)
    PHP_FE(vscf_group_session_setup_defaults_php, arginfo_vscf_group_session_setup_defaults_php)
    PHP_FE(vscf_group_session_get_session_id_php, arginfo_vscf_group_session_get_session_id_php)
    PHP_FE(vscf_group_session_add_epoch_php, arginfo_vscf_group_session_add_epoch_php)
    PHP_FE(vscf_group_session_encrypt_php, arginfo_vscf_group_session_encrypt_php)
    PHP_FE(vscf_group_session_decrypt_len_php, arginfo_vscf_group_session_decrypt_len_php)
    PHP_FE(vscf_group_session_decrypt_php, arginfo_vscf_group_session_decrypt_php)
    PHP_FE(vscf_group_session_create_group_ticket_php, arginfo_vscf_group_session_create_group_ticket_php)
    PHP_FE(vscf_message_info_editor_new_php, arginfo_vscf_message_info_editor_new_php)
    PHP_FE(vscf_message_info_editor_delete_php, arginfo_vscf_message_info_editor_delete_php)
    PHP_FE(vscf_message_info_editor_setup_defaults_php, arginfo_vscf_message_info_editor_setup_defaults_php)
    PHP_FE(vscf_message_info_editor_unpack_php, arginfo_vscf_message_info_editor_unpack_php)
    PHP_FE(vscf_message_info_editor_unlock_php, arginfo_vscf_message_info_editor_unlock_php)
    PHP_FE(vscf_message_info_editor_add_key_recipient_php, arginfo_vscf_message_info_editor_add_key_recipient_php)
    PHP_FE(vscf_message_info_editor_remove_key_recipient_php, arginfo_vscf_message_info_editor_remove_key_recipient_php)
    PHP_FE(vscf_message_info_editor_remove_all_php, arginfo_vscf_message_info_editor_remove_all_php)
    PHP_FE(vscf_message_info_editor_packed_len_php, arginfo_vscf_message_info_editor_packed_len_php)
    PHP_FE(vscf_message_info_editor_pack_php, arginfo_vscf_message_info_editor_pack_php)
    PHP_FE(vscf_signer_info_new_php, arginfo_vscf_signer_info_new_php)
    PHP_FE(vscf_signer_info_delete_php, arginfo_vscf_signer_info_delete_php)
    PHP_FE(vscf_signer_info_signer_id_php, arginfo_vscf_signer_info_signer_id_php)
    PHP_FE(vscf_signer_info_signer_alg_info_php, arginfo_vscf_signer_info_signer_alg_info_php)
    PHP_FE(vscf_signer_info_signature_php, arginfo_vscf_signer_info_signature_php)
    PHP_FE(vscf_signer_info_list_new_php, arginfo_vscf_signer_info_list_new_php)
    PHP_FE(vscf_signer_info_list_delete_php, arginfo_vscf_signer_info_list_delete_php)
    PHP_FE(vscf_signer_info_list_has_item_php, arginfo_vscf_signer_info_list_has_item_php)
    PHP_FE(vscf_signer_info_list_item_php, arginfo_vscf_signer_info_list_item_php)
    PHP_FE(vscf_signer_info_list_has_next_php, arginfo_vscf_signer_info_list_has_next_php)
    PHP_FE(vscf_signer_info_list_next_php, arginfo_vscf_signer_info_list_next_php)
    PHP_FE(vscf_signer_info_list_has_prev_php, arginfo_vscf_signer_info_list_has_prev_php)
    PHP_FE(vscf_signer_info_list_prev_php, arginfo_vscf_signer_info_list_prev_php)
    PHP_FE(vscf_signer_info_list_clear_php, arginfo_vscf_signer_info_list_clear_php)
    PHP_FE(vscf_message_info_footer_new_php, arginfo_vscf_message_info_footer_new_php)
    PHP_FE(vscf_message_info_footer_delete_php, arginfo_vscf_message_info_footer_delete_php)
    PHP_FE(vscf_message_info_footer_has_signer_infos_php, arginfo_vscf_message_info_footer_has_signer_infos_php)
    PHP_FE(vscf_message_info_footer_signer_infos_php, arginfo_vscf_message_info_footer_signer_infos_php)
    PHP_FE(vscf_message_info_footer_signer_hash_alg_info_php, arginfo_vscf_message_info_footer_signer_hash_alg_info_php)
    PHP_FE(vscf_message_info_footer_signer_digest_php, arginfo_vscf_message_info_footer_signer_digest_php)
    PHP_FE(vscf_signed_data_info_new_php, arginfo_vscf_signed_data_info_new_php)
    PHP_FE(vscf_signed_data_info_delete_php, arginfo_vscf_signed_data_info_delete_php)
    PHP_FE(vscf_signed_data_info_set_hash_alg_info_php, arginfo_vscf_signed_data_info_set_hash_alg_info_php)
    PHP_FE(vscf_signed_data_info_hash_alg_info_php, arginfo_vscf_signed_data_info_hash_alg_info_php)
    PHP_FE(vscf_footer_info_new_php, arginfo_vscf_footer_info_new_php)
    PHP_FE(vscf_footer_info_delete_php, arginfo_vscf_footer_info_delete_php)
    PHP_FE(vscf_footer_info_has_signed_data_info_php, arginfo_vscf_footer_info_has_signed_data_info_php)
    PHP_FE(vscf_footer_info_signed_data_info_php, arginfo_vscf_footer_info_signed_data_info_php)
    PHP_FE(vscf_footer_info_set_data_size_php, arginfo_vscf_footer_info_set_data_size_php)
    PHP_FE(vscf_footer_info_data_size_php, arginfo_vscf_footer_info_data_size_php)
    PHP_FE(vscf_sha224_new_php, arginfo_vscf_sha224_new_php)
    PHP_FE(vscf_sha224_delete_php, arginfo_vscf_sha224_delete_php)
    PHP_FE(vscf_sha224_alg_id_php, arginfo_vscf_sha224_alg_id_php)
    PHP_FE(vscf_sha224_produce_alg_info_php, arginfo_vscf_sha224_produce_alg_info_php)
    PHP_FE(vscf_sha224_restore_alg_info_php, arginfo_vscf_sha224_restore_alg_info_php)
    PHP_FE(vscf_sha224_hash_php, arginfo_vscf_sha224_hash_php)
    PHP_FE(vscf_sha224_start_php, arginfo_vscf_sha224_start_php)
    PHP_FE(vscf_sha224_update_php, arginfo_vscf_sha224_update_php)
    PHP_FE(vscf_sha224_finish_php, arginfo_vscf_sha224_finish_php)
    PHP_FE(vscf_sha256_new_php, arginfo_vscf_sha256_new_php)
    PHP_FE(vscf_sha256_delete_php, arginfo_vscf_sha256_delete_php)
    PHP_FE(vscf_sha256_alg_id_php, arginfo_vscf_sha256_alg_id_php)
    PHP_FE(vscf_sha256_produce_alg_info_php, arginfo_vscf_sha256_produce_alg_info_php)
    PHP_FE(vscf_sha256_restore_alg_info_php, arginfo_vscf_sha256_restore_alg_info_php)
    PHP_FE(vscf_sha256_hash_php, arginfo_vscf_sha256_hash_php)
    PHP_FE(vscf_sha256_start_php, arginfo_vscf_sha256_start_php)
    PHP_FE(vscf_sha256_update_php, arginfo_vscf_sha256_update_php)
    PHP_FE(vscf_sha256_finish_php, arginfo_vscf_sha256_finish_php)
    PHP_FE(vscf_sha384_new_php, arginfo_vscf_sha384_new_php)
    PHP_FE(vscf_sha384_delete_php, arginfo_vscf_sha384_delete_php)
    PHP_FE(vscf_sha384_alg_id_php, arginfo_vscf_sha384_alg_id_php)
    PHP_FE(vscf_sha384_produce_alg_info_php, arginfo_vscf_sha384_produce_alg_info_php)
    PHP_FE(vscf_sha384_restore_alg_info_php, arginfo_vscf_sha384_restore_alg_info_php)
    PHP_FE(vscf_sha384_hash_php, arginfo_vscf_sha384_hash_php)
    PHP_FE(vscf_sha384_start_php, arginfo_vscf_sha384_start_php)
    PHP_FE(vscf_sha384_update_php, arginfo_vscf_sha384_update_php)
    PHP_FE(vscf_sha384_finish_php, arginfo_vscf_sha384_finish_php)
    PHP_FE(vscf_sha512_new_php, arginfo_vscf_sha512_new_php)
    PHP_FE(vscf_sha512_delete_php, arginfo_vscf_sha512_delete_php)
    PHP_FE(vscf_sha512_alg_id_php, arginfo_vscf_sha512_alg_id_php)
    PHP_FE(vscf_sha512_produce_alg_info_php, arginfo_vscf_sha512_produce_alg_info_php)
    PHP_FE(vscf_sha512_restore_alg_info_php, arginfo_vscf_sha512_restore_alg_info_php)
    PHP_FE(vscf_sha512_hash_php, arginfo_vscf_sha512_hash_php)
    PHP_FE(vscf_sha512_start_php, arginfo_vscf_sha512_start_php)
    PHP_FE(vscf_sha512_update_php, arginfo_vscf_sha512_update_php)
    PHP_FE(vscf_sha512_finish_php, arginfo_vscf_sha512_finish_php)
    PHP_FE(vscf_aes256_gcm_new_php, arginfo_vscf_aes256_gcm_new_php)
    PHP_FE(vscf_aes256_gcm_delete_php, arginfo_vscf_aes256_gcm_delete_php)
    PHP_FE(vscf_aes256_gcm_alg_id_php, arginfo_vscf_aes256_gcm_alg_id_php)
    PHP_FE(vscf_aes256_gcm_produce_alg_info_php, arginfo_vscf_aes256_gcm_produce_alg_info_php)
    PHP_FE(vscf_aes256_gcm_restore_alg_info_php, arginfo_vscf_aes256_gcm_restore_alg_info_php)
    PHP_FE(vscf_aes256_gcm_encrypt_php, arginfo_vscf_aes256_gcm_encrypt_php)
    PHP_FE(vscf_aes256_gcm_encrypted_len_php, arginfo_vscf_aes256_gcm_encrypted_len_php)
    PHP_FE(vscf_aes256_gcm_precise_encrypted_len_php, arginfo_vscf_aes256_gcm_precise_encrypted_len_php)
    PHP_FE(vscf_aes256_gcm_decrypt_php, arginfo_vscf_aes256_gcm_decrypt_php)
    PHP_FE(vscf_aes256_gcm_decrypted_len_php, arginfo_vscf_aes256_gcm_decrypted_len_php)
    PHP_FE(vscf_aes256_gcm_set_nonce_php, arginfo_vscf_aes256_gcm_set_nonce_php)
    PHP_FE(vscf_aes256_gcm_set_key_php, arginfo_vscf_aes256_gcm_set_key_php)
    PHP_FE(vscf_aes256_gcm_start_encryption_php, arginfo_vscf_aes256_gcm_start_encryption_php)
    PHP_FE(vscf_aes256_gcm_start_decryption_php, arginfo_vscf_aes256_gcm_start_decryption_php)
    PHP_FE(vscf_aes256_gcm_update_php, arginfo_vscf_aes256_gcm_update_php)
    PHP_FE(vscf_aes256_gcm_out_len_php, arginfo_vscf_aes256_gcm_out_len_php)
    PHP_FE(vscf_aes256_gcm_encrypted_out_len_php, arginfo_vscf_aes256_gcm_encrypted_out_len_php)
    PHP_FE(vscf_aes256_gcm_decrypted_out_len_php, arginfo_vscf_aes256_gcm_decrypted_out_len_php)
    PHP_FE(vscf_aes256_gcm_finish_php, arginfo_vscf_aes256_gcm_finish_php)
    PHP_FE(vscf_aes256_gcm_auth_encrypt_php, arginfo_vscf_aes256_gcm_auth_encrypt_php)
    PHP_FE(vscf_aes256_gcm_auth_encrypted_len_php, arginfo_vscf_aes256_gcm_auth_encrypted_len_php)
    PHP_FE(vscf_aes256_gcm_auth_decrypt_php, arginfo_vscf_aes256_gcm_auth_decrypt_php)
    PHP_FE(vscf_aes256_gcm_auth_decrypted_len_php, arginfo_vscf_aes256_gcm_auth_decrypted_len_php)
    PHP_FE(vscf_aes256_gcm_set_auth_data_php, arginfo_vscf_aes256_gcm_set_auth_data_php)
    PHP_FE(vscf_aes256_gcm_finish_auth_encryption_php, arginfo_vscf_aes256_gcm_finish_auth_encryption_php)
    PHP_FE(vscf_aes256_gcm_finish_auth_decryption_php, arginfo_vscf_aes256_gcm_finish_auth_decryption_php)
    PHP_FE(vscf_aes256_cbc_new_php, arginfo_vscf_aes256_cbc_new_php)
    PHP_FE(vscf_aes256_cbc_delete_php, arginfo_vscf_aes256_cbc_delete_php)
    PHP_FE(vscf_aes256_cbc_alg_id_php, arginfo_vscf_aes256_cbc_alg_id_php)
    PHP_FE(vscf_aes256_cbc_produce_alg_info_php, arginfo_vscf_aes256_cbc_produce_alg_info_php)
    PHP_FE(vscf_aes256_cbc_restore_alg_info_php, arginfo_vscf_aes256_cbc_restore_alg_info_php)
    PHP_FE(vscf_aes256_cbc_encrypt_php, arginfo_vscf_aes256_cbc_encrypt_php)
    PHP_FE(vscf_aes256_cbc_encrypted_len_php, arginfo_vscf_aes256_cbc_encrypted_len_php)
    PHP_FE(vscf_aes256_cbc_precise_encrypted_len_php, arginfo_vscf_aes256_cbc_precise_encrypted_len_php)
    PHP_FE(vscf_aes256_cbc_decrypt_php, arginfo_vscf_aes256_cbc_decrypt_php)
    PHP_FE(vscf_aes256_cbc_decrypted_len_php, arginfo_vscf_aes256_cbc_decrypted_len_php)
    PHP_FE(vscf_aes256_cbc_set_nonce_php, arginfo_vscf_aes256_cbc_set_nonce_php)
    PHP_FE(vscf_aes256_cbc_set_key_php, arginfo_vscf_aes256_cbc_set_key_php)
    PHP_FE(vscf_aes256_cbc_start_encryption_php, arginfo_vscf_aes256_cbc_start_encryption_php)
    PHP_FE(vscf_aes256_cbc_start_decryption_php, arginfo_vscf_aes256_cbc_start_decryption_php)
    PHP_FE(vscf_aes256_cbc_update_php, arginfo_vscf_aes256_cbc_update_php)
    PHP_FE(vscf_aes256_cbc_out_len_php, arginfo_vscf_aes256_cbc_out_len_php)
    PHP_FE(vscf_aes256_cbc_encrypted_out_len_php, arginfo_vscf_aes256_cbc_encrypted_out_len_php)
    PHP_FE(vscf_aes256_cbc_decrypted_out_len_php, arginfo_vscf_aes256_cbc_decrypted_out_len_php)
    PHP_FE(vscf_aes256_cbc_finish_php, arginfo_vscf_aes256_cbc_finish_php)
    PHP_FE(vscf_asn1rd_new_php, arginfo_vscf_asn1rd_new_php)
    PHP_FE(vscf_asn1rd_delete_php, arginfo_vscf_asn1rd_delete_php)
    PHP_FE(vscf_asn1rd_reset_php, arginfo_vscf_asn1rd_reset_php)
    PHP_FE(vscf_asn1rd_left_len_php, arginfo_vscf_asn1rd_left_len_php)
    PHP_FE(vscf_asn1rd_has_error_php, arginfo_vscf_asn1rd_has_error_php)
    PHP_FE(vscf_asn1rd_status_php, arginfo_vscf_asn1rd_status_php)
    PHP_FE(vscf_asn1rd_get_tag_php, arginfo_vscf_asn1rd_get_tag_php)
    PHP_FE(vscf_asn1rd_get_len_php, arginfo_vscf_asn1rd_get_len_php)
    PHP_FE(vscf_asn1rd_get_data_len_php, arginfo_vscf_asn1rd_get_data_len_php)
    PHP_FE(vscf_asn1rd_read_tag_php, arginfo_vscf_asn1rd_read_tag_php)
    PHP_FE(vscf_asn1rd_read_context_tag_php, arginfo_vscf_asn1rd_read_context_tag_php)
    PHP_FE(vscf_asn1rd_read_int_php, arginfo_vscf_asn1rd_read_int_php)
    PHP_FE(vscf_asn1rd_read_int8_php, arginfo_vscf_asn1rd_read_int8_php)
    PHP_FE(vscf_asn1rd_read_int16_php, arginfo_vscf_asn1rd_read_int16_php)
    PHP_FE(vscf_asn1rd_read_int32_php, arginfo_vscf_asn1rd_read_int32_php)
    PHP_FE(vscf_asn1rd_read_int64_php, arginfo_vscf_asn1rd_read_int64_php)
    PHP_FE(vscf_asn1rd_read_uint_php, arginfo_vscf_asn1rd_read_uint_php)
    PHP_FE(vscf_asn1rd_read_uint8_php, arginfo_vscf_asn1rd_read_uint8_php)
    PHP_FE(vscf_asn1rd_read_uint16_php, arginfo_vscf_asn1rd_read_uint16_php)
    PHP_FE(vscf_asn1rd_read_uint32_php, arginfo_vscf_asn1rd_read_uint32_php)
    PHP_FE(vscf_asn1rd_read_uint64_php, arginfo_vscf_asn1rd_read_uint64_php)
    PHP_FE(vscf_asn1rd_read_bool_php, arginfo_vscf_asn1rd_read_bool_php)
    PHP_FE(vscf_asn1rd_read_null_php, arginfo_vscf_asn1rd_read_null_php)
    PHP_FE(vscf_asn1rd_read_null_optional_php, arginfo_vscf_asn1rd_read_null_optional_php)
    PHP_FE(vscf_asn1rd_read_octet_str_php, arginfo_vscf_asn1rd_read_octet_str_php)
    PHP_FE(vscf_asn1rd_read_bitstring_as_octet_str_php, arginfo_vscf_asn1rd_read_bitstring_as_octet_str_php)
    PHP_FE(vscf_asn1rd_read_utf8_str_php, arginfo_vscf_asn1rd_read_utf8_str_php)
    PHP_FE(vscf_asn1rd_read_oid_php, arginfo_vscf_asn1rd_read_oid_php)
    PHP_FE(vscf_asn1rd_read_data_php, arginfo_vscf_asn1rd_read_data_php)
    PHP_FE(vscf_asn1rd_read_sequence_php, arginfo_vscf_asn1rd_read_sequence_php)
    PHP_FE(vscf_asn1rd_read_set_php, arginfo_vscf_asn1rd_read_set_php)
    PHP_FE(vscf_asn1wr_new_php, arginfo_vscf_asn1wr_new_php)
    PHP_FE(vscf_asn1wr_delete_php, arginfo_vscf_asn1wr_delete_php)
    PHP_FE(vscf_asn1wr_reset_php, arginfo_vscf_asn1wr_reset_php)
    PHP_FE(vscf_asn1wr_finish_php, arginfo_vscf_asn1wr_finish_php)
    PHP_FE(vscf_asn1wr_bytes_php, arginfo_vscf_asn1wr_bytes_php)
    PHP_FE(vscf_asn1wr_len_php, arginfo_vscf_asn1wr_len_php)
    PHP_FE(vscf_asn1wr_written_len_php, arginfo_vscf_asn1wr_written_len_php)
    PHP_FE(vscf_asn1wr_unwritten_len_php, arginfo_vscf_asn1wr_unwritten_len_php)
    PHP_FE(vscf_asn1wr_has_error_php, arginfo_vscf_asn1wr_has_error_php)
    PHP_FE(vscf_asn1wr_status_php, arginfo_vscf_asn1wr_status_php)
    PHP_FE(vscf_asn1wr_reserve_php, arginfo_vscf_asn1wr_reserve_php)
    PHP_FE(vscf_asn1wr_write_tag_php, arginfo_vscf_asn1wr_write_tag_php)
    PHP_FE(vscf_asn1wr_write_context_tag_php, arginfo_vscf_asn1wr_write_context_tag_php)
    PHP_FE(vscf_asn1wr_write_len_php, arginfo_vscf_asn1wr_write_len_php)
    PHP_FE(vscf_asn1wr_write_int_php, arginfo_vscf_asn1wr_write_int_php)
    PHP_FE(vscf_asn1wr_write_int8_php, arginfo_vscf_asn1wr_write_int8_php)
    PHP_FE(vscf_asn1wr_write_int16_php, arginfo_vscf_asn1wr_write_int16_php)
    PHP_FE(vscf_asn1wr_write_int32_php, arginfo_vscf_asn1wr_write_int32_php)
    PHP_FE(vscf_asn1wr_write_int64_php, arginfo_vscf_asn1wr_write_int64_php)
    PHP_FE(vscf_asn1wr_write_uint_php, arginfo_vscf_asn1wr_write_uint_php)
    PHP_FE(vscf_asn1wr_write_uint8_php, arginfo_vscf_asn1wr_write_uint8_php)
    PHP_FE(vscf_asn1wr_write_uint16_php, arginfo_vscf_asn1wr_write_uint16_php)
    PHP_FE(vscf_asn1wr_write_uint32_php, arginfo_vscf_asn1wr_write_uint32_php)
    PHP_FE(vscf_asn1wr_write_uint64_php, arginfo_vscf_asn1wr_write_uint64_php)
    PHP_FE(vscf_asn1wr_write_bool_php, arginfo_vscf_asn1wr_write_bool_php)
    PHP_FE(vscf_asn1wr_write_null_php, arginfo_vscf_asn1wr_write_null_php)
    PHP_FE(vscf_asn1wr_write_octet_str_php, arginfo_vscf_asn1wr_write_octet_str_php)
    PHP_FE(vscf_asn1wr_write_octet_str_as_bitstring_php, arginfo_vscf_asn1wr_write_octet_str_as_bitstring_php)
    PHP_FE(vscf_asn1wr_write_data_php, arginfo_vscf_asn1wr_write_data_php)
    PHP_FE(vscf_asn1wr_write_utf8_str_php, arginfo_vscf_asn1wr_write_utf8_str_php)
    PHP_FE(vscf_asn1wr_write_oid_php, arginfo_vscf_asn1wr_write_oid_php)
    PHP_FE(vscf_asn1wr_write_sequence_php, arginfo_vscf_asn1wr_write_sequence_php)
    PHP_FE(vscf_asn1wr_write_set_php, arginfo_vscf_asn1wr_write_set_php)
    PHP_FE(vscf_rsa_public_key_new_php, arginfo_vscf_rsa_public_key_new_php)
    PHP_FE(vscf_rsa_public_key_delete_php, arginfo_vscf_rsa_public_key_delete_php)
    PHP_FE(vscf_rsa_public_key_key_exponent_php, arginfo_vscf_rsa_public_key_key_exponent_php)
    PHP_FE(vscf_rsa_public_key_alg_id_php, arginfo_vscf_rsa_public_key_alg_id_php)
    PHP_FE(vscf_rsa_public_key_alg_info_php, arginfo_vscf_rsa_public_key_alg_info_php)
    PHP_FE(vscf_rsa_public_key_len_php, arginfo_vscf_rsa_public_key_len_php)
    PHP_FE(vscf_rsa_public_key_bitlen_php, arginfo_vscf_rsa_public_key_bitlen_php)
    PHP_FE(vscf_rsa_public_key_is_valid_php, arginfo_vscf_rsa_public_key_is_valid_php)
    PHP_FE(vscf_rsa_private_key_new_php, arginfo_vscf_rsa_private_key_new_php)
    PHP_FE(vscf_rsa_private_key_delete_php, arginfo_vscf_rsa_private_key_delete_php)
    PHP_FE(vscf_rsa_private_key_alg_id_php, arginfo_vscf_rsa_private_key_alg_id_php)
    PHP_FE(vscf_rsa_private_key_alg_info_php, arginfo_vscf_rsa_private_key_alg_info_php)
    PHP_FE(vscf_rsa_private_key_len_php, arginfo_vscf_rsa_private_key_len_php)
    PHP_FE(vscf_rsa_private_key_bitlen_php, arginfo_vscf_rsa_private_key_bitlen_php)
    PHP_FE(vscf_rsa_private_key_is_valid_php, arginfo_vscf_rsa_private_key_is_valid_php)
    PHP_FE(vscf_rsa_private_key_extract_public_key_php, arginfo_vscf_rsa_private_key_extract_public_key_php)
    PHP_FE(vscf_rsa_new_php, arginfo_vscf_rsa_new_php)
    PHP_FE(vscf_rsa_delete_php, arginfo_vscf_rsa_delete_php)
    PHP_FE(vscf_rsa_setup_defaults_php, arginfo_vscf_rsa_setup_defaults_php)
    PHP_FE(vscf_rsa_generate_key_php, arginfo_vscf_rsa_generate_key_php)
    PHP_FE(vscf_rsa_alg_id_php, arginfo_vscf_rsa_alg_id_php)
    PHP_FE(vscf_rsa_produce_alg_info_php, arginfo_vscf_rsa_produce_alg_info_php)
    PHP_FE(vscf_rsa_restore_alg_info_php, arginfo_vscf_rsa_restore_alg_info_php)
    PHP_FE(vscf_rsa_generate_ephemeral_key_php, arginfo_vscf_rsa_generate_ephemeral_key_php)
    PHP_FE(vscf_rsa_import_public_key_php, arginfo_vscf_rsa_import_public_key_php)
    PHP_FE(vscf_rsa_export_public_key_php, arginfo_vscf_rsa_export_public_key_php)
    PHP_FE(vscf_rsa_import_private_key_php, arginfo_vscf_rsa_import_private_key_php)
    PHP_FE(vscf_rsa_export_private_key_php, arginfo_vscf_rsa_export_private_key_php)
    PHP_FE(vscf_rsa_can_encrypt_php, arginfo_vscf_rsa_can_encrypt_php)
    PHP_FE(vscf_rsa_encrypted_len_php, arginfo_vscf_rsa_encrypted_len_php)
    PHP_FE(vscf_rsa_encrypt_php, arginfo_vscf_rsa_encrypt_php)
    PHP_FE(vscf_rsa_can_decrypt_php, arginfo_vscf_rsa_can_decrypt_php)
    PHP_FE(vscf_rsa_decrypted_len_php, arginfo_vscf_rsa_decrypted_len_php)
    PHP_FE(vscf_rsa_decrypt_php, arginfo_vscf_rsa_decrypt_php)
    PHP_FE(vscf_rsa_can_sign_php, arginfo_vscf_rsa_can_sign_php)
    PHP_FE(vscf_rsa_signature_len_php, arginfo_vscf_rsa_signature_len_php)
    PHP_FE(vscf_rsa_sign_hash_php, arginfo_vscf_rsa_sign_hash_php)
    PHP_FE(vscf_rsa_can_verify_php, arginfo_vscf_rsa_can_verify_php)
    PHP_FE(vscf_rsa_verify_hash_php, arginfo_vscf_rsa_verify_hash_php)
    PHP_FE(vscf_ecc_public_key_new_php, arginfo_vscf_ecc_public_key_new_php)
    PHP_FE(vscf_ecc_public_key_delete_php, arginfo_vscf_ecc_public_key_delete_php)
    PHP_FE(vscf_ecc_public_key_alg_id_php, arginfo_vscf_ecc_public_key_alg_id_php)
    PHP_FE(vscf_ecc_public_key_alg_info_php, arginfo_vscf_ecc_public_key_alg_info_php)
    PHP_FE(vscf_ecc_public_key_len_php, arginfo_vscf_ecc_public_key_len_php)
    PHP_FE(vscf_ecc_public_key_bitlen_php, arginfo_vscf_ecc_public_key_bitlen_php)
    PHP_FE(vscf_ecc_public_key_is_valid_php, arginfo_vscf_ecc_public_key_is_valid_php)
    PHP_FE(vscf_ecc_private_key_new_php, arginfo_vscf_ecc_private_key_new_php)
    PHP_FE(vscf_ecc_private_key_delete_php, arginfo_vscf_ecc_private_key_delete_php)
    PHP_FE(vscf_ecc_private_key_alg_id_php, arginfo_vscf_ecc_private_key_alg_id_php)
    PHP_FE(vscf_ecc_private_key_alg_info_php, arginfo_vscf_ecc_private_key_alg_info_php)
    PHP_FE(vscf_ecc_private_key_len_php, arginfo_vscf_ecc_private_key_len_php)
    PHP_FE(vscf_ecc_private_key_bitlen_php, arginfo_vscf_ecc_private_key_bitlen_php)
    PHP_FE(vscf_ecc_private_key_is_valid_php, arginfo_vscf_ecc_private_key_is_valid_php)
    PHP_FE(vscf_ecc_private_key_extract_public_key_php, arginfo_vscf_ecc_private_key_extract_public_key_php)
    PHP_FE(vscf_ecc_new_php, arginfo_vscf_ecc_new_php)
    PHP_FE(vscf_ecc_delete_php, arginfo_vscf_ecc_delete_php)
    PHP_FE(vscf_ecc_setup_defaults_php, arginfo_vscf_ecc_setup_defaults_php)
    PHP_FE(vscf_ecc_generate_key_php, arginfo_vscf_ecc_generate_key_php)
    PHP_FE(vscf_ecc_alg_id_php, arginfo_vscf_ecc_alg_id_php)
    PHP_FE(vscf_ecc_produce_alg_info_php, arginfo_vscf_ecc_produce_alg_info_php)
    PHP_FE(vscf_ecc_restore_alg_info_php, arginfo_vscf_ecc_restore_alg_info_php)
    PHP_FE(vscf_ecc_generate_ephemeral_key_php, arginfo_vscf_ecc_generate_ephemeral_key_php)
    PHP_FE(vscf_ecc_import_public_key_php, arginfo_vscf_ecc_import_public_key_php)
    PHP_FE(vscf_ecc_export_public_key_php, arginfo_vscf_ecc_export_public_key_php)
    PHP_FE(vscf_ecc_import_private_key_php, arginfo_vscf_ecc_import_private_key_php)
    PHP_FE(vscf_ecc_export_private_key_php, arginfo_vscf_ecc_export_private_key_php)
    PHP_FE(vscf_ecc_can_encrypt_php, arginfo_vscf_ecc_can_encrypt_php)
    PHP_FE(vscf_ecc_encrypted_len_php, arginfo_vscf_ecc_encrypted_len_php)
    PHP_FE(vscf_ecc_encrypt_php, arginfo_vscf_ecc_encrypt_php)
    PHP_FE(vscf_ecc_can_decrypt_php, arginfo_vscf_ecc_can_decrypt_php)
    PHP_FE(vscf_ecc_decrypted_len_php, arginfo_vscf_ecc_decrypted_len_php)
    PHP_FE(vscf_ecc_decrypt_php, arginfo_vscf_ecc_decrypt_php)
    PHP_FE(vscf_ecc_can_sign_php, arginfo_vscf_ecc_can_sign_php)
    PHP_FE(vscf_ecc_signature_len_php, arginfo_vscf_ecc_signature_len_php)
    PHP_FE(vscf_ecc_sign_hash_php, arginfo_vscf_ecc_sign_hash_php)
    PHP_FE(vscf_ecc_can_verify_php, arginfo_vscf_ecc_can_verify_php)
    PHP_FE(vscf_ecc_verify_hash_php, arginfo_vscf_ecc_verify_hash_php)
    PHP_FE(vscf_ecc_compute_shared_key_php, arginfo_vscf_ecc_compute_shared_key_php)
    PHP_FE(vscf_ecc_shared_key_len_php, arginfo_vscf_ecc_shared_key_len_php)
    PHP_FE(vscf_entropy_accumulator_new_php, arginfo_vscf_entropy_accumulator_new_php)
    PHP_FE(vscf_entropy_accumulator_delete_php, arginfo_vscf_entropy_accumulator_delete_php)
    PHP_FE(vscf_entropy_accumulator_setup_defaults_php, arginfo_vscf_entropy_accumulator_setup_defaults_php)
    PHP_FE(vscf_entropy_accumulator_add_source_php, arginfo_vscf_entropy_accumulator_add_source_php)
    PHP_FE(vscf_entropy_accumulator_is_strong_php, arginfo_vscf_entropy_accumulator_is_strong_php)
    PHP_FE(vscf_entropy_accumulator_gather_php, arginfo_vscf_entropy_accumulator_gather_php)
    PHP_FE(vscf_ctr_drbg_new_php, arginfo_vscf_ctr_drbg_new_php)
    PHP_FE(vscf_ctr_drbg_delete_php, arginfo_vscf_ctr_drbg_delete_php)
    PHP_FE(vscf_ctr_drbg_setup_defaults_php, arginfo_vscf_ctr_drbg_setup_defaults_php)
    PHP_FE(vscf_ctr_drbg_enable_prediction_resistance_php, arginfo_vscf_ctr_drbg_enable_prediction_resistance_php)
    PHP_FE(vscf_ctr_drbg_set_reseed_interval_php, arginfo_vscf_ctr_drbg_set_reseed_interval_php)
    PHP_FE(vscf_ctr_drbg_set_entropy_len_php, arginfo_vscf_ctr_drbg_set_entropy_len_php)
    PHP_FE(vscf_ctr_drbg_random_php, arginfo_vscf_ctr_drbg_random_php)
    PHP_FE(vscf_ctr_drbg_reseed_php, arginfo_vscf_ctr_drbg_reseed_php)
    PHP_FE(vscf_hmac_new_php, arginfo_vscf_hmac_new_php)
    PHP_FE(vscf_hmac_delete_php, arginfo_vscf_hmac_delete_php)
    PHP_FE(vscf_hmac_alg_id_php, arginfo_vscf_hmac_alg_id_php)
    PHP_FE(vscf_hmac_produce_alg_info_php, arginfo_vscf_hmac_produce_alg_info_php)
    PHP_FE(vscf_hmac_restore_alg_info_php, arginfo_vscf_hmac_restore_alg_info_php)
    PHP_FE(vscf_hmac_digest_len_php, arginfo_vscf_hmac_digest_len_php)
    PHP_FE(vscf_hmac_mac_php, arginfo_vscf_hmac_mac_php)
    PHP_FE(vscf_hmac_start_php, arginfo_vscf_hmac_start_php)
    PHP_FE(vscf_hmac_update_php, arginfo_vscf_hmac_update_php)
    PHP_FE(vscf_hmac_finish_php, arginfo_vscf_hmac_finish_php)
    PHP_FE(vscf_hmac_reset_php, arginfo_vscf_hmac_reset_php)
    PHP_FE(vscf_hkdf_new_php, arginfo_vscf_hkdf_new_php)
    PHP_FE(vscf_hkdf_delete_php, arginfo_vscf_hkdf_delete_php)
    PHP_FE(vscf_hkdf_alg_id_php, arginfo_vscf_hkdf_alg_id_php)
    PHP_FE(vscf_hkdf_produce_alg_info_php, arginfo_vscf_hkdf_produce_alg_info_php)
    PHP_FE(vscf_hkdf_restore_alg_info_php, arginfo_vscf_hkdf_restore_alg_info_php)
    PHP_FE(vscf_hkdf_derive_php, arginfo_vscf_hkdf_derive_php)
    PHP_FE(vscf_hkdf_reset_php, arginfo_vscf_hkdf_reset_php)
    PHP_FE(vscf_hkdf_set_info_php, arginfo_vscf_hkdf_set_info_php)
    PHP_FE(vscf_kdf1_new_php, arginfo_vscf_kdf1_new_php)
    PHP_FE(vscf_kdf1_delete_php, arginfo_vscf_kdf1_delete_php)
    PHP_FE(vscf_kdf1_alg_id_php, arginfo_vscf_kdf1_alg_id_php)
    PHP_FE(vscf_kdf1_produce_alg_info_php, arginfo_vscf_kdf1_produce_alg_info_php)
    PHP_FE(vscf_kdf1_restore_alg_info_php, arginfo_vscf_kdf1_restore_alg_info_php)
    PHP_FE(vscf_kdf1_derive_php, arginfo_vscf_kdf1_derive_php)
    PHP_FE(vscf_kdf2_new_php, arginfo_vscf_kdf2_new_php)
    PHP_FE(vscf_kdf2_delete_php, arginfo_vscf_kdf2_delete_php)
    PHP_FE(vscf_kdf2_alg_id_php, arginfo_vscf_kdf2_alg_id_php)
    PHP_FE(vscf_kdf2_produce_alg_info_php, arginfo_vscf_kdf2_produce_alg_info_php)
    PHP_FE(vscf_kdf2_restore_alg_info_php, arginfo_vscf_kdf2_restore_alg_info_php)
    PHP_FE(vscf_kdf2_derive_php, arginfo_vscf_kdf2_derive_php)
    PHP_FE(vscf_fake_random_new_php, arginfo_vscf_fake_random_new_php)
    PHP_FE(vscf_fake_random_delete_php, arginfo_vscf_fake_random_delete_php)
    PHP_FE(vscf_fake_random_setup_source_byte_php, arginfo_vscf_fake_random_setup_source_byte_php)
    PHP_FE(vscf_fake_random_setup_source_data_php, arginfo_vscf_fake_random_setup_source_data_php)
    PHP_FE(vscf_fake_random_random_php, arginfo_vscf_fake_random_random_php)
    PHP_FE(vscf_fake_random_reseed_php, arginfo_vscf_fake_random_reseed_php)
    PHP_FE(vscf_fake_random_is_strong_php, arginfo_vscf_fake_random_is_strong_php)
    PHP_FE(vscf_fake_random_gather_php, arginfo_vscf_fake_random_gather_php)
    PHP_FE(vscf_pkcs5_pbkdf2_new_php, arginfo_vscf_pkcs5_pbkdf2_new_php)
    PHP_FE(vscf_pkcs5_pbkdf2_delete_php, arginfo_vscf_pkcs5_pbkdf2_delete_php)
    PHP_FE(vscf_pkcs5_pbkdf2_setup_defaults_php, arginfo_vscf_pkcs5_pbkdf2_setup_defaults_php)
    PHP_FE(vscf_pkcs5_pbkdf2_alg_id_php, arginfo_vscf_pkcs5_pbkdf2_alg_id_php)
    PHP_FE(vscf_pkcs5_pbkdf2_produce_alg_info_php, arginfo_vscf_pkcs5_pbkdf2_produce_alg_info_php)
    PHP_FE(vscf_pkcs5_pbkdf2_restore_alg_info_php, arginfo_vscf_pkcs5_pbkdf2_restore_alg_info_php)
    PHP_FE(vscf_pkcs5_pbkdf2_derive_php, arginfo_vscf_pkcs5_pbkdf2_derive_php)
    PHP_FE(vscf_pkcs5_pbkdf2_reset_php, arginfo_vscf_pkcs5_pbkdf2_reset_php)
    PHP_FE(vscf_pkcs5_pbkdf2_set_info_php, arginfo_vscf_pkcs5_pbkdf2_set_info_php)
    PHP_FE(vscf_pkcs5_pbes2_new_php, arginfo_vscf_pkcs5_pbes2_new_php)
    PHP_FE(vscf_pkcs5_pbes2_delete_php, arginfo_vscf_pkcs5_pbes2_delete_php)
    PHP_FE(vscf_pkcs5_pbes2_reset_php, arginfo_vscf_pkcs5_pbes2_reset_php)
    PHP_FE(vscf_pkcs5_pbes2_alg_id_php, arginfo_vscf_pkcs5_pbes2_alg_id_php)
    PHP_FE(vscf_pkcs5_pbes2_produce_alg_info_php, arginfo_vscf_pkcs5_pbes2_produce_alg_info_php)
    PHP_FE(vscf_pkcs5_pbes2_restore_alg_info_php, arginfo_vscf_pkcs5_pbes2_restore_alg_info_php)
    PHP_FE(vscf_pkcs5_pbes2_encrypt_php, arginfo_vscf_pkcs5_pbes2_encrypt_php)
    PHP_FE(vscf_pkcs5_pbes2_encrypted_len_php, arginfo_vscf_pkcs5_pbes2_encrypted_len_php)
    PHP_FE(vscf_pkcs5_pbes2_precise_encrypted_len_php, arginfo_vscf_pkcs5_pbes2_precise_encrypted_len_php)
    PHP_FE(vscf_pkcs5_pbes2_decrypt_php, arginfo_vscf_pkcs5_pbes2_decrypt_php)
    PHP_FE(vscf_pkcs5_pbes2_decrypted_len_php, arginfo_vscf_pkcs5_pbes2_decrypted_len_php)
    PHP_FE(vscf_seed_entropy_source_new_php, arginfo_vscf_seed_entropy_source_new_php)
    PHP_FE(vscf_seed_entropy_source_delete_php, arginfo_vscf_seed_entropy_source_delete_php)
    PHP_FE(vscf_seed_entropy_source_reset_seed_php, arginfo_vscf_seed_entropy_source_reset_seed_php)
    PHP_FE(vscf_seed_entropy_source_is_strong_php, arginfo_vscf_seed_entropy_source_is_strong_php)
    PHP_FE(vscf_seed_entropy_source_gather_php, arginfo_vscf_seed_entropy_source_gather_php)
    PHP_FE(vscf_key_material_rng_new_php, arginfo_vscf_key_material_rng_new_php)
    PHP_FE(vscf_key_material_rng_delete_php, arginfo_vscf_key_material_rng_delete_php)
    PHP_FE(vscf_key_material_rng_reset_key_material_php, arginfo_vscf_key_material_rng_reset_key_material_php)
    PHP_FE(vscf_key_material_rng_random_php, arginfo_vscf_key_material_rng_random_php)
    PHP_FE(vscf_key_material_rng_reseed_php, arginfo_vscf_key_material_rng_reseed_php)
    PHP_FE(vscf_raw_public_key_new_php, arginfo_vscf_raw_public_key_new_php)
    PHP_FE(vscf_raw_public_key_delete_php, arginfo_vscf_raw_public_key_delete_php)
    PHP_FE(vscf_raw_public_key_data_php, arginfo_vscf_raw_public_key_data_php)
    PHP_FE(vscf_raw_public_key_alg_id_php, arginfo_vscf_raw_public_key_alg_id_php)
    PHP_FE(vscf_raw_public_key_alg_info_php, arginfo_vscf_raw_public_key_alg_info_php)
    PHP_FE(vscf_raw_public_key_len_php, arginfo_vscf_raw_public_key_len_php)
    PHP_FE(vscf_raw_public_key_bitlen_php, arginfo_vscf_raw_public_key_bitlen_php)
    PHP_FE(vscf_raw_public_key_is_valid_php, arginfo_vscf_raw_public_key_is_valid_php)
    PHP_FE(vscf_raw_private_key_new_php, arginfo_vscf_raw_private_key_new_php)
    PHP_FE(vscf_raw_private_key_delete_php, arginfo_vscf_raw_private_key_delete_php)
    PHP_FE(vscf_raw_private_key_data_php, arginfo_vscf_raw_private_key_data_php)
    PHP_FE(vscf_raw_private_key_has_public_key_php, arginfo_vscf_raw_private_key_has_public_key_php)
    PHP_FE(vscf_raw_private_key_set_public_key_php, arginfo_vscf_raw_private_key_set_public_key_php)
    PHP_FE(vscf_raw_private_key_get_public_key_php, arginfo_vscf_raw_private_key_get_public_key_php)
    PHP_FE(vscf_raw_private_key_alg_id_php, arginfo_vscf_raw_private_key_alg_id_php)
    PHP_FE(vscf_raw_private_key_alg_info_php, arginfo_vscf_raw_private_key_alg_info_php)
    PHP_FE(vscf_raw_private_key_len_php, arginfo_vscf_raw_private_key_len_php)
    PHP_FE(vscf_raw_private_key_bitlen_php, arginfo_vscf_raw_private_key_bitlen_php)
    PHP_FE(vscf_raw_private_key_is_valid_php, arginfo_vscf_raw_private_key_is_valid_php)
    PHP_FE(vscf_raw_private_key_extract_public_key_php, arginfo_vscf_raw_private_key_extract_public_key_php)
    PHP_FE(vscf_pkcs8_serializer_new_php, arginfo_vscf_pkcs8_serializer_new_php)
    PHP_FE(vscf_pkcs8_serializer_delete_php, arginfo_vscf_pkcs8_serializer_delete_php)
    PHP_FE(vscf_pkcs8_serializer_setup_defaults_php, arginfo_vscf_pkcs8_serializer_setup_defaults_php)
    PHP_FE(vscf_pkcs8_serializer_serialize_public_key_inplace_php, arginfo_vscf_pkcs8_serializer_serialize_public_key_inplace_php)
    PHP_FE(vscf_pkcs8_serializer_serialize_private_key_inplace_php, arginfo_vscf_pkcs8_serializer_serialize_private_key_inplace_php)
    PHP_FE(vscf_pkcs8_serializer_serialized_public_key_len_php, arginfo_vscf_pkcs8_serializer_serialized_public_key_len_php)
    PHP_FE(vscf_pkcs8_serializer_serialize_public_key_php, arginfo_vscf_pkcs8_serializer_serialize_public_key_php)
    PHP_FE(vscf_pkcs8_serializer_serialized_private_key_len_php, arginfo_vscf_pkcs8_serializer_serialized_private_key_len_php)
    PHP_FE(vscf_pkcs8_serializer_serialize_private_key_php, arginfo_vscf_pkcs8_serializer_serialize_private_key_php)
    PHP_FE(vscf_sec1_serializer_new_php, arginfo_vscf_sec1_serializer_new_php)
    PHP_FE(vscf_sec1_serializer_delete_php, arginfo_vscf_sec1_serializer_delete_php)
    PHP_FE(vscf_sec1_serializer_setup_defaults_php, arginfo_vscf_sec1_serializer_setup_defaults_php)
    PHP_FE(vscf_sec1_serializer_serialize_public_key_inplace_php, arginfo_vscf_sec1_serializer_serialize_public_key_inplace_php)
    PHP_FE(vscf_sec1_serializer_serialize_private_key_inplace_php, arginfo_vscf_sec1_serializer_serialize_private_key_inplace_php)
    PHP_FE(vscf_sec1_serializer_serialized_public_key_len_php, arginfo_vscf_sec1_serializer_serialized_public_key_len_php)
    PHP_FE(vscf_sec1_serializer_serialize_public_key_php, arginfo_vscf_sec1_serializer_serialize_public_key_php)
    PHP_FE(vscf_sec1_serializer_serialized_private_key_len_php, arginfo_vscf_sec1_serializer_serialized_private_key_len_php)
    PHP_FE(vscf_sec1_serializer_serialize_private_key_php, arginfo_vscf_sec1_serializer_serialize_private_key_php)
    PHP_FE(vscf_key_asn1_serializer_new_php, arginfo_vscf_key_asn1_serializer_new_php)
    PHP_FE(vscf_key_asn1_serializer_delete_php, arginfo_vscf_key_asn1_serializer_delete_php)
    PHP_FE(vscf_key_asn1_serializer_setup_defaults_php, arginfo_vscf_key_asn1_serializer_setup_defaults_php)
    PHP_FE(vscf_key_asn1_serializer_serialize_public_key_inplace_php, arginfo_vscf_key_asn1_serializer_serialize_public_key_inplace_php)
    PHP_FE(vscf_key_asn1_serializer_serialize_private_key_inplace_php, arginfo_vscf_key_asn1_serializer_serialize_private_key_inplace_php)
    PHP_FE(vscf_key_asn1_serializer_serialized_public_key_len_php, arginfo_vscf_key_asn1_serializer_serialized_public_key_len_php)
    PHP_FE(vscf_key_asn1_serializer_serialize_public_key_php, arginfo_vscf_key_asn1_serializer_serialize_public_key_php)
    PHP_FE(vscf_key_asn1_serializer_serialized_private_key_len_php, arginfo_vscf_key_asn1_serializer_serialized_private_key_len_php)
    PHP_FE(vscf_key_asn1_serializer_serialize_private_key_php, arginfo_vscf_key_asn1_serializer_serialize_private_key_php)
    PHP_FE(vscf_key_asn1_deserializer_new_php, arginfo_vscf_key_asn1_deserializer_new_php)
    PHP_FE(vscf_key_asn1_deserializer_delete_php, arginfo_vscf_key_asn1_deserializer_delete_php)
    PHP_FE(vscf_key_asn1_deserializer_setup_defaults_php, arginfo_vscf_key_asn1_deserializer_setup_defaults_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_public_key_inplace_php, arginfo_vscf_key_asn1_deserializer_deserialize_public_key_inplace_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_private_key_inplace_php, arginfo_vscf_key_asn1_deserializer_deserialize_private_key_inplace_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_public_key_php, arginfo_vscf_key_asn1_deserializer_deserialize_public_key_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_private_key_php, arginfo_vscf_key_asn1_deserializer_deserialize_private_key_php)
    PHP_FE(vscf_ed25519_new_php, arginfo_vscf_ed25519_new_php)
    PHP_FE(vscf_ed25519_delete_php, arginfo_vscf_ed25519_delete_php)
    PHP_FE(vscf_ed25519_setup_defaults_php, arginfo_vscf_ed25519_setup_defaults_php)
    PHP_FE(vscf_ed25519_generate_key_php, arginfo_vscf_ed25519_generate_key_php)
    PHP_FE(vscf_ed25519_alg_id_php, arginfo_vscf_ed25519_alg_id_php)
    PHP_FE(vscf_ed25519_produce_alg_info_php, arginfo_vscf_ed25519_produce_alg_info_php)
    PHP_FE(vscf_ed25519_restore_alg_info_php, arginfo_vscf_ed25519_restore_alg_info_php)
    PHP_FE(vscf_ed25519_generate_ephemeral_key_php, arginfo_vscf_ed25519_generate_ephemeral_key_php)
    PHP_FE(vscf_ed25519_import_public_key_php, arginfo_vscf_ed25519_import_public_key_php)
    PHP_FE(vscf_ed25519_export_public_key_php, arginfo_vscf_ed25519_export_public_key_php)
    PHP_FE(vscf_ed25519_import_private_key_php, arginfo_vscf_ed25519_import_private_key_php)
    PHP_FE(vscf_ed25519_export_private_key_php, arginfo_vscf_ed25519_export_private_key_php)
    PHP_FE(vscf_ed25519_can_encrypt_php, arginfo_vscf_ed25519_can_encrypt_php)
    PHP_FE(vscf_ed25519_encrypted_len_php, arginfo_vscf_ed25519_encrypted_len_php)
    PHP_FE(vscf_ed25519_encrypt_php, arginfo_vscf_ed25519_encrypt_php)
    PHP_FE(vscf_ed25519_can_decrypt_php, arginfo_vscf_ed25519_can_decrypt_php)
    PHP_FE(vscf_ed25519_decrypted_len_php, arginfo_vscf_ed25519_decrypted_len_php)
    PHP_FE(vscf_ed25519_decrypt_php, arginfo_vscf_ed25519_decrypt_php)
    PHP_FE(vscf_ed25519_can_sign_php, arginfo_vscf_ed25519_can_sign_php)
    PHP_FE(vscf_ed25519_signature_len_php, arginfo_vscf_ed25519_signature_len_php)
    PHP_FE(vscf_ed25519_sign_hash_php, arginfo_vscf_ed25519_sign_hash_php)
    PHP_FE(vscf_ed25519_can_verify_php, arginfo_vscf_ed25519_can_verify_php)
    PHP_FE(vscf_ed25519_verify_hash_php, arginfo_vscf_ed25519_verify_hash_php)
    PHP_FE(vscf_ed25519_compute_shared_key_php, arginfo_vscf_ed25519_compute_shared_key_php)
    PHP_FE(vscf_ed25519_shared_key_len_php, arginfo_vscf_ed25519_shared_key_len_php)
    PHP_FE(vscf_curve25519_new_php, arginfo_vscf_curve25519_new_php)
    PHP_FE(vscf_curve25519_delete_php, arginfo_vscf_curve25519_delete_php)
    PHP_FE(vscf_curve25519_setup_defaults_php, arginfo_vscf_curve25519_setup_defaults_php)
    PHP_FE(vscf_curve25519_generate_key_php, arginfo_vscf_curve25519_generate_key_php)
    PHP_FE(vscf_curve25519_alg_id_php, arginfo_vscf_curve25519_alg_id_php)
    PHP_FE(vscf_curve25519_produce_alg_info_php, arginfo_vscf_curve25519_produce_alg_info_php)
    PHP_FE(vscf_curve25519_restore_alg_info_php, arginfo_vscf_curve25519_restore_alg_info_php)
    PHP_FE(vscf_curve25519_generate_ephemeral_key_php, arginfo_vscf_curve25519_generate_ephemeral_key_php)
    PHP_FE(vscf_curve25519_import_public_key_php, arginfo_vscf_curve25519_import_public_key_php)
    PHP_FE(vscf_curve25519_export_public_key_php, arginfo_vscf_curve25519_export_public_key_php)
    PHP_FE(vscf_curve25519_import_private_key_php, arginfo_vscf_curve25519_import_private_key_php)
    PHP_FE(vscf_curve25519_export_private_key_php, arginfo_vscf_curve25519_export_private_key_php)
    PHP_FE(vscf_curve25519_can_encrypt_php, arginfo_vscf_curve25519_can_encrypt_php)
    PHP_FE(vscf_curve25519_encrypted_len_php, arginfo_vscf_curve25519_encrypted_len_php)
    PHP_FE(vscf_curve25519_encrypt_php, arginfo_vscf_curve25519_encrypt_php)
    PHP_FE(vscf_curve25519_can_decrypt_php, arginfo_vscf_curve25519_can_decrypt_php)
    PHP_FE(vscf_curve25519_decrypted_len_php, arginfo_vscf_curve25519_decrypted_len_php)
    PHP_FE(vscf_curve25519_decrypt_php, arginfo_vscf_curve25519_decrypt_php)
    PHP_FE(vscf_curve25519_compute_shared_key_php, arginfo_vscf_curve25519_compute_shared_key_php)
    PHP_FE(vscf_curve25519_shared_key_len_php, arginfo_vscf_curve25519_shared_key_len_php)
    PHP_FE(vscf_simple_alg_info_new_php, arginfo_vscf_simple_alg_info_new_php)
    PHP_FE(vscf_simple_alg_info_delete_php, arginfo_vscf_simple_alg_info_delete_php)
    PHP_FE(vscf_simple_alg_info_alg_id_php, arginfo_vscf_simple_alg_info_alg_id_php)
    PHP_FE(vscf_hash_based_alg_info_new_php, arginfo_vscf_hash_based_alg_info_new_php)
    PHP_FE(vscf_hash_based_alg_info_delete_php, arginfo_vscf_hash_based_alg_info_delete_php)
    PHP_FE(vscf_hash_based_alg_info_hash_alg_info_php, arginfo_vscf_hash_based_alg_info_hash_alg_info_php)
    PHP_FE(vscf_hash_based_alg_info_alg_id_php, arginfo_vscf_hash_based_alg_info_alg_id_php)
    PHP_FE(vscf_cipher_alg_info_new_php, arginfo_vscf_cipher_alg_info_new_php)
    PHP_FE(vscf_cipher_alg_info_delete_php, arginfo_vscf_cipher_alg_info_delete_php)
    PHP_FE(vscf_cipher_alg_info_nonce_php, arginfo_vscf_cipher_alg_info_nonce_php)
    PHP_FE(vscf_cipher_alg_info_alg_id_php, arginfo_vscf_cipher_alg_info_alg_id_php)
    PHP_FE(vscf_salted_kdf_alg_info_new_php, arginfo_vscf_salted_kdf_alg_info_new_php)
    PHP_FE(vscf_salted_kdf_alg_info_delete_php, arginfo_vscf_salted_kdf_alg_info_delete_php)
    PHP_FE(vscf_salted_kdf_alg_info_hash_alg_info_php, arginfo_vscf_salted_kdf_alg_info_hash_alg_info_php)
    PHP_FE(vscf_salted_kdf_alg_info_salt_php, arginfo_vscf_salted_kdf_alg_info_salt_php)
    PHP_FE(vscf_salted_kdf_alg_info_iteration_count_php, arginfo_vscf_salted_kdf_alg_info_iteration_count_php)
    PHP_FE(vscf_salted_kdf_alg_info_alg_id_php, arginfo_vscf_salted_kdf_alg_info_alg_id_php)
    PHP_FE(vscf_pbe_alg_info_new_php, arginfo_vscf_pbe_alg_info_new_php)
    PHP_FE(vscf_pbe_alg_info_delete_php, arginfo_vscf_pbe_alg_info_delete_php)
    PHP_FE(vscf_pbe_alg_info_kdf_alg_info_php, arginfo_vscf_pbe_alg_info_kdf_alg_info_php)
    PHP_FE(vscf_pbe_alg_info_cipher_alg_info_php, arginfo_vscf_pbe_alg_info_cipher_alg_info_php)
    PHP_FE(vscf_pbe_alg_info_alg_id_php, arginfo_vscf_pbe_alg_info_alg_id_php)
    PHP_FE(vscf_ecc_alg_info_new_php, arginfo_vscf_ecc_alg_info_new_php)
    PHP_FE(vscf_ecc_alg_info_delete_php, arginfo_vscf_ecc_alg_info_delete_php)
    PHP_FE(vscf_ecc_alg_info_key_id_php, arginfo_vscf_ecc_alg_info_key_id_php)
    PHP_FE(vscf_ecc_alg_info_domain_id_php, arginfo_vscf_ecc_alg_info_domain_id_php)
    PHP_FE(vscf_ecc_alg_info_alg_id_php, arginfo_vscf_ecc_alg_info_alg_id_php)
    PHP_FE(vscf_alg_info_der_serializer_new_php, arginfo_vscf_alg_info_der_serializer_new_php)
    PHP_FE(vscf_alg_info_der_serializer_delete_php, arginfo_vscf_alg_info_der_serializer_delete_php)
    PHP_FE(vscf_alg_info_der_serializer_setup_defaults_php, arginfo_vscf_alg_info_der_serializer_setup_defaults_php)
    PHP_FE(vscf_alg_info_der_serializer_serialize_inplace_php, arginfo_vscf_alg_info_der_serializer_serialize_inplace_php)
    PHP_FE(vscf_alg_info_der_serializer_serialized_len_php, arginfo_vscf_alg_info_der_serializer_serialized_len_php)
    PHP_FE(vscf_alg_info_der_serializer_serialize_php, arginfo_vscf_alg_info_der_serializer_serialize_php)
    PHP_FE(vscf_alg_info_der_deserializer_new_php, arginfo_vscf_alg_info_der_deserializer_new_php)
    PHP_FE(vscf_alg_info_der_deserializer_delete_php, arginfo_vscf_alg_info_der_deserializer_delete_php)
    PHP_FE(vscf_alg_info_der_deserializer_setup_defaults_php, arginfo_vscf_alg_info_der_deserializer_setup_defaults_php)
    PHP_FE(vscf_alg_info_der_deserializer_deserialize_inplace_php, arginfo_vscf_alg_info_der_deserializer_deserialize_inplace_php)
    PHP_FE(vscf_alg_info_der_deserializer_deserialize_php, arginfo_vscf_alg_info_der_deserializer_deserialize_php)
    PHP_FE(vscf_message_info_der_serializer_new_php, arginfo_vscf_message_info_der_serializer_new_php)
    PHP_FE(vscf_message_info_der_serializer_delete_php, arginfo_vscf_message_info_der_serializer_delete_php)
    PHP_FE(vscf_message_info_der_serializer_setup_defaults_php, arginfo_vscf_message_info_der_serializer_setup_defaults_php)
    PHP_FE(vscf_message_info_der_serializer_serialized_len_php, arginfo_vscf_message_info_der_serializer_serialized_len_php)
    PHP_FE(vscf_message_info_der_serializer_serialize_php, arginfo_vscf_message_info_der_serializer_serialize_php)
    PHP_FE(vscf_message_info_der_serializer_read_prefix_php, arginfo_vscf_message_info_der_serializer_read_prefix_php)
    PHP_FE(vscf_message_info_der_serializer_deserialize_php, arginfo_vscf_message_info_der_serializer_deserialize_php)
    PHP_FE(vscf_message_info_der_serializer_serialized_footer_len_php, arginfo_vscf_message_info_der_serializer_serialized_footer_len_php)
    PHP_FE(vscf_message_info_der_serializer_serialize_footer_php, arginfo_vscf_message_info_der_serializer_serialize_footer_php)
    PHP_FE(vscf_message_info_der_serializer_deserialize_footer_php, arginfo_vscf_message_info_der_serializer_deserialize_footer_php)
    PHP_FE_END
};

//
// Extension module definition
//
zend_module_entry vscf_foundation_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCF_FOUNDATION_PHP_EXTNAME,
    vscf_foundation_php_functions,
    PHP_MINIT(vscf_foundation_php),
    PHP_MSHUTDOWN(vscf_foundation_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCF_FOUNDATION_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscf_foundation_php)

//
// Extension init functions definition
//
static void vscf_message_info_dtor_php(zend_resource *rsrc) {
    vscf_message_info_delete((vscf_message_info_t *)rsrc->ptr);
}
static void vscf_key_recipient_info_dtor_php(zend_resource *rsrc) {
    vscf_key_recipient_info_delete((vscf_key_recipient_info_t *)rsrc->ptr);
}
static void vscf_key_recipient_info_list_dtor_php(zend_resource *rsrc) {
    vscf_key_recipient_info_list_delete((vscf_key_recipient_info_list_t *)rsrc->ptr);
}
static void vscf_password_recipient_info_dtor_php(zend_resource *rsrc) {
    vscf_password_recipient_info_delete((vscf_password_recipient_info_t *)rsrc->ptr);
}
static void vscf_password_recipient_info_list_dtor_php(zend_resource *rsrc) {
    vscf_password_recipient_info_list_delete((vscf_password_recipient_info_list_t *)rsrc->ptr);
}
static void vscf_ecies_dtor_php(zend_resource *rsrc) {
    vscf_ecies_delete((vscf_ecies_t *)rsrc->ptr);
}
static void vscf_recipient_cipher_dtor_php(zend_resource *rsrc) {
    vscf_recipient_cipher_delete((vscf_recipient_cipher_t *)rsrc->ptr);
}
static void vscf_message_info_custom_params_dtor_php(zend_resource *rsrc) {
    vscf_message_info_custom_params_delete((vscf_message_info_custom_params_t *)rsrc->ptr);
}
static void vscf_key_provider_dtor_php(zend_resource *rsrc) {
    vscf_key_provider_delete((vscf_key_provider_t *)rsrc->ptr);
}
static void vscf_signer_dtor_php(zend_resource *rsrc) {
    vscf_signer_delete((vscf_signer_t *)rsrc->ptr);
}
static void vscf_verifier_dtor_php(zend_resource *rsrc) {
    vscf_verifier_delete((vscf_verifier_t *)rsrc->ptr);
}
static void vscf_brainkey_client_dtor_php(zend_resource *rsrc) {
    vscf_brainkey_client_delete((vscf_brainkey_client_t *)rsrc->ptr);
}
static void vscf_brainkey_server_dtor_php(zend_resource *rsrc) {
    vscf_brainkey_server_delete((vscf_brainkey_server_t *)rsrc->ptr);
}
static void vscf_group_session_message_dtor_php(zend_resource *rsrc) {
    vscf_group_session_message_delete((vscf_group_session_message_t *)rsrc->ptr);
}
static void vscf_group_session_ticket_dtor_php(zend_resource *rsrc) {
    vscf_group_session_ticket_delete((vscf_group_session_ticket_t *)rsrc->ptr);
}
static void vscf_group_session_dtor_php(zend_resource *rsrc) {
    vscf_group_session_delete((vscf_group_session_t *)rsrc->ptr);
}
static void vscf_message_info_editor_dtor_php(zend_resource *rsrc) {
    vscf_message_info_editor_delete((vscf_message_info_editor_t *)rsrc->ptr);
}
static void vscf_signer_info_dtor_php(zend_resource *rsrc) {
    vscf_signer_info_delete((vscf_signer_info_t *)rsrc->ptr);
}
static void vscf_signer_info_list_dtor_php(zend_resource *rsrc) {
    vscf_signer_info_list_delete((vscf_signer_info_list_t *)rsrc->ptr);
}
static void vscf_message_info_footer_dtor_php(zend_resource *rsrc) {
    vscf_message_info_footer_delete((vscf_message_info_footer_t *)rsrc->ptr);
}
static void vscf_signed_data_info_dtor_php(zend_resource *rsrc) {
    vscf_signed_data_info_delete((vscf_signed_data_info_t *)rsrc->ptr);
}
static void vscf_footer_info_dtor_php(zend_resource *rsrc) {
    vscf_footer_info_delete((vscf_footer_info_t *)rsrc->ptr);
}
static void vscf_sha224_dtor_php(zend_resource *rsrc) {
    vscf_sha224_delete((vscf_sha224_t *)rsrc->ptr);
}
static void vscf_sha256_dtor_php(zend_resource *rsrc) {
    vscf_sha256_delete((vscf_sha256_t *)rsrc->ptr);
}
static void vscf_sha384_dtor_php(zend_resource *rsrc) {
    vscf_sha384_delete((vscf_sha384_t *)rsrc->ptr);
}
static void vscf_sha512_dtor_php(zend_resource *rsrc) {
    vscf_sha512_delete((vscf_sha512_t *)rsrc->ptr);
}
static void vscf_aes256_gcm_dtor_php(zend_resource *rsrc) {
    vscf_aes256_gcm_delete((vscf_aes256_gcm_t *)rsrc->ptr);
}
static void vscf_aes256_cbc_dtor_php(zend_resource *rsrc) {
    vscf_aes256_cbc_delete((vscf_aes256_cbc_t *)rsrc->ptr);
}
static void vscf_asn1rd_dtor_php(zend_resource *rsrc) {
    vscf_asn1rd_delete((vscf_asn1rd_t *)rsrc->ptr);
}
static void vscf_asn1wr_dtor_php(zend_resource *rsrc) {
    vscf_asn1wr_delete((vscf_asn1wr_t *)rsrc->ptr);
}
static void vscf_rsa_public_key_dtor_php(zend_resource *rsrc) {
    vscf_rsa_public_key_delete((vscf_rsa_public_key_t *)rsrc->ptr);
}
static void vscf_rsa_private_key_dtor_php(zend_resource *rsrc) {
    vscf_rsa_private_key_delete((vscf_rsa_private_key_t *)rsrc->ptr);
}
static void vscf_rsa_dtor_php(zend_resource *rsrc) {
    vscf_rsa_delete((vscf_rsa_t *)rsrc->ptr);
}
static void vscf_ecc_public_key_dtor_php(zend_resource *rsrc) {
    vscf_ecc_public_key_delete((vscf_ecc_public_key_t *)rsrc->ptr);
}
static void vscf_ecc_private_key_dtor_php(zend_resource *rsrc) {
    vscf_ecc_private_key_delete((vscf_ecc_private_key_t *)rsrc->ptr);
}
static void vscf_ecc_dtor_php(zend_resource *rsrc) {
    vscf_ecc_delete((vscf_ecc_t *)rsrc->ptr);
}
static void vscf_entropy_accumulator_dtor_php(zend_resource *rsrc) {
    vscf_entropy_accumulator_delete((vscf_entropy_accumulator_t *)rsrc->ptr);
}
static void vscf_ctr_drbg_dtor_php(zend_resource *rsrc) {
    vscf_ctr_drbg_delete((vscf_ctr_drbg_t *)rsrc->ptr);
}
static void vscf_hmac_dtor_php(zend_resource *rsrc) {
    vscf_hmac_delete((vscf_hmac_t *)rsrc->ptr);
}
static void vscf_hkdf_dtor_php(zend_resource *rsrc) {
    vscf_hkdf_delete((vscf_hkdf_t *)rsrc->ptr);
}
static void vscf_kdf1_dtor_php(zend_resource *rsrc) {
    vscf_kdf1_delete((vscf_kdf1_t *)rsrc->ptr);
}
static void vscf_kdf2_dtor_php(zend_resource *rsrc) {
    vscf_kdf2_delete((vscf_kdf2_t *)rsrc->ptr);
}
static void vscf_fake_random_dtor_php(zend_resource *rsrc) {
    vscf_fake_random_delete((vscf_fake_random_t *)rsrc->ptr);
}
static void vscf_pkcs5_pbkdf2_dtor_php(zend_resource *rsrc) {
    vscf_pkcs5_pbkdf2_delete((vscf_pkcs5_pbkdf2_t *)rsrc->ptr);
}
static void vscf_pkcs5_pbes2_dtor_php(zend_resource *rsrc) {
    vscf_pkcs5_pbes2_delete((vscf_pkcs5_pbes2_t *)rsrc->ptr);
}
static void vscf_seed_entropy_source_dtor_php(zend_resource *rsrc) {
    vscf_seed_entropy_source_delete((vscf_seed_entropy_source_t *)rsrc->ptr);
}
static void vscf_key_material_rng_dtor_php(zend_resource *rsrc) {
    vscf_key_material_rng_delete((vscf_key_material_rng_t *)rsrc->ptr);
}
static void vscf_raw_public_key_dtor_php(zend_resource *rsrc) {
    vscf_raw_public_key_delete((vscf_raw_public_key_t *)rsrc->ptr);
}
static void vscf_raw_private_key_dtor_php(zend_resource *rsrc) {
    vscf_raw_private_key_delete((vscf_raw_private_key_t *)rsrc->ptr);
}
static void vscf_pkcs8_serializer_dtor_php(zend_resource *rsrc) {
    vscf_pkcs8_serializer_delete((vscf_pkcs8_serializer_t *)rsrc->ptr);
}
static void vscf_sec1_serializer_dtor_php(zend_resource *rsrc) {
    vscf_sec1_serializer_delete((vscf_sec1_serializer_t *)rsrc->ptr);
}
static void vscf_key_asn1_serializer_dtor_php(zend_resource *rsrc) {
    vscf_key_asn1_serializer_delete((vscf_key_asn1_serializer_t *)rsrc->ptr);
}
static void vscf_key_asn1_deserializer_dtor_php(zend_resource *rsrc) {
    vscf_key_asn1_deserializer_delete((vscf_key_asn1_deserializer_t *)rsrc->ptr);
}
static void vscf_ed25519_dtor_php(zend_resource *rsrc) {
    vscf_ed25519_delete((vscf_ed25519_t *)rsrc->ptr);
}
static void vscf_curve25519_dtor_php(zend_resource *rsrc) {
    vscf_curve25519_delete((vscf_curve25519_t *)rsrc->ptr);
}
static void vscf_simple_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_simple_alg_info_delete((vscf_simple_alg_info_t *)rsrc->ptr);
}
static void vscf_hash_based_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_hash_based_alg_info_delete((vscf_hash_based_alg_info_t *)rsrc->ptr);
}
static void vscf_cipher_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_cipher_alg_info_delete((vscf_cipher_alg_info_t *)rsrc->ptr);
}
static void vscf_salted_kdf_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_salted_kdf_alg_info_delete((vscf_salted_kdf_alg_info_t *)rsrc->ptr);
}
static void vscf_pbe_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_pbe_alg_info_delete((vscf_pbe_alg_info_t *)rsrc->ptr);
}
static void vscf_ecc_alg_info_dtor_php(zend_resource *rsrc) {
    vscf_ecc_alg_info_delete((vscf_ecc_alg_info_t *)rsrc->ptr);
}
static void vscf_alg_info_der_serializer_dtor_php(zend_resource *rsrc) {
    vscf_alg_info_der_serializer_delete((vscf_alg_info_der_serializer_t *)rsrc->ptr);
}
static void vscf_alg_info_der_deserializer_dtor_php(zend_resource *rsrc) {
    vscf_alg_info_der_deserializer_delete((vscf_alg_info_der_deserializer_t *)rsrc->ptr);
}
static void vscf_message_info_der_serializer_dtor_php(zend_resource *rsrc) {
    vscf_message_info_der_serializer_delete((vscf_message_info_der_serializer_t *)rsrc->ptr);
}
PHP_MINIT_FUNCTION(vscf_foundation_php) {
    le_vscf_message_info_t = zend_register_list_destructors_ex(vscf_message_info_dtor_php, NULL, VSCF_MESSAGE_INFO_PHP_RES_NAME, module_number);
    le_vscf_key_recipient_info_t = zend_register_list_destructors_ex(vscf_key_recipient_info_dtor_php, NULL, VSCF_KEY_RECIPIENT_INFO_PHP_RES_NAME, module_number);
    le_vscf_key_recipient_info_list_t = zend_register_list_destructors_ex(vscf_key_recipient_info_list_dtor_php, NULL, VSCF_KEY_RECIPIENT_INFO_LIST_PHP_RES_NAME, module_number);
    le_vscf_password_recipient_info_t = zend_register_list_destructors_ex(vscf_password_recipient_info_dtor_php, NULL, VSCF_PASSWORD_RECIPIENT_INFO_PHP_RES_NAME, module_number);
    le_vscf_password_recipient_info_list_t = zend_register_list_destructors_ex(vscf_password_recipient_info_list_dtor_php, NULL, VSCF_PASSWORD_RECIPIENT_INFO_LIST_PHP_RES_NAME, module_number);
    le_vscf_ecies_t = zend_register_list_destructors_ex(vscf_ecies_dtor_php, NULL, VSCF_ECIES_PHP_RES_NAME, module_number);
    le_vscf_recipient_cipher_t = zend_register_list_destructors_ex(vscf_recipient_cipher_dtor_php, NULL, VSCF_RECIPIENT_CIPHER_PHP_RES_NAME, module_number);
    le_vscf_message_info_custom_params_t = zend_register_list_destructors_ex(vscf_message_info_custom_params_dtor_php, NULL, VSCF_MESSAGE_INFO_CUSTOM_PARAMS_PHP_RES_NAME, module_number);
    le_vscf_key_provider_t = zend_register_list_destructors_ex(vscf_key_provider_dtor_php, NULL, VSCF_KEY_PROVIDER_PHP_RES_NAME, module_number);
    le_vscf_signer_t = zend_register_list_destructors_ex(vscf_signer_dtor_php, NULL, VSCF_SIGNER_PHP_RES_NAME, module_number);
    le_vscf_verifier_t = zend_register_list_destructors_ex(vscf_verifier_dtor_php, NULL, VSCF_VERIFIER_PHP_RES_NAME, module_number);
    le_vscf_brainkey_client_t = zend_register_list_destructors_ex(vscf_brainkey_client_dtor_php, NULL, VSCF_BRAINKEY_CLIENT_PHP_RES_NAME, module_number);
    le_vscf_brainkey_server_t = zend_register_list_destructors_ex(vscf_brainkey_server_dtor_php, NULL, VSCF_BRAINKEY_SERVER_PHP_RES_NAME, module_number);
    le_vscf_group_session_message_t = zend_register_list_destructors_ex(vscf_group_session_message_dtor_php, NULL, VSCF_GROUP_SESSION_MESSAGE_PHP_RES_NAME, module_number);
    le_vscf_group_session_ticket_t = zend_register_list_destructors_ex(vscf_group_session_ticket_dtor_php, NULL, VSCF_GROUP_SESSION_TICKET_PHP_RES_NAME, module_number);
    le_vscf_group_session_t = zend_register_list_destructors_ex(vscf_group_session_dtor_php, NULL, VSCF_GROUP_SESSION_PHP_RES_NAME, module_number);
    le_vscf_message_info_editor_t = zend_register_list_destructors_ex(vscf_message_info_editor_dtor_php, NULL, VSCF_MESSAGE_INFO_EDITOR_PHP_RES_NAME, module_number);
    le_vscf_signer_info_t = zend_register_list_destructors_ex(vscf_signer_info_dtor_php, NULL, VSCF_SIGNER_INFO_PHP_RES_NAME, module_number);
    le_vscf_signer_info_list_t = zend_register_list_destructors_ex(vscf_signer_info_list_dtor_php, NULL, VSCF_SIGNER_INFO_LIST_PHP_RES_NAME, module_number);
    le_vscf_message_info_footer_t = zend_register_list_destructors_ex(vscf_message_info_footer_dtor_php, NULL, VSCF_MESSAGE_INFO_FOOTER_PHP_RES_NAME, module_number);
    le_vscf_signed_data_info_t = zend_register_list_destructors_ex(vscf_signed_data_info_dtor_php, NULL, VSCF_SIGNED_DATA_INFO_PHP_RES_NAME, module_number);
    le_vscf_footer_info_t = zend_register_list_destructors_ex(vscf_footer_info_dtor_php, NULL, VSCF_FOOTER_INFO_PHP_RES_NAME, module_number);
    le_vscf_sha224_t = zend_register_list_destructors_ex(vscf_sha224_dtor_php, NULL, VSCF_SHA224_PHP_RES_NAME, module_number);
    le_vscf_sha256_t = zend_register_list_destructors_ex(vscf_sha256_dtor_php, NULL, VSCF_SHA256_PHP_RES_NAME, module_number);
    le_vscf_sha384_t = zend_register_list_destructors_ex(vscf_sha384_dtor_php, NULL, VSCF_SHA384_PHP_RES_NAME, module_number);
    le_vscf_sha512_t = zend_register_list_destructors_ex(vscf_sha512_dtor_php, NULL, VSCF_SHA512_PHP_RES_NAME, module_number);
    le_vscf_aes256_gcm_t = zend_register_list_destructors_ex(vscf_aes256_gcm_dtor_php, NULL, VSCF_AES256_GCM_PHP_RES_NAME, module_number);
    le_vscf_aes256_cbc_t = zend_register_list_destructors_ex(vscf_aes256_cbc_dtor_php, NULL, VSCF_AES256_CBC_PHP_RES_NAME, module_number);
    le_vscf_asn1rd_t = zend_register_list_destructors_ex(vscf_asn1rd_dtor_php, NULL, VSCF_ASN1RD_PHP_RES_NAME, module_number);
    le_vscf_asn1wr_t = zend_register_list_destructors_ex(vscf_asn1wr_dtor_php, NULL, VSCF_ASN1WR_PHP_RES_NAME, module_number);
    le_vscf_rsa_public_key_t = zend_register_list_destructors_ex(vscf_rsa_public_key_dtor_php, NULL, VSCF_RSA_PUBLIC_KEY_PHP_RES_NAME, module_number);
    le_vscf_rsa_private_key_t = zend_register_list_destructors_ex(vscf_rsa_private_key_dtor_php, NULL, VSCF_RSA_PRIVATE_KEY_PHP_RES_NAME, module_number);
    le_vscf_rsa_t = zend_register_list_destructors_ex(vscf_rsa_dtor_php, NULL, VSCF_RSA_PHP_RES_NAME, module_number);
    le_vscf_ecc_public_key_t = zend_register_list_destructors_ex(vscf_ecc_public_key_dtor_php, NULL, VSCF_ECC_PUBLIC_KEY_PHP_RES_NAME, module_number);
    le_vscf_ecc_private_key_t = zend_register_list_destructors_ex(vscf_ecc_private_key_dtor_php, NULL, VSCF_ECC_PRIVATE_KEY_PHP_RES_NAME, module_number);
    le_vscf_ecc_t = zend_register_list_destructors_ex(vscf_ecc_dtor_php, NULL, VSCF_ECC_PHP_RES_NAME, module_number);
    le_vscf_entropy_accumulator_t = zend_register_list_destructors_ex(vscf_entropy_accumulator_dtor_php, NULL, VSCF_ENTROPY_ACCUMULATOR_PHP_RES_NAME, module_number);
    le_vscf_ctr_drbg_t = zend_register_list_destructors_ex(vscf_ctr_drbg_dtor_php, NULL, VSCF_CTR_DRBG_PHP_RES_NAME, module_number);
    le_vscf_hmac_t = zend_register_list_destructors_ex(vscf_hmac_dtor_php, NULL, VSCF_HMAC_PHP_RES_NAME, module_number);
    le_vscf_hkdf_t = zend_register_list_destructors_ex(vscf_hkdf_dtor_php, NULL, VSCF_HKDF_PHP_RES_NAME, module_number);
    le_vscf_kdf1_t = zend_register_list_destructors_ex(vscf_kdf1_dtor_php, NULL, VSCF_KDF1_PHP_RES_NAME, module_number);
    le_vscf_kdf2_t = zend_register_list_destructors_ex(vscf_kdf2_dtor_php, NULL, VSCF_KDF2_PHP_RES_NAME, module_number);
    le_vscf_fake_random_t = zend_register_list_destructors_ex(vscf_fake_random_dtor_php, NULL, VSCF_FAKE_RANDOM_PHP_RES_NAME, module_number);
    le_vscf_pkcs5_pbkdf2_t = zend_register_list_destructors_ex(vscf_pkcs5_pbkdf2_dtor_php, NULL, VSCF_PKCS5_PBKDF2_PHP_RES_NAME, module_number);
    le_vscf_pkcs5_pbes2_t = zend_register_list_destructors_ex(vscf_pkcs5_pbes2_dtor_php, NULL, VSCF_PKCS5_PBES2_PHP_RES_NAME, module_number);
    le_vscf_seed_entropy_source_t = zend_register_list_destructors_ex(vscf_seed_entropy_source_dtor_php, NULL, VSCF_SEED_ENTROPY_SOURCE_PHP_RES_NAME, module_number);
    le_vscf_key_material_rng_t = zend_register_list_destructors_ex(vscf_key_material_rng_dtor_php, NULL, VSCF_KEY_MATERIAL_RNG_PHP_RES_NAME, module_number);
    le_vscf_raw_public_key_t = zend_register_list_destructors_ex(vscf_raw_public_key_dtor_php, NULL, VSCF_RAW_PUBLIC_KEY_PHP_RES_NAME, module_number);
    le_vscf_raw_private_key_t = zend_register_list_destructors_ex(vscf_raw_private_key_dtor_php, NULL, VSCF_RAW_PRIVATE_KEY_PHP_RES_NAME, module_number);
    le_vscf_pkcs8_serializer_t = zend_register_list_destructors_ex(vscf_pkcs8_serializer_dtor_php, NULL, VSCF_PKCS8_SERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_sec1_serializer_t = zend_register_list_destructors_ex(vscf_sec1_serializer_dtor_php, NULL, VSCF_SEC1_SERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_key_asn1_serializer_t = zend_register_list_destructors_ex(vscf_key_asn1_serializer_dtor_php, NULL, VSCF_KEY_ASN1_SERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_key_asn1_deserializer_t = zend_register_list_destructors_ex(vscf_key_asn1_deserializer_dtor_php, NULL, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_ed25519_t = zend_register_list_destructors_ex(vscf_ed25519_dtor_php, NULL, VSCF_ED25519_PHP_RES_NAME, module_number);
    le_vscf_curve25519_t = zend_register_list_destructors_ex(vscf_curve25519_dtor_php, NULL, VSCF_CURVE25519_PHP_RES_NAME, module_number);
    le_vscf_simple_alg_info_t = zend_register_list_destructors_ex(vscf_simple_alg_info_dtor_php, NULL, VSCF_SIMPLE_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_hash_based_alg_info_t = zend_register_list_destructors_ex(vscf_hash_based_alg_info_dtor_php, NULL, VSCF_HASH_BASED_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_cipher_alg_info_t = zend_register_list_destructors_ex(vscf_cipher_alg_info_dtor_php, NULL, VSCF_CIPHER_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_salted_kdf_alg_info_t = zend_register_list_destructors_ex(vscf_salted_kdf_alg_info_dtor_php, NULL, VSCF_SALTED_KDF_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_pbe_alg_info_t = zend_register_list_destructors_ex(vscf_pbe_alg_info_dtor_php, NULL, VSCF_PBE_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_ecc_alg_info_t = zend_register_list_destructors_ex(vscf_ecc_alg_info_dtor_php, NULL, VSCF_ECC_ALG_INFO_PHP_RES_NAME, module_number);
    le_vscf_alg_info_der_serializer_t = zend_register_list_destructors_ex(vscf_alg_info_der_serializer_dtor_php, NULL, VSCF_ALG_INFO_DER_SERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_alg_info_der_deserializer_t = zend_register_list_destructors_ex(vscf_alg_info_der_deserializer_dtor_php, NULL, VSCF_ALG_INFO_DER_DESERIALIZER_PHP_RES_NAME, module_number);
    le_vscf_message_info_der_serializer_t = zend_register_list_destructors_ex(vscf_message_info_der_serializer_dtor_php, NULL, VSCF_MESSAGE_INFO_DER_SERIALIZER_PHP_RES_NAME, module_number);
    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(vscf_foundation_php) {
    return SUCCESS;
}
