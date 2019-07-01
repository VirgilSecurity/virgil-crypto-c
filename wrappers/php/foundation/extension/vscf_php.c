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
// @end

#include "vscf_assert.h"
#include "vscf_sha256.h"
#include "vscf_kdf1.h"
#include "vscf_base64.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_key_provider.h"

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"
#include "vscf_status.h"

#include "vscf_error.h"

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>


// --------------------------------------------------------------------------
//  Constants
// --------------------------------------------------------------------------
const char VSCF_PHP_VERSION[] = "0.1.0";
const char VSCF_PHP_EXTNAME[] = "vscf_php";

const char VSCF_IMPL_PHP_RES_NAME[] = "vscf_php";
const char VSCF_BASE64_PHP_RES_NAME[] = "vscf_php_base64";
const char VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME[] = "vscf_php_key_asn1_deserializer";
const char VSCF_KEY_PROVIDER_PHP_RES_NAME[] = "vscf_php_key_provider";

// --------------------------------------------------------------------------
//  Registered resources
// --------------------------------------------------------------------------
int le_vscf_impl;
int le_vscf_base64;
int le_vscf_key_asn1_deserializer;
int le_vscf_key_provider;

// --------------------------------------------------------------------------
//  Extension init functions declaration
// --------------------------------------------------------------------------
PHP_MINIT_FUNCTION(vscf_php);
PHP_MSHUTDOWN_FUNCTION(vscf_php);

#define VSCF_HANDLE_STATUS(status) \
do { \
    if(status != vscf_status_SUCCESS) {  \
    vscf_handle_throw_exception(status); \
        goto fail;\
    } \
} while (false)

void
vscf_handle_throw_exception(vscf_status_t status) {
        switch(status) {
            case vscf_status_ERROR_BAD_ARGUMENTS:
                zend_throw_exception(NULL, "Foundation: This error should not be returned if assertions is enabled.", status);
                break;
            case vscf_status_ERROR_UNINITIALIZED:
                zend_throw_exception(NULL, "Foundation: Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.", status);
                break;
            case vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR:
                zend_throw_exception(NULL, "Foundation: Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.", status);
                break;
            case vscf_status_ERROR_SMALL_BUFFER:
                zend_throw_exception(NULL, "Foundation: Buffer capacity is not enough to hold result.", status);
                break;
            case vscf_status_ERROR_UNSUPPORTED_ALGORITHM:
                zend_throw_exception(NULL, "Foundation: Unsupported algorithm.", status);
                break;
            case vscf_status_ERROR_AUTH_FAILED:
                zend_throw_exception(NULL, "Foundation: Authentication failed during decryption.", status);
                break;
            case vscf_status_ERROR_OUT_OF_DATA:
                zend_throw_exception(NULL, "Foundation: Attempt to read data out of buffer bounds.", status);
                break;
           case vscf_status_ERROR_BAD_ASN1:
                zend_throw_exception(NULL, "Foundation:  ASN.1 encoded data is corrupted.", status);
                break;
            case vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING:
                zend_throw_exception(NULL, "Foundation: Attempt to read ASN.1 type that is bigger then requested C type.", status);
                break;
            case vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of PKCS#1 public key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of PKCS#1 private key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of PKCS#8 public key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of PKCS#8 private key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_ENCRYPTED_DATA:
                zend_throw_exception(NULL, "Foundation: Encrypted data is corrupted.", status);
                break;
            case vscf_status_ERROR_RANDOM_FAILED:
                zend_throw_exception(NULL, "Foundation: Underlying random operation returns error.", status);
                break;
            case vscf_status_ERROR_KEY_GENERATION_FAILED:
                zend_throw_exception(NULL, "Foundation: Generation of the private or secret key failed.", status);
                break;
            case vscf_status_ERROR_ENTROPY_SOURCE_FAILED:
                zend_throw_exception(NULL, "Foundation: One of the entropy sources failed.", status);
                break;
            case vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG:
                zend_throw_exception(NULL, "Foundation: Requested data to be generated is too big.", status);
                break;
            case vscf_status_ERROR_BAD_BASE64:
                zend_throw_exception(NULL, "Foundation: Base64 encoded string contains invalid characters.", status);
                break;
            case vscf_status_ERROR_BAD_PEM:
                zend_throw_exception(NULL, "Foundation: PEM data is corrupted.", status);
                break;
            case vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED:
                zend_throw_exception(NULL, "Foundation: Exchange key return zero.", status);
                break;
            case vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: Ed25519 public key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: Ed25519 private key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: CURVE25519 public key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: CURVE25519 private key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: Elliptic curve public key format is corrupted see RFC 5480.", status);
                break;
            case vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: Elliptic curve public key format is corrupted see RFC 5915.", status);
                break;
            case vscf_status_ERROR_BAD_DER_PUBLIC_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of a public key is corrupted.", status);
                break;
            case vscf_status_ERROR_BAD_DER_PRIVATE_KEY:
                zend_throw_exception(NULL, "Foundation: ASN.1 representation of a private key is corrupted.", status);
                break;
            case vscf_status_ERROR_NO_MESSAGE_INFO:
                zend_throw_exception(NULL, "Foundation: Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.", status);
                break;
            case vscf_status_ERROR_BAD_MESSAGE_INFO:
                zend_throw_exception(NULL, "Foundation:  Message info is corrupted.", status);
                break;
            case vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
                zend_throw_exception(NULL, "Foundation: Recipient defined with id is not found within message info during data decryption.", status);
                break;
            case vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
                zend_throw_exception(NULL, "Foundation: Content encryption key can not be decrypted with a given private key.", status);
                break;
            case vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
                zend_throw_exception(NULL, "Foundation: Content encryption key can not be decrypted with a given password.", status);
                break;
            case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
                zend_throw_exception(NULL, "Foundation: Custom parameter with a given key is not found within message info.", status);
                break;
            case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
                zend_throw_exception(NULL, "Foundation: A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.", status);
                break;
            case vscf_status_ERROR_BAD_SIGNATURE:
                zend_throw_exception(NULL, "Foundation: Signature format is corrupted.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey password length is out of range.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey number length should be 32 byte.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey point length should be 65 bytes.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey name is out of range.", status);
                break;
            case vscf_status_ERROR_BRAINKEY_INTERNAL:
                zend_throw_exception(NULL, "Foundation: Brainkey internal error.", status);
                break;
            case vscf_status_ERROR_BRAINKEY_INVALID_POINT:
                zend_throw_exception(NULL, "Foundation: Brainkey point is invalid.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey number buffer length capacity should be >= 32 byte.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey point buffer length capacity should be >= 32 byte.", status);
                break;
            case vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
                zend_throw_exception(NULL, "Foundation: Brainkey seed buffer length capacity should be >= 32 byte.", status);
                break;
            case vscf_status_ERROR_INVALID_IDENTITY_SECRET:
                zend_throw_exception(NULL, "Foundation: Brainkey identity secret is invalid.", status);
                break;
    }
}

// --------------------------------------------------------------------------
//  Functions wrapping
// --------------------------------------------------------------------------
//
//  Wrap method: vscf_sha256_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_new_php) {
    vscf_sha256_t *sha256 = vscf_sha256_new();
    zend_resource *sha256_res = zend_register_resource(sha256, le_vscf_impl);
    RETVAL_RES(sha256_res);
}

//
//  Wrap method: vscf_sha256_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_delete_php /*name*/,
        0 /*_unused*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_delete_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Fetch for type checking and then release
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(sha256);
    zend_list_close(Z_RES_P(in_cctx));
    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_hash_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_hash_php) {
    //
    //  Declare input arguments
    //
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //  Allocate output buffer for output 'digest'
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    vscf_sha256_hash(data, digest);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    //  Write returned result
    //
    RETVAL_STR(out_digest);

    vsc_buffer_destroy(&digest);
}

//
//  Wrap method: vscf_sha256_start
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_start_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_start_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(sha256);

    vscf_sha256_start(sha256);

    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_update
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_update_php /*name*/,
        0 /*return_reference*/,
        2 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_update_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(sha256);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    vscf_sha256_update(sha256, data);

    RETURN_TRUE;
}

//
//  Wrap method: vscf_sha256_finish
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_sha256_finish_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_sha256_finish_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_sha256_t *sha256 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(sha256);

    //  Allocate output buffer for output 'digest'
    zend_string *out_digest = zend_string_alloc(vscf_sha256_DIGEST_LEN, 0);
    vsc_buffer_t *digest = vsc_buffer_new();
    vsc_buffer_use(digest, (byte *)ZSTR_VAL(out_digest), ZSTR_LEN(out_digest));

    vscf_sha256_finish(sha256, digest);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_digest) = vsc_buffer_len(digest);

    //
    //  Write returned result
    //
    RETVAL_STR(out_digest);

    vsc_buffer_destroy(&digest);
}

//
//  Wrap method: vscf_kdf1_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_kdf1_new_php) {
    vscf_kdf1_t *kdf1 = vscf_kdf1_new();
    zend_resource *kdf1_res = zend_register_resource(kdf1, le_vscf_impl);
    RETVAL_RES(kdf1_res);
}

//
//  Wrap method: vscf_kdf1_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_delete_php /*name*/,
        0 /*_unused*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_kdf1_delete_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Fetch for type checking and then release
    //
    vscf_kdf1_t *kdf1 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(kdf1);
    zend_list_close(Z_RES_P(in_cctx));
    RETURN_TRUE;
}

//
//  Wrap method: vscf_kdf1_use_hash
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_use_hash_php /*name*/,
        0 /*return_reference*/,
        2 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_kdf1_use_hash_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    zval *in_cctx2 = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_cctx2, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_kdf1_t *vscf_kdf1 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(vscf_kdf1);

    vscf_impl_t *hash = zend_fetch_resource_ex(in_cctx2, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(hash);

    vscf_kdf1_use_hash(vscf_kdf1, hash);

    RETURN_TRUE;
}

//
//  Wrap method: vscf_kdf1_derive
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_kdf1_derive_php /*name*/,
        0 /*return_reference*/,
        3 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key_len, IS_LONG, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_kdf1_derive_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_data = NULL;
    size_t in_data_len = 0;
    zend_long key_len;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
        Z_PARAM_LONG(key_len)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_kdf1_t *vscf_kdf1 = zend_fetch_resource_ex(in_cctx, VSCF_IMPL_PHP_RES_NAME, le_vscf_impl);
    VSCF_ASSERT_PTR(vscf_kdf1);

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);
    // size_t key_len = size_t(key_len);

    //  Allocate output buffer for output 'key'
    zend_string *out_key = zend_string_alloc(key_len, 0);
    vsc_buffer_t *key = vsc_buffer_new();
    vsc_buffer_use(key, (byte *)ZSTR_VAL(out_key), ZSTR_LEN(out_key));

    vscf_kdf1_derive(vscf_kdf1, data, key_len, key);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_key) = vsc_buffer_len(key);

    //
    //  Write returned result
    //
    RETVAL_STR(out_key);
    vsc_buffer_destroy(&key);    
}

//
//  Wrap method: vscf_base64_encode
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_base64_encode_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_base64_encode_php) {
    //
    //  Declare input arguments
    //
    char *in_data = NULL;
    size_t in_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_data, in_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    vsc_data_t data = vsc_data((const byte*)in_data, in_data_len);

    //  Allocate output buffer for output 'str'
    zend_string *out_str = zend_string_alloc(vscf_base64_encoded_len(in_data_len), 0);
    vsc_buffer_t *str = vsc_buffer_new();
    vsc_buffer_use(str, (byte *)ZSTR_VAL(out_str), ZSTR_LEN(out_str));

    vscf_base64_encode(data, str);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_str) = vsc_buffer_len(str);

    //
    //  Write returned result
    //
    RETVAL_STR(out_str);

    vsc_buffer_destroy(&str);
}

//
//  Wrap method: vscf_base64_decode
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_base64_decode_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_base64_decode_php) {
    //
    //  Declare input arguments
    //
    char *in_str = NULL;
    size_t in_str_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_str, in_str_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    vsc_data_t str = vsc_data((const byte*)in_str, in_str_len);

    //  Allocate output buffer for output 'data'
    zend_string *out_data = zend_string_alloc(vscf_base64_decoded_len(in_str_len), 0);
    vsc_buffer_t *data = vsc_buffer_new();
    vsc_buffer_use(data, (byte *)ZSTR_VAL(out_data), ZSTR_LEN(out_data));

    vscf_status_t status = vscf_base64_decode(str, data);

    //
    //  Handle error
    //

    VSCF_HANDLE_STATUS(status);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_data) = vsc_buffer_len(data);

    //
    //  Write returned result
    //
    RETVAL_STR(out_data);

    goto success;

fail:
    zend_string_free(out_data);
success:
    vsc_buffer_destroy(&data);
}

//
//  Wrap method: vscf_key_asn1_deserializer_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_asn1_deserializer_new_php) {
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    zend_resource *key_asn1_deserializer_res = zend_register_resource(key_asn1_deserializer, le_vscf_key_asn1_deserializer);
    RETVAL_RES(key_asn1_deserializer_res);
}

//
//  Wrap method: vscf_key_asn1_deserializer_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_delete_php /*name*/,
        0 /*_unused*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_asn1_deserializer_delete_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Fetch for type checking and then release
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_cctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer);
    VSCF_ASSERT_PTR(key_asn1_deserializer);
    zend_list_close(Z_RES_P(in_cctx));
    RETURN_TRUE;
}

//
//  Wrap method: vscf_key_asn1_deserializer_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_setup_defaults_php /*name*/,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_asn1_deserializer_setup_defaults_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_key_asn1_deserializer_t *vscf_key_asn1_deserializer = zend_fetch_resource_ex(in_cctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer);
    VSCF_ASSERT_PTR(vscf_key_asn1_deserializer);

    vscf_key_asn1_deserializer_setup_defaults(vscf_key_asn1_deserializer);

    RETURN_TRUE;
}

//
//  Wrap method: vscf_key_asn1_deserializer_deserialize_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_deserialize_public_key_php /*name*/,
        0 /*return_reference*/,
        2 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, public_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_public_key_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_public_key_data = NULL;
    size_t in_public_key_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_public_key_data, in_public_key_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_cctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vsc_data_t public_key_data = vsc_data((const byte*)in_public_key_data, in_public_key_data_len);

    //  Allocate output buffer for output 'raw_key'
    zend_string *out_raw_key = zend_string_alloc(in_public_key_data_len, 0);
    vsc_buffer_t *raw_key = vsc_buffer_new();
    vsc_buffer_use(raw_key, (byte *)ZSTR_VAL(out_raw_key), ZSTR_LEN(out_raw_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_asn1_deserializer_deserialize_public_key(key_asn1_deserializer, public_key_data, &error);

    vscf_status_t status = vscf_error_status(&error);

    //
    //  Handle error
    //
    VSCF_HANDLE_STATUS(status);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_raw_key) = vsc_buffer_len(raw_key);

    //
    //  Write returned result
    //
    RETVAL_STR(out_raw_key);

    goto success;

fail:
    zend_string_free(out_raw_key);
success:
    vsc_buffer_destroy(&raw_key);
}

//
//  Wrap method: vscf_key_asn1_deserializer_deserialize_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_asn1_deserializer_deserialize_private_key_php /*name*/,
        0 /*return_reference*/,
        2 /*required_num_args*/,
        IS_STRING /*type*/,
        0 /*allow_null*/)

    ZEND_ARG_INFO(0, c_ctx)
    ZEND_ARG_TYPE_INFO(0, private_key_data, IS_STRING, 0)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_asn1_deserializer_deserialize_private_key_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;
    char *in_private_key_data = NULL;
    size_t in_private_key_data_len = 0;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
        Z_PARAM_STRING_EX(in_private_key_data, in_private_key_data_len, 1 /*check_null*/, 0 /*deref and separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Proxy call
    //
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = zend_fetch_resource_ex(in_cctx, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, le_vscf_key_asn1_deserializer);
    VSCF_ASSERT_PTR(key_asn1_deserializer);

    vsc_data_t private_key_data = vsc_data((const byte*)in_private_key_data, in_private_key_data_len);

    //  Allocate output buffer for output 'raw_key'
    zend_string *out_raw_key = zend_string_alloc(in_private_key_data_len, 0);
    vsc_buffer_t *raw_key = vsc_buffer_new();
    vsc_buffer_use(raw_key, (byte *)ZSTR_VAL(out_raw_key), ZSTR_LEN(out_raw_key));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_asn1_deserializer_deserialize_public_key(key_asn1_deserializer, private_key_data, &error);

    vscf_status_t status = vscf_error_status(&error);

    //
    //  Handle error
    //
    VSCF_HANDLE_STATUS(status);

    //
    //  Correct string length to the actual
    //
    ZSTR_LEN(out_raw_key) = vsc_buffer_len(raw_key);

    //
    //  Write returned result
    //
    RETVAL_STR(out_raw_key);

    goto success;

fail:
    zend_string_free(out_raw_key);
success:
    vsc_buffer_destroy(&raw_key);
}

//
//  Wrap method: vscf_key_provider_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_provider_new_php /*name*/,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_provider_new_php) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    zend_resource *key_provider_res = zend_register_resource(key_provider, le_vscf_key_provider);
    RETVAL_RES(key_provider_res);
}

//
//  Wrap method: vscf_key_provider_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscf_key_provider_delete_php /*name*/,
        0 /*_unused*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)
    ZEND_ARG_INFO(0, c_ctx)
ZEND_END_ARG_INFO()


PHP_FUNCTION(vscf_key_provider_delete_php) {
    //
    //  Declare input arguments
    //
    zval *in_cctx = NULL;

    //
    //  Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_cctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    //  Fetch for type checking and then release
    //
    vscf_key_provider_t *key_provider = zend_fetch_resource_ex(in_cctx, VSCF_KEY_PROVIDER_PHP_RES_NAME, le_vscf_key_provider);
    VSCF_ASSERT_PTR(key_provider);
    zend_list_close(Z_RES_P(in_cctx));
    RETURN_TRUE;
}

// --------------------------------------------------------------------------
//  Define all function entries
// --------------------------------------------------------------------------
static zend_function_entry vscf_php_functions[] = {
    // Sha256
    PHP_FE(vscf_sha256_new_php, arginfo_vscf_sha256_new_php)
    PHP_FE(vscf_sha256_delete_php, arginfo_vscf_sha256_delete_php)
    PHP_FE(vscf_sha256_hash_php, arginfo_vscf_sha256_hash_php)
    PHP_FE(vscf_sha256_start_php, arginfo_vscf_sha256_start_php)
    PHP_FE(vscf_sha256_update_php, arginfo_vscf_sha256_update_php)
    PHP_FE(vscf_sha256_finish_php, arginfo_vscf_sha256_finish_php)
    // Kdf1
    PHP_FE(vscf_kdf1_new_php, arginfo_vscf_kdf1_new_php)
    PHP_FE(vscf_kdf1_delete_php, arginfo_vscf_kdf1_delete_php)
    PHP_FE(vscf_kdf1_use_hash_php, arginfo_vscf_kdf1_use_hash_php)
    PHP_FE(vscf_kdf1_derive_php, arginfo_vscf_kdf1_derive_php)
    // Base64
    PHP_FE(vscf_base64_encode_php, arginfo_vscf_base64_encode_php)
    PHP_FE(vscf_base64_decode_php, arginfo_vscf_base64_decode_php)
    // KEY_ASN1_DESERIALIZER
    PHP_FE(vscf_key_asn1_deserializer_new_php, arginfo_vscf_key_asn1_deserializer_new_php)
    PHP_FE(vscf_key_asn1_deserializer_delete_php, arginfo_vscf_key_asn1_deserializer_delete_php)
    PHP_FE(vscf_key_asn1_deserializer_setup_defaults_php, arginfo_vscf_key_asn1_deserializer_setup_defaults_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_public_key_php, arginfo_vscf_key_asn1_deserializer_deserialize_public_key_php)
    PHP_FE(vscf_key_asn1_deserializer_deserialize_private_key_php, arginfo_vscf_key_asn1_deserializer_deserialize_private_key_php)
    // KEY_ASN1_DESERIALIZER
    PHP_FE(vscf_key_provider_new_php, arginfo_vscf_key_provider_new_php)
    PHP_FE(vscf_key_provider_delete_php, arginfo_vscf_key_provider_delete_php)
    PHP_FE_END
};


// --------------------------------------------------------------------------
//  Extension module definition
// --------------------------------------------------------------------------
zend_module_entry vscf_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCF_PHP_EXTNAME,
    vscf_php_functions,
    PHP_MINIT(vscf_php),
    PHP_MSHUTDOWN(vscf_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCF_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscf_php)


// --------------------------------------------------------------------------
//  Extension init functions definition
// --------------------------------------------------------------------------
static void vscf_dtor_php(zend_resource *rsrc) {
    vscf_impl_delete((vscf_impl_t *)rsrc->ptr);
}

static void vscf_key_asn1_deserializer_dtor_php(zend_resource *rsrc) {
    vscf_key_asn1_deserializer_delete((vscf_key_asn1_deserializer_t *)rsrc->ptr);
}

static void vscf_key_provider_dtor_php(zend_resource *rsrc) {
    vscf_key_provider_delete((vscf_key_provider_t *)rsrc->ptr);
}

PHP_MINIT_FUNCTION(vscf_php) {

    le_vscf_impl = zend_register_list_destructors_ex(
            vscf_dtor_php, NULL, VSCF_IMPL_PHP_RES_NAME, module_number);

    le_vscf_key_asn1_deserializer = zend_register_list_destructors_ex(
            vscf_key_asn1_deserializer_dtor_php, NULL, VSCF_KEY_ASN1_DESERIALIZER_PHP_RES_NAME, module_number);

    le_vscf_key_provider = zend_register_list_destructors_ex(
            vscf_key_provider_dtor_php, NULL, VSCF_KEY_PROVIDER_PHP_RES_NAME, module_number);    

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(vscf_php) {

    return SUCCESS;
}