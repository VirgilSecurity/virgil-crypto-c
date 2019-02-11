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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_RSA_PRIVATE_KEY && VSCF_ASN1RD && VSCF_ASN1WR && VSCF_FAKE_RANDOM && VSCF_SHA512)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_public_key.h"
#include "vscf_rsa_private_key.h"
#include "vscf_rsa_public_key.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_fake_random.h"
#include "vscf_sha512.h"

#include "test_data_rsa.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__rsa_private_key_key_len__imported_2048_PRIVATE_KEY_PKCS1__returns_256(void) {
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1rd(private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));

    vscf_error_t result = vscf_rsa_private_key_import_private_key(private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);
    VSCF_ASSERT(result == vscf_SUCCESS);

    TEST_ASSERT_EQUAL(256, vscf_rsa_private_key_key_len(private_key));

    vscf_rsa_private_key_destroy(&private_key);
}

void
test__rsa_private_key_export_private_key__from_imported_2048_PRIVATE_KEY_PKCS1__expected_equal(void) {
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1rd(private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_take_asn1wr(private_key, vscf_asn1wr_impl(vscf_asn1wr_new()));

    vscf_error_t result = vscf_rsa_private_key_import_private_key(private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);
    VSCF_ASSERT(result == vscf_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_rsa_private_key_exported_private_key_len(private_key));

    result = vscf_rsa_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(test_rsa_2048_PRIVATE_KEY_PKCS1.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_rsa_2048_PRIVATE_KEY_PKCS1.bytes, vsc_buffer_bytes(exported_key_buf),
            vsc_buffer_len(exported_key_buf));

    vsc_buffer_destroy(&exported_key_buf);
    vscf_rsa_private_key_destroy(&private_key);
}

void
test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB_and_hash_sha512__returns_DATA_1(
        void) {

    //  Setup dependencies
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1rd(private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_take_hash(private_key, vscf_sha512_impl(vscf_sha512_new()));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_private_key_take_random(private_key, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t result = vscf_rsa_private_key_import_private_key(private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Decrypt
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_rsa_private_key_decrypted_len(private_key, test_rsa_2048_ENCRYPTED_DATA_1.len));
    vscf_rsa_private_key_decrypt(private_key, test_rsa_2048_ENCRYPTED_DATA_1, out);

    //  Check
    TEST_ASSERT_EQUAL(test_rsa_DATA_1.len, vsc_buffer_len(out));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_rsa_DATA_1.bytes, vsc_buffer_bytes(out), vsc_buffer_len(out));

    //  Cleanup
    vsc_buffer_destroy(&out);
    vscf_rsa_private_key_destroy(&private_key);
}


void
test__rsa_private_key_extract_public_key__from_imported_2048_PRIVATE_KEY_PKCS1__when_exported_equals_2048_PUBLIC_KEY_PKCS1(
        void) {

#if VSCF_RSA_PUBLIC_KEY
    //  Setup dependencies
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1rd(private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_take_asn1wr(private_key, vscf_asn1wr_impl(vscf_asn1wr_new()));

    //  Import private key
    vscf_error_t result = vscf_rsa_private_key_import_private_key(private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Extract public key
    vscf_impl_t *public_key = vscf_rsa_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_key_buf = vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));

    vscf_error_t export_err = vscf_public_key_export_public_key(public_key, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_SUCCESS);

    //  Check
    TEST_ASSERT_EQUAL(test_rsa_2048_PUBLIC_KEY_PKCS1.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_rsa_2048_PUBLIC_KEY_PKCS1.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));

    vscf_rsa_private_key_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&exported_key_buf);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PUBLIC_KEY is disabled");
#endif
}

void
test__rsa_private_key_sign__with_imported_2048_PRIVATE_KEY_PKCS1_and_random_AB_and_hash_sha512_and_DATA_1__equals_2048_DATA_1_SIGNATURE(
        void) {

    //  Setup dependencies
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1rd(private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_take_hash(private_key, vscf_sha512_impl(vscf_sha512_new()));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_private_key_take_random(private_key, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t result = vscf_rsa_private_key_import_private_key(private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Sign
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_rsa_private_key_signature_len(private_key));
    vscf_error_t sign_result = vscf_rsa_private_key_sign(private_key, test_rsa_DATA_1, signature);

    //  Check
    TEST_ASSERT_EQUAL(vscf_SUCCESS, sign_result);
    TEST_ASSERT_EQUAL(test_rsa_2048_DATA_1_SIGNATURE.len, vsc_buffer_len(signature));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_rsa_2048_DATA_1_SIGNATURE.bytes, vsc_buffer_bytes(signature), vsc_buffer_len(signature));

    //  Cleanup
    vsc_buffer_destroy(&signature);
    vscf_rsa_private_key_destroy(&private_key);
}

void
test__rsa_private_key_generate_key__bitlen_256_and_exponent_3__exported_equals_256_GENERATED_PRIVATE_KEY_PKCS1(void) {

    //  Setup dependencies
    vscf_rsa_private_key_t *private_key = vscf_rsa_private_key_new();

    vscf_rsa_private_key_take_asn1wr(private_key, vscf_asn1wr_impl(vscf_asn1wr_new()));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_rsa_RANDOM);
    vscf_rsa_private_key_take_random(private_key, vscf_fake_random_impl(fake_random));

    //  Generate
    vscf_rsa_private_key_set_keygen_params(private_key, 256, 3);
    vscf_error_t gen_res = vscf_rsa_private_key_generate_key(private_key);

    //  Check
    TEST_ASSERT_EQUAL(vscf_SUCCESS, gen_res);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_rsa_private_key_exported_private_key_len(private_key));

    vscf_error_t export_res = vscf_rsa_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, export_res);
    TEST_ASSERT_EQUAL(test_rsa_256_GENERATED_PRIVATE_KEY_PKCS1.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_rsa_256_GENERATED_PRIVATE_KEY_PKCS1.bytes, vsc_buffer_bytes(exported_key_buf),
            vsc_buffer_len(exported_key_buf));

    //  Cleanup
    vsc_buffer_destroy(&exported_key_buf);
    vscf_rsa_private_key_destroy(&private_key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// clang-format off
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__rsa_private_key_key_len__imported_2048_PRIVATE_KEY_PKCS1__returns_256);
    RUN_TEST(test__rsa_private_key_export_private_key__from_imported_2048_PRIVATE_KEY_PKCS1__expected_equal);
    RUN_TEST(test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB_and_hash_sha512__returns_DATA_1);
    RUN_TEST(test__rsa_private_key_extract_public_key__from_imported_2048_PRIVATE_KEY_PKCS1__when_exported_equals_2048_PUBLIC_KEY_PKCS1);
    RUN_TEST(test__rsa_private_key_sign__with_imported_2048_PRIVATE_KEY_PKCS1_and_random_AB_and_hash_sha512_and_DATA_1__equals_2048_DATA_1_SIGNATURE);
    RUN_TEST(test__rsa_private_key_generate_key__bitlen_256_and_exponent_3__exported_equals_256_GENERATED_PRIVATE_KEY_PKCS1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
