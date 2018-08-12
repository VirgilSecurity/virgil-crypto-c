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


#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_RSA_PRIVATE_KEY && VSCF_ASN1RD && VSCF_ASN1WR && VSCF_FAKE_RANDOM && VSCF_SHA512)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_rsa_private_key.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_fake_random.h"
#include "vscf_sha512.h"

#include "test_data_rsa.h"


void
test__rsa_private_key_key_len__imported_2048_PRIVATE_KEY_PKCS1__returns_256(void) {
    vscf_rsa_private_key_impl_t *private_key_impl = vscf_rsa_private_key_new();
    vscf_impl_t *asn1rd = vscf_asn1rd_impl(vscf_asn1rd_new());

    vscf_rsa_private_key_take_asn1_reader(private_key_impl, &asn1rd);

    vscf_error_t result = vscf_rsa_private_key_import_private_key(
            private_key_impl, vsc_data(test_rsa_2048_PRIVATE_KEY_PKCS1, test_rsa_2048_PRIVATE_KEY_PKCS1_LEN));
    VSCF_ASSERT(result == vscf_SUCCESS);

    TEST_ASSERT_EQUAL(256, vscf_rsa_private_key_key_len(private_key_impl));

    vscf_rsa_private_key_destroy(&private_key_impl);
}

void
test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB_and_hash_sha512__returns_DATA_1(
        void) {

    //  Setup dependencies
    vscf_rsa_private_key_impl_t *private_key_impl = vscf_rsa_private_key_new();
    vscf_impl_t *asn1rd = vscf_asn1rd_impl(vscf_asn1rd_new());
    vscf_rsa_private_key_take_asn1_reader(private_key_impl, &asn1rd);


    vscf_fake_random_impl_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_private_key_use_random(private_key_impl, vscf_fake_random_impl(fake_random));


    vscf_rsa_private_key_use_hash_api(private_key_impl, vscf_sha512_hash_api());

    //  Import public key
    vscf_error_t result = vscf_rsa_private_key_import_private_key(
            private_key_impl, vsc_data(test_rsa_2048_PRIVATE_KEY_PKCS1, test_rsa_2048_PRIVATE_KEY_PKCS1_LEN));
    VSCF_ASSERT(result == vscf_SUCCESS);


    //  Encrypt
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_rsa_private_key_decrypted_len(private_key_impl, test_rsa_2048_ENCRYPTED_DATA_1_LEN));
    vscf_rsa_private_key_decrypt(
            private_key_impl, vsc_data(test_rsa_2048_ENCRYPTED_DATA_1, test_rsa_2048_ENCRYPTED_DATA_1_LEN), out);

    //  Check
    TEST_ASSERT_EQUAL(test_rsa_DATA_1_LEN, vsc_buffer_len(out));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_rsa_DATA_1, vsc_buffer_bytes(out), vsc_buffer_len(out));

    //  Cleanup
    vsc_buffer_destroy(&out);
    vscf_fake_random_destroy(&fake_random);
    vscf_rsa_private_key_destroy(&private_key_impl);
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
    RUN_TEST(test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB_and_hash_sha512__returns_DATA_1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
