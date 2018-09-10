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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_KDF2 &&VSCF_SHA256
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_kdf2.h"
#include "vscf_sha256.h"
#include "vscf_assert.h"
#include "vscf_memory.h"

#include "test_data_kdf2.h"


// --------------------------------------------------------------------------
// Test implementation of the interface 'kdf'.
// --------------------------------------------------------------------------
void
test__derive__sha256_vector_1__success(void) {

    vscf_kdf2_impl_t *kdf2_impl = vscf_kdf2_new();
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_kdf2_VECTOR_1_KEY.len);

    vscf_kdf2_take_hash_stream(kdf2_impl, vscf_sha256_impl(vscf_sha256_new()));

    vscf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_1_DATA, key, test_kdf2_VECTOR_1_KEY.len);

    vscf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL(test_kdf2_VECTOR_1_KEY.len, vsc_buffer_len(key));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_1_KEY.bytes, vsc_buffer_bytes(key), vsc_buffer_len(key));

    vsc_buffer_destroy(&key);
}

void
test__derive__sha256_vector_2__success(void) {

    vscf_kdf2_impl_t *kdf2_impl = vscf_kdf2_new();
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_kdf2_VECTOR_2_KEY.len);

    vscf_kdf2_take_hash_stream(kdf2_impl, vscf_sha256_impl(vscf_sha256_new()));

    vscf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_2_DATA, key, test_kdf2_VECTOR_2_KEY.len);

    vscf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL(test_kdf2_VECTOR_2_KEY.len, vsc_buffer_len(key));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_2_KEY.bytes, vsc_buffer_bytes(key), vsc_buffer_len(key));

    vsc_buffer_destroy(&key);
}

void
test__derive__sha256_vector_3__success(void) {

    vscf_kdf2_impl_t *kdf2_impl = vscf_kdf2_new();
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_kdf2_VECTOR_3_KEY.len);

    vscf_kdf2_take_hash_stream(kdf2_impl, vscf_sha256_impl(vscf_sha256_new()));

    vscf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_3_DATA, key, test_kdf2_VECTOR_3_KEY.len);

    vscf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL(test_kdf2_VECTOR_3_KEY.len, vsc_buffer_len(key));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_3_KEY.bytes, vsc_buffer_bytes(key), vsc_buffer_len(key));

    vsc_buffer_destroy(&key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__derive__sha256_vector_1__success);
    RUN_TEST(test__derive__sha256_vector_2__success);
    RUN_TEST(test__derive__sha256_vector_3__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
