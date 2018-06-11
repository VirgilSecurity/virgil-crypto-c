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

#include "vsf_kdf2.h"
#include "vsf_sha256.h"
#include "vsf_assert.h"
#include "vsf_memory.h"

#include "test_utils.h"
#include "test_data_kdf2.h"


// --------------------------------------------------------------------------
// Test implementation of the interface 'kdf'.
// --------------------------------------------------------------------------

void
test__derive__sha256_vector_1__success(void) {

    byte* key = vsf_alloc(test_kdf2_VECTOR_1_KEY_LEN);

    vsf_kdf2_impl_t* kdf2_impl = vsf_kdf2_new();
    vsf_impl_t* sha256_impl = vsf_sha256_impl(vsf_sha256_new());

    vsf_kdf2_take_hash_stream(kdf2_impl, &sha256_impl);

    vsf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_1_DATA, test_kdf2_VECTOR_1_DATA_LEN, key, test_kdf2_VECTOR_1_KEY_LEN);

    vsf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_1_KEY, key, test_kdf2_VECTOR_1_KEY_LEN);

    vsf_dealloc(key);
}

void
test__derive__sha256_vector_2__success(void) {

    byte* key = vsf_alloc(test_kdf2_VECTOR_2_KEY_LEN);

    vsf_kdf2_impl_t* kdf2_impl = vsf_kdf2_new();
    vsf_impl_t* sha256_impl = vsf_sha256_impl(vsf_sha256_new());

    vsf_kdf2_take_hash_stream(kdf2_impl, &sha256_impl);

    vsf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_2_DATA, test_kdf2_VECTOR_2_DATA_LEN, key, test_kdf2_VECTOR_2_KEY_LEN);

    vsf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_2_KEY, key, test_kdf2_VECTOR_2_KEY_LEN);

    vsf_dealloc(key);
}

void
test__derive__sha256_vector_3__success(void) {

    byte* key = vsf_alloc(test_kdf2_VECTOR_3_KEY_LEN);

    vsf_kdf2_impl_t* kdf2_impl = vsf_kdf2_new();
    vsf_impl_t* sha256_impl = vsf_sha256_impl(vsf_sha256_new());

    vsf_kdf2_take_hash_stream(kdf2_impl, &sha256_impl);

    vsf_kdf2_derive(kdf2_impl, test_kdf2_VECTOR_3_DATA, test_kdf2_VECTOR_3_DATA_LEN, key, test_kdf2_VECTOR_3_KEY_LEN);

    vsf_kdf2_destroy(&kdf2_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_kdf2_VECTOR_3_KEY, key, test_kdf2_VECTOR_3_KEY_LEN);

    vsf_dealloc(key);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__derive__sha256_vector_1__success);
    RUN_TEST(test__derive__sha256_vector_2__success);
    RUN_TEST(test__derive__sha256_vector_3__success);

    return UNITY_END();
}
