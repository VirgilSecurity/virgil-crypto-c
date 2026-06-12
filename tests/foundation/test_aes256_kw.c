//  Copyright (C) 2015-2026 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_AES256_KW
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_aes256_kw.h"
#include "vscf_status.h"

//  RFC 3394 4.6: Wrap 256 bits of key data with a 256-bit KEK.
static const byte k_kek[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const byte k_key[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const byte k_wrapped[40] = {0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87,
        0xf8, 0x26, 0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99, 0xf4, 0x3b,
        0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21};


void
test__wrap__rfc3394_vector__matches_expected(void) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_kw_wrapped_len(kw, sizeof(k_key)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_aes256_kw_wrap(kw, vsc_data(k_kek, sizeof(k_kek)), vsc_data(k_key, sizeof(k_key)), out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_data(k_wrapped, sizeof(k_wrapped)), out);

    vsc_buffer_destroy(&out);
    vscf_aes256_kw_destroy(&kw);
}

void
test__unwrap__rfc3394_vector__matches_expected(void) {
    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_kw_unwrapped_len(kw, sizeof(k_wrapped)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_aes256_kw_unwrap(kw, vsc_data(k_kek, sizeof(k_kek)), vsc_data(k_wrapped, sizeof(k_wrapped)), out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_data(k_key, sizeof(k_key)), out);

    vsc_buffer_destroy(&out);
    vscf_aes256_kw_destroy(&kw);
}

void
test__unwrap__tampered_wrapped_key__auth_fails(void) {
    byte tampered[40];
    memcpy(tampered, k_wrapped, sizeof(tampered));
    tampered[0] ^= 0x01;

    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_kw_unwrapped_len(kw, sizeof(tampered)));
    TEST_ASSERT_EQUAL(vscf_status_ERROR_AUTH_FAILED,
            vscf_aes256_kw_unwrap(kw, vsc_data(k_kek, sizeof(k_kek)), vsc_data(tampered, sizeof(tampered)), out));

    vsc_buffer_destroy(&out);
    vscf_aes256_kw_destroy(&kw);
}

void
test__wrap_then_unwrap__arbitrary_key__roundtrip(void) {
    byte key[48];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (byte)(i * 7 + 1);
    }

    vscf_aes256_kw_t *kw = vscf_aes256_kw_new();

    vsc_buffer_t *wrapped = vsc_buffer_new_with_capacity(vscf_aes256_kw_wrapped_len(kw, sizeof(key)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_aes256_kw_wrap(kw, vsc_data(k_kek, sizeof(k_kek)), vsc_data(key, sizeof(key)), wrapped));

    vsc_buffer_t *unwrapped = vsc_buffer_new_with_capacity(vscf_aes256_kw_unwrapped_len(kw, vsc_buffer_len(wrapped)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_aes256_kw_unwrap(kw, vsc_data(k_kek, sizeof(k_kek)), vsc_buffer_data(wrapped), unwrapped));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_data(key, sizeof(key)), unwrapped);

    vsc_buffer_destroy(&unwrapped);
    vsc_buffer_destroy(&wrapped);
    vscf_aes256_kw_destroy(&kw);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__wrap__rfc3394_vector__matches_expected);
    RUN_TEST(test__unwrap__rfc3394_vector__matches_expected);
    RUN_TEST(test__unwrap__tampered_wrapped_key__auth_fails);
    RUN_TEST(test__wrap_then_unwrap__arbitrary_key__roundtrip);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
