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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_X25519_PUBLIC_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM && VSCF_ALG)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_alg.h"
#include "vscf_fake_random.h"
#include "vscf_random.h"
#include "vscf_x25519_public_key.h"

#include "test_data_x25519.h"


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
test__key_len__imported_public_key__returns_32(void) {
    vscf_x25519_public_key_t *public_key = vscf_x25519_public_key_new();

    vscf_status_t result = vscf_x25519_public_key_import_public_key(public_key, test_x25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    TEST_ASSERT_EQUAL(32, vscf_x25519_public_key_key_len(public_key));

    vscf_x25519_public_key_destroy(&public_key);
}

void
test__export_public_key__from_imported_public_key__are_equal(void) {
    vscf_x25519_public_key_t *public_key = vscf_x25519_public_key_new();

    vscf_status_t result = vscf_x25519_public_key_import_public_key(public_key, test_x25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_x25519_public_key_exported_public_key_len(public_key));
    result = vscf_x25519_public_key_export_public_key(public_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_PUBLIC_KEY, exported_key_buf);

    vsc_buffer_destroy(&exported_key_buf);
    vscf_x25519_public_key_destroy(&public_key);
}

void
test__encrypt__message_with_imported_key__success(void) {

    vscf_x25519_public_key_t *public_key = vscf_x25519_public_key_new();
    vscf_x25519_public_key_setup_defaults(public_key);

    vscf_status_t result = vscf_x25519_public_key_import_public_key(public_key, test_x25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    vsc_buffer_t *enc_msg =
            vsc_buffer_new_with_capacity(vscf_x25519_public_key_encrypted_len(public_key, test_x25519_MESSAGE.len));
    vscf_status_t status = vscf_x25519_public_key_encrypt(public_key, test_x25519_MESSAGE, enc_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_destroy(&enc_msg);
    vscf_x25519_public_key_destroy(&public_key);
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
    RUN_TEST(test__key_len__imported_public_key__returns_32);
    RUN_TEST(test__export_public_key__from_imported_public_key__are_equal);
    RUN_TEST(test__encrypt__message_with_imported_key__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
