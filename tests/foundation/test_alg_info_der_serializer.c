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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ALG_INFO_DER_SERIALIZER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg_info_der_serializer.h"
#include "vscf_kdf_alg_info.h"
#include "vscf_simple_alg_info.h"

#include "test_data_alg_info_der.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


void
test__serialize__sha256__returns_valid_der(void) {
    vscf_alg_info_der_serializer_t *serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_setup_defaults(serializer);

    vscf_impl_t *sha256_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA256));

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len(serializer, sha256_info));
    vsc_buffer_switch_reverse_mode(out, true);

    vscf_alg_info_der_serializer_serialize(serializer, sha256_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_alg_info_SHA256_DER, out);

    vscf_impl_destroy(&sha256_info);
    vscf_alg_info_der_serializer_destroy(&serializer);
    vsc_buffer_destroy(&out);
}

void
test__serialize__kdf1_sha256__returns_valid_der(void) {
    vscf_alg_info_der_serializer_t *serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_setup_defaults(serializer);

    vscf_simple_alg_info_t *hash_info = vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA256);
    vscf_impl_t *kdf_info = vscf_kdf_alg_info_impl(vscf_kdf_alg_info_new_with_members(vscf_alg_id_KDF1, hash_info));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len(serializer, kdf_info));
    vsc_buffer_switch_reverse_mode(out, true);

    vscf_alg_info_der_serializer_serialize(serializer, kdf_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_alg_info_KDF1_SHA256_DER, out);

    vscf_simple_alg_info_destroy(&hash_info);
    vscf_impl_destroy(&kdf_info);
    vscf_alg_info_der_serializer_destroy(&serializer);
    vsc_buffer_destroy(&out);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__serialize__sha256__returns_valid_der);
    RUN_TEST(test__serialize__kdf1_sha256__returns_valid_der);

#if TEST_DEPENDENCIES_AVAILABLE
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
