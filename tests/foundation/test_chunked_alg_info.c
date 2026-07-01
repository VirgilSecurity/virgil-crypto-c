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


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_CHUNKED_ALG_INFO && VSCF_ALG_INFO_DER_SERIALIZER && VSCF_ALG_INFO_DER_DESERIALIZER)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg_info.h"
#include "vscf_chunked_alg_info.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_deserializer.h"

#include <virgil/crypto/common/vsc_buffer.h>

//
//  A canonical 12-byte nonce.
//
static const byte test_chunked_nonce_12[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};

//
//  Serialize a chunked_alg_info to a freshly allocated buffer (caller destroys).
//
static vsc_buffer_t *
serialize_chunked(vscf_impl_t *alg_info) {
    vscf_alg_info_der_serializer_t *serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_setup_defaults(serializer);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len(serializer, alg_info));
    vscf_alg_info_der_serializer_serialize(serializer, alg_info, out);

    vscf_alg_info_der_serializer_destroy(&serializer);
    return out;
}

// --------------------------------------------------------------------------
//  Happy path: build -> serialize -> deserialize -> fields equal.
// --------------------------------------------------------------------------
void
test__serialize_deserialize__chunked_alg_info__fields_equal(void) {
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 1, 65536, vsc_data(test_chunked_nonce_12, sizeof(test_chunked_nonce_12))));

    vsc_buffer_t *der = serialize_chunked(alg_info);

    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *restored = vscf_alg_info_der_deserializer_deserialize(deserializer, vsc_buffer_data(der), &error);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(restored);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM_CHUNKED, vscf_alg_info_alg_id(restored));

    vscf_chunked_alg_info_t *chunked = (vscf_chunked_alg_info_t *)restored;
    TEST_ASSERT_EQUAL(1, vscf_chunked_alg_info_version(chunked));
    TEST_ASSERT_EQUAL(65536, vscf_chunked_alg_info_chunk_size(chunked));
    TEST_ASSERT_EQUAL_MEMORY(
            test_chunked_nonce_12, vscf_chunked_alg_info_nonce(chunked).bytes, sizeof(test_chunked_nonce_12));
    TEST_ASSERT_EQUAL(sizeof(test_chunked_nonce_12), vscf_chunked_alg_info_nonce(chunked).len);

    vscf_impl_destroy(&restored);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
    vsc_buffer_destroy(&der);
    vscf_impl_destroy(&alg_info);
}

// --------------------------------------------------------------------------
//  Validation: reject bad chunk_size / nonce length / version.
// --------------------------------------------------------------------------
static void
assert_deserialize_rejected(vscf_impl_t *alg_info) {
    vsc_buffer_t *der = serialize_chunked(alg_info);

    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *restored = vscf_alg_info_der_deserializer_deserialize(deserializer, vsc_buffer_data(der), &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ENCRYPTED_DATA, vscf_error_status(&error));
    TEST_ASSERT_NULL(restored);

    vscf_alg_info_der_deserializer_destroy(&deserializer);
    vsc_buffer_destroy(&der);
    vscf_impl_destroy(&alg_info);
}

void
test__deserialize__chunk_size_zero__rejected(void) {
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 1, 0, vsc_data(test_chunked_nonce_12, sizeof(test_chunked_nonce_12))));
    assert_deserialize_rejected(alg_info);
}

void
test__deserialize__chunk_size_over_max__rejected(void) {
    //  MAX is 64 MiB; one byte over.
    vscf_impl_t *alg_info =
            vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(vscf_alg_id_AES256_GCM_CHUNKED, 1,
                    64 * 1024 * 1024 + 1, vsc_data(test_chunked_nonce_12, sizeof(test_chunked_nonce_12))));
    assert_deserialize_rejected(alg_info);
}

void
test__deserialize__nonce_len_8__rejected(void) {
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 1, 65536, vsc_data(test_chunked_nonce_12, 8)));
    assert_deserialize_rejected(alg_info);
}

void
test__deserialize__nonce_len_16__rejected(void) {
    static const byte nonce_16[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 1, 65536, vsc_data(nonce_16, sizeof(nonce_16))));
    assert_deserialize_rejected(alg_info);
}

void
test__deserialize__version_2__rejected(void) {
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 2, 65536, vsc_data(test_chunked_nonce_12, sizeof(test_chunked_nonce_12))));
    assert_deserialize_rejected(alg_info);
}

// --------------------------------------------------------------------------
//  Malformed / truncated DER must return an error and not crash.
// --------------------------------------------------------------------------
void
test__deserialize__truncated_der__error_no_crash(void) {
    vscf_impl_t *alg_info = vscf_chunked_alg_info_impl(vscf_chunked_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM_CHUNKED, 1, 65536, vsc_data(test_chunked_nonce_12, sizeof(test_chunked_nonce_12))));

    vsc_buffer_t *der = serialize_chunked(alg_info);
    vsc_data_t full = vsc_buffer_data(der);

    //  Feed every strict prefix of the valid DER; none may crash, each must
    //  either fail cleanly or (never) succeed with a well-formed structure.
    for (size_t prefix_len = 1; prefix_len < full.len; ++prefix_len) {
        vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
        vscf_alg_info_der_deserializer_setup_defaults(deserializer);

        vscf_error_t error;
        vscf_error_reset(&error);

        vscf_impl_t *restored =
                vscf_alg_info_der_deserializer_deserialize(deserializer, vsc_data(full.bytes, prefix_len), &error);

        //  A truncated buffer must never yield a valid object.
        TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
        TEST_ASSERT_NULL(restored);

        vscf_impl_destroy(&restored);
        vscf_alg_info_der_deserializer_destroy(&deserializer);
    }

    vsc_buffer_destroy(&der);
    vscf_impl_destroy(&alg_info);
}

void
test__deserialize__garbage_der__error_no_crash(void) {
    static const byte garbage[] = {0x30, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *restored =
            vscf_alg_info_der_deserializer_deserialize(deserializer, vsc_data(garbage, sizeof(garbage)), &error);

    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NULL(restored);

    vscf_impl_destroy(&restored);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Test list.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__serialize_deserialize__chunked_alg_info__fields_equal);
    RUN_TEST(test__deserialize__chunk_size_zero__rejected);
    RUN_TEST(test__deserialize__chunk_size_over_max__rejected);
    RUN_TEST(test__deserialize__nonce_len_8__rejected);
    RUN_TEST(test__deserialize__nonce_len_16__rejected);
    RUN_TEST(test__deserialize__version_2__rejected);
    RUN_TEST(test__deserialize__truncated_der__error_no_crash);
    RUN_TEST(test__deserialize__garbage_der__error_no_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
