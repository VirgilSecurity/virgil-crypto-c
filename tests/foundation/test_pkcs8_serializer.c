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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_PKCS8_SERIALIZER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_pkcs8_serializer.h"
#include "vscf_simple_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_chained_key_alg_info.h"

#include "test_data_rsa.h"
#include "test_data_ed25519.h"
#include "test_data_curve25519.h"
#include "test_data_round5.h"
#include "test_data_falcon.h"
#include "test_data_compound_key.h"
#include "test_data_chained_key.h"


// --------------------------------------------------------------------------
// PKCS#8 RSA keys.
// --------------------------------------------------------------------------
void
test__serialized_public_key_len__rsa2048__greater_then_293(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_rsa_2048_PUBLIC_KEY_PKCS1, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    TEST_ASSERT_GREATER_OR_EQUAL(293, len);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_public_key__rsa2048__equals_to_rsa_2048_public_key_pkcs8_der(void) {

    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_rsa_2048_PUBLIC_KEY_PKCS1, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialized_private_key_len__rsa2048__greater_then_1214(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    TEST_ASSERT_GREATER_OR_EQUAL(1214, len);

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs8_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}


// --------------------------------------------------------------------------
// PKCS#8 ed25519 keys.
// --------------------------------------------------------------------------
void
test__serialized_public_key_len__ed25519__greater_then_44(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    TEST_ASSERT_GREATER_OR_EQUAL(44, len);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_public_key__ed25519__equals_to_ed25519_public_key_pkcs8_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ed25519_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialized_private_key_len__ed25519__greater_then_48(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(test_ed25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    TEST_ASSERT_GREATER_OR_EQUAL(48, len);

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_private_key__ed25519__equals_to_ed25519_private_key_pkcs8_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(test_ed25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ed25519_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

// --------------------------------------------------------------------------
// PKCS#8 curve25519 keys.
// --------------------------------------------------------------------------
void
test__serialized_public_key_len__curve25519__greater_then_44(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_curve25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    TEST_ASSERT_GREATER_OR_EQUAL(44, len);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_public_key__curve25519__equals_to_curve25519_public_key_pkcs8_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_curve25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_curve25519_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialized_private_key_len__curve25519__greater_then_48(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    TEST_ASSERT_GREATER_OR_EQUAL(48, len);

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_private_key__curve25519__equals_to_curve25519_private_key_pkcs8_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_curve25519_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}


// --------------------------------------------------------------------------
// PKCS#8 Post-Quantum Keys.
// --------------------------------------------------------------------------
void
test__serialize_public_key__round5__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));

    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_round5_ND_5PKE_5D_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5PKE_5D_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__serialize_private_key__round5__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));

    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_round5_ND_5PKE_5D_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5PKE_5D_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__serialize_public_key__falcon__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_FALCON));

    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_falcon_PUBLIC_KEY_512, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_falcon_PUBLIC_KEY_512_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__serialize_private_key__falcon__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_FALCON));

    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_falcon_PRIVATE_KEY_512, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_falcon_PRIVATE_KEY_512_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

// --------------------------------------------------------------------------
// PKCS#8 Compound Keys.
// --------------------------------------------------------------------------
void
test__serialize_public_key__compound_curve25519_ed25519__equals_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *ed25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &curve25519_alg_info, &ed25519_alg_info));

    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_private_key__compound_curve25519_ed25519__equals_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *ed25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));

    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &curve25519_alg_info, &ed25519_alg_info));

    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

// --------------------------------------------------------------------------
// PKCS#8 Chained Keys.
// --------------------------------------------------------------------------
void
test__serialize_public_key__chained_curve25519_curve25519__equals_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *l1_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *l2_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_curve25519_alg_info, &l2_curve25519_alg_info));

    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_chained_key_CURVE25519_CURVE25519_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_chained_key_CURVE25519_CURVE25519_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_private_key__chained_curve25519_curve25519__equals_der(void) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *l1_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *l2_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_curve25519_alg_info, &l2_curve25519_alg_info));

    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_chained_key_CURVE25519_CURVE25519_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_chained_key_CURVE25519_CURVE25519_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
}

void
test__serialize_public_key__chained_curve25519_round5__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *l1_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *l2_round5_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));

    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_curve25519_alg_info, &l2_round5_alg_info));

    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PUBLIC_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__serialize_private_key__chained_curve25519_round5__equals_der(void) {
#if VSCF_POST_QUANTUM
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_impl_t *l1_curve25519_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));

    vscf_impl_t *l2_round5_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));

    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_curve25519_alg_info, &l2_round5_alg_info));

    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(
            test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PRIVATE_KEY, &alg_info);

    size_t len = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);
    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_pkcs8_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__serialized_public_key_len__rsa2048__greater_then_293);
    RUN_TEST(test__serialize_public_key__rsa2048__equals_to_rsa_2048_public_key_pkcs8_der);
    RUN_TEST(test__serialized_private_key_len__rsa2048__greater_then_1214);
    RUN_TEST(test__serialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs8_der);

    RUN_TEST(test__serialized_public_key_len__ed25519__greater_then_44);
    RUN_TEST(test__serialize_public_key__ed25519__equals_to_ed25519_public_key_pkcs8_der);
    RUN_TEST(test__serialized_private_key_len__ed25519__greater_then_48);
    RUN_TEST(test__serialize_private_key__ed25519__equals_to_ed25519_private_key_pkcs8_der);

    RUN_TEST(test__serialized_public_key_len__curve25519__greater_then_44);
    RUN_TEST(test__serialize_public_key__curve25519__equals_to_curve25519_public_key_pkcs8_der);
    RUN_TEST(test__serialized_private_key_len__curve25519__greater_then_48);
    RUN_TEST(test__serialize_private_key__curve25519__equals_to_curve25519_private_key_pkcs8_der);

    RUN_TEST(test__serialize_public_key__round5__equals_der);
    RUN_TEST(test__serialize_private_key__round5__equals_der);
    RUN_TEST(test__serialize_public_key__falcon__equals_der);
    RUN_TEST(test__serialize_private_key__falcon__equals_der);

    RUN_TEST(test__serialize_public_key__compound_curve25519_ed25519__equals_der);
    RUN_TEST(test__serialize_private_key__compound_curve25519_ed25519__equals_der);

    RUN_TEST(test__serialize_public_key__chained_curve25519_curve25519__equals_der);
    RUN_TEST(test__serialize_private_key__chained_curve25519_curve25519__equals_der);
    RUN_TEST(test__serialize_public_key__chained_curve25519_round5__equals_der);
    RUN_TEST(test__serialize_private_key__chained_curve25519_round5__equals_der);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
