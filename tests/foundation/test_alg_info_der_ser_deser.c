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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ALG_INFO_DER_DESERIALIZER &&VSCF_ASN1RD
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg_info.h"

#include "vscf_kdf_alg_info_defs.h"

#include "vscf_kdf_alg_info.h"

#include "vscf_kdf_alg_info.h"

#include "vscf_alg_info_der_deserializer.h"

#include "vscf_alg_info_der_serializer.h"

#include "test_data_alg_info_ser_deser.h"

#include <stdio.h>

void
test__deserialize_alg_info__sha256_DER(void) {
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(alg_info_der_deserializer);
    vscf_simple_alg_info_t *simple_alg = (vscf_simple_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            alg_info_der_deserializer, test_alg_info_SHA256_DER_DESERIALIZER);

    TEST_ASSERT_EQUAL(vscf_simple_alg_info_alg_id(simple_alg), test_alg_info_DER_SHA256_VALID_OUTPUT);
    vscf_simple_alg_info_delete(simple_alg);
    vscf_alg_info_der_deserializer_delete(alg_info_der_deserializer);
}

void
test__deserialize_alg_info__kdf1_DER(void) {
    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(alg_info_der_deserializer);
    vscf_kdf_alg_info_t *kdf_alg = (vscf_kdf_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            alg_info_der_deserializer, test_alg_info_KDF1_DER_DESERIALIZER);

    TEST_ASSERT_EQUAL(vscf_kdf_alg_info_alg_id(kdf_alg), test_alg_info_DER_KDF1_VALID_OUTPUT);
    vscf_simple_alg_info_t *hash_alg = kdf_alg->hash_alg_info;
    TEST_ASSERT_EQUAL(vscf_simple_alg_info_alg_id(hash_alg), test_alg_info_DER_SHA256_VALID_OUTPUT);
    vscf_kdf_alg_info_delete(kdf_alg);
    vscf_alg_info_der_deserializer_delete(alg_info_der_deserializer);
}

void
test__serialize_alg_info__sha256_DER(void) {
    vscf_alg_info_der_serializer_t *alg_info_der_serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_setup_defaults(alg_info_der_serializer);
    vscf_simple_alg_info_t *simple_alg = vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA256);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_alg_info_der_serializer_serialize_len(alg_info_der_serializer, vscf_simple_alg_info_impl(simple_alg)));
    vscf_alg_info_der_serializer_serialize(alg_info_der_serializer, vscf_simple_alg_info_impl(simple_alg), out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_alg_info_SHA256_DER_DESERIALIZER, out);
    vsc_buffer_delete(out);
    vscf_simple_alg_info_delete(simple_alg);
    vscf_alg_info_der_serializer_delete(alg_info_der_serializer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__deserialize_alg_info__sha256_DER);
    RUN_TEST(test__deserialize_alg_info__kdf1_DER);
    RUN_TEST(test__serialize_alg_info__sha256_DER);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}