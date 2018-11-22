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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_PKCS8_DER_SERIALIZER &&VSCF_ASN1RD
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_data_rsa.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_pkcs8_der_serializer.h"
#include "vscf_rsa_private_key.h"
#include "vscf_rsa_public_key.h"


// --------------------------------------------------------------------------
// PKCS#8 RSA keys.
// --------------------------------------------------------------------------

void
test__serialized_public_key_len__rsa2048__greater_then_293(void) {
#if VSCF_RSA_PUBLIC_KEY
    vscf_pkcs8_der_serializer_impl_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_rsa_public_key_impl_t *rsa_public_key = vscf_rsa_public_key_new();
    vscf_rsa_public_key_take_asn1rd(rsa_public_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_public_key_import_public_key(rsa_public_key, test_rsa_2048_PUBLIC_KEY_PKCS1);

    size_t len = vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8, vscf_rsa_public_key_impl(rsa_public_key));

    TEST_ASSERT_GREATER_OR_EQUAL(293, len);

    vscf_rsa_public_key_destroy(&rsa_public_key);
    vscf_pkcs8_der_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PUBLIC_KEY is disabled");
#endif
}

void
test__serialize_public_key__rsa2048__equals_to_rsa_2048_public_key_pkcs8_der(void) {
#if VSCF_RSA_PUBLIC_KEY
    vscf_pkcs8_der_serializer_impl_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_rsa_public_key_impl_t *rsa_public_key = vscf_rsa_public_key_new();
    vscf_rsa_public_key_take_asn1rd(rsa_public_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_public_key_take_asn1wr(rsa_public_key, vscf_asn1wr_impl(vscf_asn1wr_new()));
    vscf_rsa_public_key_import_public_key(rsa_public_key, test_rsa_2048_PUBLIC_KEY_PKCS1);

    size_t len = vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8, vscf_rsa_public_key_impl(rsa_public_key));
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    vscf_pkcs8_der_serializer_serialize_public_key(pkcs8, vscf_rsa_public_key_impl(rsa_public_key), out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PUBLIC_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_rsa_public_key_destroy(&rsa_public_key);
    vscf_pkcs8_der_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PUBLIC_KEY is disabled");
#endif
}

void
test__serialized_private_key_len__rsa2048__greater_then_1216(void) {
#if VSCF_RSA_PRIVATE_KEY
    vscf_pkcs8_der_serializer_impl_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_rsa_private_key_impl_t *rsa_private_key = vscf_rsa_private_key_new();
    vscf_rsa_private_key_take_asn1rd(rsa_private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_import_private_key(rsa_private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);

    size_t len =
            vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8, vscf_rsa_private_key_impl(rsa_private_key));

    TEST_ASSERT_GREATER_OR_EQUAL(1216, len);

    vscf_rsa_private_key_destroy(&rsa_private_key);
    vscf_pkcs8_der_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PRIVATE_KEY is disabled");
#endif
}

void
test__serialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs8_der(void) {
#if VSCF_RSA_PRIVATE_KEY
    vscf_pkcs8_der_serializer_impl_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_rsa_private_key_impl_t *rsa_private_key = vscf_rsa_private_key_new();
    vscf_rsa_private_key_take_asn1rd(rsa_private_key, vscf_asn1rd_impl(vscf_asn1rd_new()));
    vscf_rsa_private_key_take_asn1wr(rsa_private_key, vscf_asn1wr_impl(vscf_asn1wr_new()));
    vscf_rsa_private_key_import_private_key(rsa_private_key, test_rsa_2048_PRIVATE_KEY_PKCS1);

    size_t len =
            vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8, vscf_rsa_private_key_impl(rsa_private_key));
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(len);

    vscf_pkcs8_der_serializer_serialize_private_key(pkcs8, vscf_rsa_private_key_impl(rsa_private_key), out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PRIVATE_KEY_PKCS8_DER, out);

    vsc_buffer_destroy(&out);
    vscf_rsa_private_key_destroy(&rsa_private_key);
    vscf_pkcs8_der_serializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PRIVATE_KEY is disabled");
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
    RUN_TEST(test__serialized_private_key_len__rsa2048__greater_then_1216);
    RUN_TEST(test__serialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs8_der);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
