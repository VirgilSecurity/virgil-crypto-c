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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_MESSAGE_INFO && VSCF_CMS && VSCF_SIMPLE_ALG_INFO && VSCF_CIPHER_ALG_INFO)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_cms.h"
#include "vscf_message_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_simple_alg_info.h"

#include "test_data_message_info_cms.h"


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
test__serialize__one_rsa2048_key_recipient__returns_valid_cms(void) {

    vscf_impl_t *key_encryption_alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));

    vscf_key_recipient_info_t *key_recipient =
            vscf_key_recipient_info_new_with_members(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.recipient_id,
                    &key_encryption_alg_info, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.encrypted_key);

    vscf_impl_t *data_encryption_alg_info = vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.data_encryption_alg_nonce));


    vscf_message_info_t *message_info = vscf_message_info_new();
    vscf_message_info_add_key_recipient(message_info, &key_recipient);
    vscf_message_info_set_data_encryption_alg_info(message_info, data_encryption_alg_info);

    vscf_cms_t *cms = vscf_cms_new();
    vscf_cms_setup_defaults(cms);

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_cms_serialized_len(cms, message_info));
    vscf_cms_serialize(cms, message_info, out);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT.serialized, out);

    vsc_buffer_destroy(&out);
    vscf_cms_destroy(&cms);
    vscf_message_info_destroy(&message_info);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__serialize__one_rsa2048_key_recipient__returns_valid_cms);

#if TEST_DEPENDENCIES_AVAILABLE
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
