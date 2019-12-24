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
#include "test_data_uokms_server_client.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCE_UOKMS_CLIENT
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/phe/vsce_uokms_wrap_rotation.h>

void
test__rotate__mocked_rnd__should_match(void) {
    vsce_uokms_wrap_rotation_t *wrap_rotation = vsce_uokms_wrap_rotation_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_wrap_rotation_setup_defaults(wrap_rotation));

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_wrap_rotation_set_update_token(wrap_rotation, test_uokms_update_token));

    vsc_buffer_t *new_wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_wrap_rotation_update_wrap(wrap_rotation, test_uokms_wrap, new_wrap));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_new_wrap, new_wrap);

    vsc_buffer_destroy(&new_wrap);
    vsce_uokms_wrap_rotation_destroy(&wrap_rotation);
}
#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__rotate__mocked_rnd__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
