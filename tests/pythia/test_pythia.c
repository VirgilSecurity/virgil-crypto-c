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


#define TEST_DEPENDENCIES_AVAILABLE VSCP_PYTHIA
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscp_pythia.h"


// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------
void
test__new__always__returns_not_null(void) {
    vscp_pythia_t *pythia = vscp_pythia_new();

    TEST_ASSERT_NOT_NULL(pythia);

    vscp_pythia_destroy(&pythia);
}

// --------------------------------------------------------------------------
// Happy path tests.
// --------------------------------------------------------------------------
void
test__blind__valid_args___returns_success(void) {
    vscp_pythia_t *pythia = vscp_pythia_new();

    vsc_data_t password = vsc_data((const byte *)"password", 8);

    vsc_buffer_t *blinded_password = vsc_buffer_new_with_capacity(vscp_pythia_blinded_password_buf_len());
    vsc_buffer_t *blinding_secret = vsc_buffer_new_with_capacity(vscp_pythia_blinding_secret_buf_len());

    vscp_error_t result = vscp_pythia_blind(pythia, password, blinded_password, blinding_secret);

    TEST_ASSERT_EQUAL(vscp_SUCCESS, result);

    vsc_buffer_destroy(&blinded_password);
    vsc_buffer_destroy(&blinding_secret);
    vscp_pythia_destroy(&pythia);
}

#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    vscp_global_init();

    RUN_TEST(test__new__always__returns_not_null);
    RUN_TEST(test__blind__valid_args___returns_success);

    vscp_global_cleanup();
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
