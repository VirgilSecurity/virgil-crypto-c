//  Copyright (C) 2015-2021 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE (VSSQ_MESSENGER)
#if TEST_DEPENDENCIES_AVAILABLE


#include "test_comm_kit_utils.h"

#include "vssq_messenger.h"
#include "vssq_contact_utils.h"
#include "vssq_error_message.h"

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_binary.h>


void
test__messenger_vhost_register__random_user__success(void) {
    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *messenger = create_vhost_messenger_and_register_user();

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger);
}

void
test__messenger_vhost_register_then_authenticate__random_user__success(void) {
    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *messenger_for_registration = create_vhost_messenger_and_register_user();
    vssq_messenger_t *messenger_for_authentication = create_messenger();

    //
    //  Authenticate.
    //
    const vssq_messenger_creds_t *creds = vssq_messenger_creds(messenger_for_registration);
    const vssq_status_t authenticate_status = vssq_messenger_authenticate(messenger_for_authentication, creds);
    TEST_ASSERT_EQUAL_MESSAGE(
            vssq_status_SUCCESS, authenticate_status, vssq_error_message_from_status(authenticate_status).chars);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&messenger_for_registration);
    vssq_messenger_destroy(&messenger_for_authentication);
}

void
test__messenger_vhost_find_user_with_username__random_user__success(void) {
    vssq_error_t error;
    vssq_error_reset(&error);

    //
    //  Create messenger and random username.
    //
    vssq_messenger_t *bob_messenger = create_vhost_messenger_and_register_user();
    vssq_messenger_t *alice_messenger = create_vhost_messenger_and_register_user();

    //
    //  Alice try to find Bob.
    //
    vssq_messenger_user_t *user_bob =
            vssq_messenger_find_user_with_username(alice_messenger, vssq_messenger_username(bob_messenger), &error);

    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, error.status, vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(user_bob);

    //
    //  Bob try to find Alice.
    //
    vssq_messenger_user_t *user_alice =
            vssq_messenger_find_user_with_username(bob_messenger, vssq_messenger_username(alice_messenger), &error);

    TEST_ASSERT_EQUAL_MESSAGE(vssq_status_SUCCESS, error.status, vssq_error_message_from_error(&error).chars);
    TEST_ASSERT_NOT_NULL(user_alice);

    //
    //  Cleanup.
    //
    vssq_messenger_destroy(&bob_messenger);
    vssq_messenger_destroy(&alice_messenger);
    vssq_messenger_user_destroy(&user_bob);
    vssq_messenger_user_destroy(&user_alice);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__messenger_vhost_register__random_user__success);
    RUN_TEST(test__messenger_vhost_register_then_authenticate__random_user__success);
    RUN_TEST(test__messenger_vhost_find_user_with_username__random_user__success);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
