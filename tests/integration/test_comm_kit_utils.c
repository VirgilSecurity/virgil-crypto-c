//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "test_comm_kit_utils.h"

#include "unity.h"
#include "test_utils.h"

#include "vssq_messenger.h"
#include "vssq_contact_utils.h"

#include <virgil/crypto/common/vsc_str_buffer.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_binary.h>

static vsc_str_buffer_t *
generate_random_username(void) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();

    if (vscf_ctr_drbg_setup_defaults(ctr_drbg) != vscf_status_SUCCESS) {
        TEST_FAIL_MESSAGE("Can not initialize RNG.");
    }

    const vsc_str_t username_prefix = vsc_str_from_str("test_");

    const size_t random_bytes_len = (vssq_contact_utils_USERNAME_LEN_MAX - username_prefix.len) >> 1;
    vsc_buffer_t *random_bytes = vsc_buffer_new_with_capacity(random_bytes_len);

    if (vscf_ctr_drbg_random(ctr_drbg, random_bytes_len, random_bytes) != vscf_status_SUCCESS) {
        TEST_FAIL_MESSAGE("Random failed.");
    }

    vsc_str_buffer_t *username = vsc_str_buffer_new_with_capacity(vssq_contact_utils_USERNAME_LEN_MAX);
    vsc_str_buffer_write_str(username, username_prefix);

    vscf_binary_to_hex(vsc_buffer_data(random_bytes), username);

    vsc_buffer_destroy(&random_bytes);
    vscf_ctr_drbg_destroy(&ctr_drbg);

    return username;
}


vssq_messenger_t *
create_messenger(void) {
    //
    //  Configure.
    //
    vsc_str_t base_url = vsc_str_from_str("https://messenger-dev.virgilsecurity.com");
    vsc_str_t contact_discovery_url = vsc_str_from_str("https://disco-dev-va.virgilsecurity.com");
    vsc_str_t ejabberd_url = vsc_str_from_str("xmpp-dev.virgilsecurity.com");

    vssq_messenger_config_t *config = vssq_messenger_config_new_with(base_url, contact_discovery_url, ejabberd_url);

    vssq_messenger_t *messenger = vssq_messenger_new_with_config(config);
    const vssq_status_t status = vssq_messenger_setup_defaults(messenger);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(status);

    vssq_messenger_config_destroy(&config);

    return messenger;
}


vssq_messenger_t *
create_messenger_and_register_user(void) {

    vssq_messenger_t *messenger = create_messenger();
    vsc_str_buffer_t *username = generate_random_username();

    const vssq_status_t status = vssq_messenger_register(messenger, vsc_str_buffer_str(username));
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(status);

    vsc_str_buffer_destroy(&username);

    return messenger;
}

vssq_messenger_t *
create_vhost_messenger(void) {
    //
    //  Configure.
    //
    vsc_str_t base_url = vsc_str_from_str("https://messenger-dev.virgilsecurity.com");
    vsc_str_t contact_discovery_url = vsc_str_from_str("https://disco-dev-va.virgilsecurity.com");
    vsc_str_t ejabberd_url = vsc_str_from_str("xmpp-dev.virgilsecurity.com");
    vsc_str_t vhost_id = vsc_str_from_str("be166cd051053f913fc28b5fc70adc67");

    vssq_messenger_config_t *config = vssq_messenger_config_new_with(base_url, contact_discovery_url, ejabberd_url);
    vssq_messenger_config_set_default_vhost_id(config, vhost_id);

    vssq_messenger_t *messenger = vssq_messenger_new_with_config(config);
    const vssq_status_t status = vssq_messenger_setup_defaults(messenger);
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(status);

    vssq_messenger_config_destroy(&config);

    return messenger;
}


vssq_messenger_t *
create_vhost_messenger_and_register_user(void) {

    vssq_messenger_t *messenger = create_vhost_messenger();
    vsc_str_buffer_t *username = generate_random_username();

    const vssq_status_t status = vssq_messenger_register(messenger, vsc_str_buffer_str(username));
    TEST_ASSERT_VSSQ_STATUS_SUCCESS(status);

    vsc_str_buffer_destroy(&username);

    return messenger;
}
