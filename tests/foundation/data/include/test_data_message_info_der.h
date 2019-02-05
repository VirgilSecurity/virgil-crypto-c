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

#include "vsc_data.h"

typedef struct {
    const vsc_data_t serialized;
    const vsc_data_t recipient_id;
    const vsc_data_t encrypted_key;
    const vsc_data_t data_encryption_alg_nonce;
} test_one_key_recipient_cms_t;

typedef struct {
    const vsc_data_t serialized;
    const vsc_data_t kdf_salt;
    const size_t kdf_iteration_count;
    const vsc_data_t key_encryption_alg_nonce;
    const vsc_data_t data_encryption_alg_nonce;
    const vsc_data_t encrypted_key;
} test_one_password_recipient_cms_t;

typedef struct {
    const vsc_data_t serialized;
    const vsc_data_t key_recipient1_id;
    const vsc_data_t key_recipient1_alg_oid;
    const vsc_data_t key_recipient2_id;
    const vsc_data_t key_recipient2_alg_oid;
    const vsc_data_t pwd_recipient3_key_derivation_alg_oid;
    const vsc_data_t pwd_recipient3_key_encryption_alg_oid;
    const vsc_data_t data_alg_nonce;
} test_multiple_recipients_cms_t;


extern const test_one_key_recipient_cms_t test_message_info_cms_ONE_RSA2048_KEY_RECIPIENT;
extern const test_one_key_recipient_cms_t test_message_info_cms_V2_ONE_RSA2048_KEY_RECIPIENT;
// extern const test_one_key_recipient_cms_t test_message_info_cms_ONE_ED25519_KEY_RECIPIENT;
extern const test_one_password_recipient_cms_t test_message_info_cms_ONE_PASSWORD_RECIPIENT;
// extern const test_multiple_recipients_cms_t test_message_info_cms_MULTIPLE_RECIPIENTS;
