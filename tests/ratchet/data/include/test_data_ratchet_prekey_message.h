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

#ifndef VIRGIL_CRYPTO_C_TOP_TEST_DATA_RATCHET_MESSAGE_H
#define VIRGIL_CRYPTO_C_TOP_TEST_DATA_RATCHET_MESSAGE_H

#include "vsc_data.h"

extern const uint8_t test_ratchet_prekey_message_protocol_version;
extern const vsc_data_t test_ratchet_prekey_message_sender_identity_key;
extern const vsc_data_t test_ratchet_prekey_message_sender_ephemeral_key;
extern const vsc_data_t test_ratchet_prekey_message_receiver_longterm_key;
extern const vsc_data_t test_ratchet_prekey_message_receiver_onetime_key;
extern const vsc_data_t test_ratchet_prekey_message_message;

extern const uint8_t test_ratchet_prekey_message_protocol_version_big;
extern const vsc_data_t test_ratchet_prekey_message_message_big;


#endif //VIRGIL_CRYPTO_C_TOP_TEST_DATA_RATCHET_MESSAGE_H
