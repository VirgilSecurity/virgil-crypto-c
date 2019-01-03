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

#include "test_data_ratchet_session.h"

const byte test_ratchet_session_plain_text1_BYTES[] = "Hello, this is first test message";

const byte test_ratchet_session_plain_text2_BYTES[] = "Test message number two";

const byte test_ratchet_session_plain_text3_BYTES[] = "Third message, just to be 100% sure";

const vsc_data_t test_ratchet_session_plain_text1 = {
        test_ratchet_session_plain_text1_BYTES, sizeof(test_ratchet_session_plain_text1_BYTES)
};

const vsc_data_t test_ratchet_session_plain_text2 = {
        test_ratchet_session_plain_text2_BYTES, sizeof(test_ratchet_session_plain_text2_BYTES)
};

const vsc_data_t test_ratchet_session_plain_text3 = {
        test_ratchet_session_plain_text3_BYTES, sizeof(test_ratchet_session_plain_text3_BYTES)
};

const byte test_ratchet_session_alice_identity_private_key_BYTES[] = {
        0x0f, 0xc4, 0x6d, 0x9e, 0x04, 0x49, 0xd7, 0x90,
        0xcb, 0x64, 0xd6, 0xe4, 0xb3, 0x83, 0x24, 0xe9,
        0x5a, 0x70, 0x88, 0xb0, 0x36, 0xea, 0x5b, 0x37,
        0xac, 0x7a, 0x8b, 0x50, 0x3f, 0x8a, 0xec, 0xb9,
};

const byte test_ratchet_session_alice_identity_public_key_BYTES[] = {
        0x28, 0xFE, 0xC1, 0xCF, 0xE2, 0x25, 0x73, 0xD4,
        0x37, 0x16, 0x16, 0xF4, 0x32, 0x54, 0x62, 0x68,
        0xE4, 0xDB, 0xE2, 0xF8, 0x5D, 0xFE, 0x02, 0x94,
        0x72, 0x53, 0xF3, 0x39, 0x49, 0xC1, 0x98, 0x77,
};

const byte test_ratchet_session_alice_ephemeral_private_key_BYTES[] = {
        0x57, 0x7C, 0x66, 0x08, 0x1A, 0xD2, 0x17, 0x8C,
        0x03, 0x9C, 0xD0, 0x98, 0x26, 0xEF, 0x23, 0x64,
        0x7C, 0xC7, 0x71, 0xAC, 0x53, 0xF3, 0x9F, 0xF2,
        0x1E, 0xA8, 0xD4, 0xF7, 0x6F, 0x1D, 0x0B, 0x4C,
};

const byte test_ratchet_session_alice_ephemeral_public_key_BYTES[] = {
        0x93, 0xF7, 0x9D, 0x0E, 0xEA, 0x03, 0x87, 0x27,
        0xC0, 0xBB, 0xFD, 0x02, 0xCC, 0x9D, 0xCC, 0xF4,
        0x70, 0x33, 0x6B, 0xB4, 0xA9, 0x77, 0xF7, 0xA9,
        0xFC, 0x57, 0x1F, 0xEF, 0xE7, 0xEF, 0xA2, 0x3E,
};

const byte test_ratchet_session_alice_ratchet_private_key_BYTES[] = {
        0xA7, 0xD0, 0x77, 0x1B, 0x5C, 0xC3, 0xF9, 0xB3,
        0xAB, 0xD0, 0x0F, 0x48, 0x20, 0xB0, 0xDC, 0xCA,
        0xBB, 0xCF, 0xA0, 0x77, 0xE6, 0x2B, 0x8D, 0xCC,
        0x7A, 0x0D, 0x70, 0xA3, 0x61, 0x02, 0xCC, 0x7C,
};

const byte test_ratchet_session_alice_ratchet_public_key_BYTES[] = {
        0x35, 0xE5, 0x8D, 0xD8, 0x81, 0xE9, 0x59, 0x2F,
        0x51, 0x56, 0x05, 0xB9, 0xA8, 0xD5, 0x62, 0x12,
        0x59, 0xA9, 0xF2, 0xF6, 0x20, 0x94, 0xC3, 0x94,
        0x93, 0x1F, 0x96, 0x3B, 0xF8, 0xF2, 0x5E, 0x76,
};

const byte test_ratchet_session_bob_identity_private_key_BYTES[] = {
        0x1f, 0xf1, 0x32, 0x35, 0xb0, 0xbe, 0x13, 0xa9,
        0x91, 0xcd, 0xa7, 0xd4, 0x0f, 0x8b, 0x56, 0xb5,
        0xf8, 0x27, 0xaf, 0x54, 0x1a, 0x05, 0x06, 0xe9,
        0x05, 0x6f, 0x45, 0x54, 0x1a, 0x95, 0xd8, 0x28,
};

const byte test_ratchet_session_bob_identity_public_key_BYTES[] = {
        0xA5, 0x65, 0x8F, 0xBE, 0xE0, 0x29, 0xFD, 0x54,
        0x11, 0xA0, 0xD6, 0x4D, 0xD6, 0x0D, 0x07, 0x1A,
        0x9D, 0x66, 0x65, 0x1E, 0x59, 0xE0, 0xFE, 0xBD,
        0x07, 0x92, 0xBB, 0x8E, 0x7C, 0x06, 0xDD, 0x20,
};

const byte test_ratchet_session_bob_long_term_private_key_BYTES[] = {
        0xee, 0x8a, 0xc3, 0x6c, 0xa3, 0x2a, 0xd1, 0xbf,
        0xed, 0x76, 0xca, 0x49, 0x4d, 0xda, 0x95, 0xbe,
        0x18, 0x24, 0x79, 0x43, 0x6e, 0x2f, 0xf9, 0x19,
        0x2a, 0x54, 0xb2, 0xad, 0x64, 0x9d, 0x2d, 0x68,
};

const byte test_ratchet_session_bob_long_term_public_key_BYTES[] = {
        0xCD, 0x5F, 0x9F, 0x2E, 0x84, 0xC4, 0x11, 0xC2,
        0x40, 0x7C, 0x22, 0xB4, 0x30, 0x21, 0xFD, 0x52,
        0x1C, 0x85, 0xA5, 0xB6, 0x01, 0x78, 0xA7, 0x86,
        0xCB, 0x15, 0xDA, 0xAE, 0x27, 0xC4, 0x1B, 0x08,
};

const byte test_ratchet_session_bob_long_term_key_id_BYTES[] = {
        0xb7, 0x7c, 0xf2, 0x59, 0x90, 0xef, 0xa1, 0xa1,
};

const byte test_ratchet_session_bob_one_time_private_key_BYTES[] = {
        0xf3, 0xd9, 0x47, 0x7c, 0x91, 0x27, 0x2c, 0xa0,
        0x0f, 0x9f, 0x9a, 0x5c, 0x07, 0x02, 0x05, 0xc1,
        0x39, 0x2b, 0x1c, 0xf6, 0x24, 0x11, 0xb1, 0x9e,
        0x6e, 0x07, 0x24, 0x3f, 0xf6, 0xdf, 0x58, 0xe2,
};

const byte test_ratchet_session_bob_one_time_public_key_BYTES[] = {
        0x49, 0xE5, 0xAC, 0xC2, 0x95, 0x9F, 0xEC, 0x37,
        0xA4, 0x14, 0x59, 0x06, 0x99, 0x80, 0x81, 0xD1,
        0x77, 0x67, 0x82, 0xC5, 0x41, 0x4E, 0xAE, 0x34,
        0x35, 0x38, 0x4F, 0xEE, 0xE1, 0x47, 0xC0, 0x1D,
};

const byte test_ratchet_session_bob_one_time_key_id_BYTES[] = {
        0x40, 0x7b, 0x5b, 0x5d, 0x68, 0x66, 0x39, 0x23,
};

const vsc_data_t test_ratchet_session_alice_identity_private_key = {
        test_ratchet_session_alice_identity_private_key_BYTES, sizeof(test_ratchet_session_alice_identity_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_alice_identity_public_key = {
        test_ratchet_session_alice_identity_public_key_BYTES, sizeof(test_ratchet_session_alice_identity_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_alice_ephemeral_private_key = {
        test_ratchet_session_alice_ephemeral_private_key_BYTES, sizeof(test_ratchet_session_alice_ephemeral_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_alice_ephemeral_public_key = {
        test_ratchet_session_alice_ephemeral_public_key_BYTES, sizeof(test_ratchet_session_alice_ephemeral_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_alice_ratchet_private_key = {
        test_ratchet_session_alice_ratchet_private_key_BYTES, sizeof(test_ratchet_session_alice_ratchet_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_alice_ratchet_public_key = {
        test_ratchet_session_alice_ratchet_public_key_BYTES, sizeof(test_ratchet_session_alice_ratchet_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_identity_private_key = {
        test_ratchet_session_bob_identity_private_key_BYTES, sizeof(test_ratchet_session_bob_identity_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_identity_public_key = {
        test_ratchet_session_bob_identity_public_key_BYTES, sizeof(test_ratchet_session_bob_identity_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_long_term_private_key = {
        test_ratchet_session_bob_long_term_private_key_BYTES, sizeof(test_ratchet_session_bob_long_term_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_long_term_public_key = {
        test_ratchet_session_bob_long_term_public_key_BYTES, sizeof(test_ratchet_session_bob_long_term_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_long_term_key_id = {
        test_ratchet_session_bob_long_term_key_id_BYTES, sizeof(test_ratchet_session_bob_long_term_key_id_BYTES)
};

const vsc_data_t test_ratchet_session_bob_one_time_private_key = {
        test_ratchet_session_bob_one_time_private_key_BYTES, sizeof(test_ratchet_session_bob_one_time_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_one_time_public_key = {
        test_ratchet_session_bob_one_time_public_key_BYTES, sizeof(test_ratchet_session_bob_one_time_public_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_one_time_key_id = {
        test_ratchet_session_bob_one_time_key_id_BYTES, sizeof(test_ratchet_session_bob_one_time_key_id_BYTES)
};
