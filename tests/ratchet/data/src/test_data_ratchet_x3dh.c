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

#include <test_data_ratchet_x3dh.h>

const byte test_data_ratchet_x3dh_sender_identity_private_key_BYTES[] = {
        0xB6, 0x27, 0x46, 0x06, 0xFC, 0x34, 0x9F, 0x4D,
        0x75, 0xC6, 0x9F, 0xE0, 0x91, 0x08, 0x03, 0x33,
        0x9C, 0xA4, 0x83, 0xEA, 0x93, 0xC1, 0x13, 0x9C,
        0xC5, 0x68, 0x3F, 0x13, 0x1D, 0x82, 0xA2, 0xE7,
};

const byte test_data_ratchet_x3dh_sender_identity_public_key_BYTES[] = {
        0x03, 0x77, 0x13, 0x3C, 0xAB, 0x75, 0x96, 0x20,
        0x63, 0xB5, 0xD0, 0x11, 0xB6, 0x4D, 0x82, 0x3B,
        0xEB, 0xF1, 0xC7, 0x87, 0x1B, 0x50, 0x6F, 0x09,
        0x46, 0xE9, 0xA9, 0xC6, 0xB4, 0x45, 0xEB, 0x07,
};

const byte test_data_ratchet_x3dh_sender_ephemeral_private_key_BYTES[] = {
        0x96, 0x36, 0xD0, 0x41, 0xDD, 0x13, 0x34, 0x38,
        0x81, 0x65, 0x7A, 0x45, 0xA5, 0xCE, 0x85, 0x06,
        0xF6, 0xDB, 0x43, 0xFD, 0xE7, 0x2A, 0xBA, 0x92,
        0xAB, 0x47, 0x21, 0x90, 0xCF, 0xB0, 0x2B, 0xAF,
};

const byte test_data_ratchet_x3dh_sender_ephemeral_public_key_BYTES[] = {
        0x62, 0x58, 0x67, 0x22, 0x9A, 0x34, 0xF8, 0xDB,
        0xC8, 0xB9, 0x0C, 0x32, 0xE0, 0x76, 0x78, 0x7E,
        0x28, 0xA7, 0xE2, 0x93, 0x8D, 0xAE, 0xFD, 0x9D,
        0x07, 0x27, 0xAD, 0x6B, 0x93, 0x90, 0x13, 0x5E,
};

const byte test_data_ratchet_x3dh_receiver_identity_private_key_BYTES[] = {
        0x59, 0x44, 0x9B, 0x5A, 0x13, 0xBE, 0xFE, 0xF5,
        0xE7, 0x4B, 0x44, 0xE7, 0x37, 0x17, 0x84, 0x50,
        0x75, 0x2D, 0x2B, 0xDF, 0x12, 0x15, 0x06, 0xF0,
        0x72, 0xD5, 0x85, 0x6E, 0xB7, 0x9C, 0x46, 0x6D,
};

const byte test_data_ratchet_x3dh_receiver_identity_public_key_BYTES[] = {
        0xAB, 0x25, 0x99, 0x58, 0x02, 0x9F, 0x5C, 0x9B,
        0x2A, 0xD5, 0xF3, 0x36, 0xD3, 0xFE, 0x3F, 0x61,
        0x86, 0x80, 0x0E, 0x87, 0x8B, 0x0C, 0x62, 0x23,
        0x5A, 0x37, 0x95, 0xC4, 0xD7, 0xA5, 0x39, 0x57,
};

const byte test_data_ratchet_x3dh_receiver_long_term_private_key_BYTES[] = {
        0x25, 0x50, 0x5E, 0x5B, 0x59, 0xF6, 0x9D, 0x12,
        0x16, 0x87, 0x17, 0xFC, 0x1F, 0xD4, 0x2E, 0x4A,
        0x0B, 0xD5, 0xF7, 0x63, 0xF8, 0xB8, 0x84, 0x2C,
        0x34, 0xC8, 0x53, 0xAB, 0x93, 0xA9, 0xDB, 0x73,
};

const byte test_data_ratchet_x3dh_receiver_long_term_public_key_BYTES[] = {
        0x45, 0xCC, 0x62, 0x41, 0xA2, 0x65, 0x29, 0xCF,
        0x7D, 0x72, 0x41, 0xD6, 0xF1, 0x8A, 0xC2, 0x62,
        0x33, 0xBC, 0xF5, 0x6D, 0xBB, 0x2A, 0x7F, 0xEA,
        0x1C, 0x8D, 0xC3, 0xC1, 0xE2, 0xFA, 0x94, 0x44,
};

const byte test_data_ratchet_x3dh_receiver_one_time_private_key_BYTES[] = {
        0x61, 0xD8, 0x41, 0x4C, 0xC4, 0xA5, 0xB4, 0x94,
        0xB4, 0x2B, 0x15, 0x61, 0x09, 0xB7, 0xAE, 0x74,
        0x96, 0xE7, 0x0A, 0xA5, 0x67, 0xB6, 0xFE, 0x6F,
        0x09, 0xC0, 0xAD, 0x0A, 0x0E, 0x58, 0xE7, 0x99,
};

const byte test_data_ratchet_x3dh_receiver_one_time_public_key_BYTES[] = {
        0xA0, 0xF7, 0x55, 0x9B, 0x06, 0x9D, 0x82, 0x91,
        0xB7, 0x2C, 0x96, 0x30, 0xE3, 0x35, 0xE7, 0xB3,
        0x48, 0x82, 0xC4, 0x1F, 0x67, 0xA1, 0xFD, 0xAC,
        0x5F, 0xAB, 0x6A, 0xC3, 0x1C, 0x3F, 0x2B, 0x08,
};

const byte test_data_ratchet_x3dh_shared_secret_BYTES[] = {
        0xE3, 0x7F, 0x71, 0x88, 0x0F, 0x82, 0xED, 0x8C,
        0x71, 0xDC, 0xA1, 0xAA, 0x93, 0xA8, 0x06, 0x3D,
        0x8E, 0xEC, 0xCC, 0x0A, 0xD8, 0x5E, 0x59, 0xB2,
        0x36, 0xC6, 0x2B, 0xFE, 0x4A, 0x52, 0x66, 0xD2,
};

const byte test_data_ratchet_x3dh_shared_secret_weak_BYTES[] = {
        0xF6, 0x67, 0x04, 0x25, 0x85, 0x1D, 0xE8, 0x30,
        0x70, 0x77, 0xA4, 0xC4, 0x65, 0x9F, 0x3E, 0xE7,
        0x25, 0x5E, 0xCD, 0x5F, 0x66, 0x38, 0xA5, 0xEE,
        0x65, 0xDF, 0x4D, 0xC3, 0x45, 0x57, 0xE3, 0x0C,
};

const vsc_data_t test_data_ratchet_x3dh_sender_identity_private_key = {
        test_data_ratchet_x3dh_sender_identity_private_key_BYTES, sizeof(test_data_ratchet_x3dh_sender_identity_private_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_sender_identity_public_key = {
        test_data_ratchet_x3dh_sender_identity_public_key_BYTES, sizeof(test_data_ratchet_x3dh_sender_identity_public_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_sender_ephemeral_private_key = {
        test_data_ratchet_x3dh_sender_ephemeral_private_key_BYTES, sizeof(test_data_ratchet_x3dh_sender_ephemeral_private_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_sender_ephemeral_public_key = {
        test_data_ratchet_x3dh_sender_ephemeral_public_key_BYTES, sizeof(test_data_ratchet_x3dh_sender_ephemeral_public_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_identity_private_key = {
        test_data_ratchet_x3dh_receiver_identity_private_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_identity_private_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_identity_public_key = {
        test_data_ratchet_x3dh_receiver_identity_public_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_identity_public_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_long_term_private_key = {
        test_data_ratchet_x3dh_receiver_long_term_private_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_long_term_private_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_long_term_public_key = {
        test_data_ratchet_x3dh_receiver_long_term_public_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_long_term_public_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_one_time_private_key = {
        test_data_ratchet_x3dh_receiver_one_time_private_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_one_time_private_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_receiver_one_time_public_key = {
        test_data_ratchet_x3dh_receiver_one_time_public_key_BYTES, sizeof(test_data_ratchet_x3dh_receiver_one_time_public_key_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_shared_secret = {
        test_data_ratchet_x3dh_shared_secret_BYTES, sizeof(test_data_ratchet_x3dh_shared_secret_BYTES)
};

const vsc_data_t test_data_ratchet_x3dh_shared_secret_weak = {
        test_data_ratchet_x3dh_shared_secret_weak_BYTES, sizeof(test_data_ratchet_x3dh_shared_secret_weak_BYTES)
};
