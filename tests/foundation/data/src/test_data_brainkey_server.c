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


#include "test_data_brainkey_server.h"

const byte test_data_brainkey_server_fake_rng_BYTES[] = {
        0xdc, 0x73, 0x26, 0x4d, 0x23, 0x78, 0x91, 0x81,
        0xf0, 0x66, 0x8b, 0x79, 0x18, 0xac, 0xf0, 0x88,
        0x77, 0xd5, 0xb3, 0xdd, 0xa6, 0xa8, 0x4e, 0x67,
        0x55, 0xfe, 0xa9, 0x75, 0xbf, 0x0b, 0x54, 0xf3,
};

const byte test_data_brainkey_server_fake_identity_secret_BYTES[] = {
        0xdc, 0x73, 0x26, 0x4d, 0x23, 0x78, 0x91, 0x81,
        0xf0, 0x66, 0x8b, 0x79, 0x18, 0xac, 0xf0, 0x88,
        0x77, 0xd5, 0xb3, 0xdd, 0xa6, 0xa8, 0x4e, 0x67,
        0x55, 0xfe, 0xa9, 0x75, 0xbf, 0x0b, 0x54, 0xf3,
};

const byte test_data_brainkey_server_identity_secret_BYTES[] = {
        0xB1, 0x5C, 0x6A, 0x6C, 0x06, 0x6D, 0xEC, 0xDB,
        0x32, 0x57, 0x48, 0x9F, 0x2B, 0xC8, 0xAB, 0xA0,
        0xAB, 0x41, 0x22, 0x13, 0xCD, 0xBC, 0x2B, 0xD6,
        0x50, 0x33, 0x40, 0x61, 0x4C, 0xB2, 0x39, 0xAA,
};

const byte test_data_brainkey_server_blinded_point_BYTES[] = {
        0x04, 0x62, 0xD5, 0x45, 0x08, 0xBA, 0x89, 0xDA,
        0x4E, 0xEA, 0x0F, 0x63, 0xD2, 0x17, 0x76, 0xCC,
        0x23, 0xEE, 0x3C, 0x35, 0xD7, 0x3D, 0xE5, 0x9D,
        0xFC, 0x04, 0xEC, 0xF1, 0x32, 0xAE, 0x45, 0xAE,
        0x16, 0xAD, 0xA1, 0xE0, 0xB7, 0xD4, 0xEB, 0x80,
        0xE4, 0x13, 0x48, 0x27, 0x05, 0x5D, 0x3B, 0xB9,
        0x84, 0x63, 0x15, 0xFF, 0xBB, 0x7A, 0xF9, 0x77,
        0x08, 0x08, 0xFB, 0x85, 0x33, 0x57, 0xF4, 0x59,
        0xB7
};

const byte test_data_brainkey_server_hardened_point_BYTES[] = {
        0x04, 0xCD, 0xBB, 0x64, 0x56, 0x69, 0x85, 0x13,
        0x68, 0x6C, 0x91, 0x1D, 0xD5, 0xA7, 0xC8, 0x1A,
        0xDA, 0x50, 0xDF, 0x08, 0x3F, 0x6F, 0xD7, 0xDD,
        0xA5, 0x46, 0xA6, 0xAB, 0xDE, 0xD6, 0x0A, 0x97,
        0xB5, 0xA1, 0x06, 0x18, 0x41, 0x6F, 0x2D, 0x4D,
        0x33, 0x3F, 0x29, 0x55, 0x4B, 0x73, 0x59, 0x81,
        0x33, 0xDC, 0xD0, 0x2C, 0x8A, 0x2D, 0x0B, 0xCE,
        0xE4, 0xB8, 0x55, 0x8A, 0x4E, 0x40, 0xBE, 0xEA,
        0x0E
};

const vsc_data_t test_data_brainkey_server_identity_secret = {
        test_data_brainkey_server_identity_secret_BYTES, sizeof(test_data_brainkey_server_identity_secret_BYTES)
};

const vsc_data_t test_data_brainkey_server_blinded_point = {
        test_data_brainkey_server_blinded_point_BYTES, sizeof(test_data_brainkey_server_blinded_point_BYTES)
};

const vsc_data_t test_data_brainkey_server_hardened_point = {
        test_data_brainkey_server_hardened_point_BYTES, sizeof(test_data_brainkey_server_hardened_point_BYTES)
};

const vsc_data_t test_data_brainkey_server_fake_rng = {
        test_data_brainkey_server_fake_rng_BYTES, sizeof(test_data_brainkey_server_fake_rng_BYTES)
};

const vsc_data_t test_data_brainkey_server_fake_identity_secret = {
        test_data_brainkey_server_fake_identity_secret_BYTES, sizeof(test_data_brainkey_server_fake_identity_secret_BYTES)
};


