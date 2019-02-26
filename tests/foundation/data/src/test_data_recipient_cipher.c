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


#include "test_data_recipient_cipher.h"

//  "Virgil Security Library for C"
static const byte MESSAGE_BYTES[] = {
    0x56, 0x69, 0x72, 0x67, 0x69, 0x6c, 0x20, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20,
    0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x43, 0x0a
};

vsc_data_t test_data_recipient_cipher_MESSAGE = {
    MESSAGE_BYTES, sizeof(MESSAGE_BYTES)
};

static byte ED25519_RECIPIENT_ID[] = {
    0x6A, 0x07, 0x82, 0x58, 0xDF, 0x74, 0x4E, 0x6A,
    0x91, 0xEF, 0x00, 0x40, 0x57, 0xFA, 0xA4, 0xB2,
    0x4D, 0x33, 0x9F, 0xB1, 0xC0, 0x3D, 0x6C, 0x19,
    0xC5, 0xED, 0x52, 0xEB, 0xB5, 0x20, 0xA3, 0xB4,
};

vsc_data_t test_data_recipient_cipher_ED25519_RECIPIENT_ID = {
    ED25519_RECIPIENT_ID, sizeof(ED25519_RECIPIENT_ID)
};

static byte ED25519_PUBLIC_KEY_BYTES[] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70, 0x03, 0x21, 0x00, 0x86, 0x61, 0x40, 0x74,
    0xb7, 0xa5, 0xd1, 0x13, 0x04, 0x48, 0xbe, 0x69,
    0xa4, 0xa2, 0x5c, 0xe5, 0x8d, 0xbf, 0x76, 0x0a,
    0x87, 0xbb, 0xf9, 0x2a, 0x03, 0xad, 0xd9, 0x73,
    0xf3, 0x8e, 0xce, 0x7c
};

vsc_data_t test_data_recipient_cipher_ED25519_PUBLIC_KEY = {
    ED25519_PUBLIC_KEY_BYTES, sizeof(ED25519_PUBLIC_KEY_BYTES)
};

static byte ED25519_PRIVATE_KEY_BYTES[] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x10, 0xda, 0x87, 0x56, 0x6b, 0x44, 0x6e, 0xdb,
    0x74, 0xaf, 0xa6, 0xeb, 0x67, 0x54, 0x77, 0x43,
    0x67, 0x08, 0x1e, 0xfa, 0x5f, 0xcd, 0x39, 0xc1,
    0x9e, 0x64, 0xa3, 0x68, 0x30, 0x44, 0x5b, 0x1b,
};

vsc_data_t test_data_recipient_cipher_ED25519_PRIVATE_KEY = {
    ED25519_PRIVATE_KEY_BYTES, sizeof(ED25519_PRIVATE_KEY_BYTES)
};
