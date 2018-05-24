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


#include "test_data_aes_256_gcm.h"

//
//  Test vector 1
//  AES-GCM NIST Validation (AES-256,128,0,0,128) #0
//
const byte test_aes_256_gcm_KEY[] = {
    0xfb, 0x80, 0x94, 0xdd, 0x2e, 0xdd, 0xb3, 0xd8,
    0x00, 0x4b, 0xb7, 0x91, 0x34, 0x02, 0x3c, 0xa2,
    0xbe, 0x4d, 0xe9, 0xb6, 0x68, 0xa9, 0xe4, 0x60,
    0x8a, 0xbd, 0xf2, 0x13, 0x0e, 0x8b, 0xec, 0xb8,
};

const byte test_aes_256_gcm_DATA[] = {};

const byte test_aes_256_gcm_NONCE[] = {
    0x49, 0x1a, 0x14, 0xe1, 0x3b, 0x59, 0x1c, 0xf2,
    0xf3, 0x9d, 0xa9, 0x6b, 0x68, 0x82, 0xb5, 0xe5,
};

const byte test_aes_256_gcm_ADD[] = {};

const byte test_aes_256_gcm_ENC[] = {};

const byte test_aes_256_gcm_AUTH_TAG[] = {
    0x80, 0x88, 0x3f, 0x2c, 0x92, 0x54, 0x34, 0xa5,
    0xed, 0xfc, 0xef, 0xd5, 0xb1, 0x23, 0xd5, 0x20,
};


const size_t test_aes_256_gcm_KEY_LEN = sizeof (test_aes_256_gcm_KEY);
const size_t test_aes_256_gcm_DATA_LEN = sizeof (test_aes_256_gcm_DATA);
const size_t test_aes_256_gcm_NONCE_LEN = sizeof (test_aes_256_gcm_NONCE);
const size_t test_aes_256_gcm_ADD_LEN = sizeof (test_aes_256_gcm_ADD);
const size_t test_aes_256_gcm_ENC_LEN = sizeof (test_aes_256_gcm_ENC);
const size_t test_aes_256_gcm_AUTH_TAG_LEN = sizeof (test_aes_256_gcm_AUTH_TAG);
