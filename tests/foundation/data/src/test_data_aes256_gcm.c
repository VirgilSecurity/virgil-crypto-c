//  Copyright (C) 2015-2022 Virgil Security, Inc.
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


#include "test_data_aes256_gcm.h"

//
//  Test vector 1
//  AES-GCM NIST Validation (AES-256,128,0,0,128) #0
//
const vsc_data_t test_aes256_gcm_VECTOR_1_DATA = {(const byte *)0xDEADBEAF, 0};

const vsc_data_t test_aes256_gcm_VECTOR_1_ENC = {(const byte *)0xDEADBEAF, 0};

const byte test_aes256_gcm_VECTOR_1_KEY_BYTES[] = {
    0xfb, 0x80, 0x94, 0xdd, 0x2e, 0xdd, 0xb3, 0xd8,
    0x00, 0x4b, 0xb7, 0x91, 0x34, 0x02, 0x3c, 0xa2,
    0xbe, 0x4d, 0xe9, 0xb6, 0x68, 0xa9, 0xe4, 0x60,
    0x8a, 0xbd, 0xf2, 0x13, 0x0e, 0x8b, 0xec, 0xb8,
};

const vsc_data_t test_aes256_gcm_VECTOR_1_KEY = {
    test_aes256_gcm_VECTOR_1_KEY_BYTES, sizeof(test_aes256_gcm_VECTOR_1_KEY_BYTES)
};

const byte test_aes256_gcm_VECTOR_1_NONCE_BYTES[] = {
    0x49, 0x1a, 0x14, 0xe1, 0x3b, 0x59, 0x1c, 0xf2,
    0xf3, 0x9d, 0xa9, 0x6b
};

const vsc_data_t test_aes256_gcm_VECTOR_1_NONCE = {
    test_aes256_gcm_VECTOR_1_NONCE_BYTES, sizeof(test_aes256_gcm_VECTOR_1_NONCE_BYTES)
};

const byte test_aes256_gcm_VECTOR_1_AUTH_TAG_BYTES[] = {
    0x80, 0x88, 0x3f, 0x2c, 0x92, 0x54, 0x34, 0xa5,
    0xed, 0xfc, 0xef, 0xd5, 0xb1, 0x23, 0xd5, 0x20,
};

const vsc_data_t test_aes256_gcm_VECTOR_1_AUTH_TAG = {
    test_aes256_gcm_VECTOR_1_AUTH_TAG_BYTES, sizeof(test_aes256_gcm_VECTOR_1_AUTH_TAG_BYTES)
};

const byte test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_BYTES[] = {
    0x9D, 0x02, 0x77, 0xAA, 0x0A, 0xFF, 0xD2, 0x1F,
    0xC7, 0x2C, 0xD0, 0xD4, 0xED, 0x56, 0xDA, 0x76,
};

const vsc_data_t test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG = {
    test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_BYTES, sizeof(test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_BYTES)
};


//
//  Test vector 2
//  AES-GCM NIST Validation (AES-256,128,0,1024,128) #0
//
const byte test_aes256_gcm_VECTOR_2_KEY_BYTES[] = {
    0x43, 0xc9, 0xe2, 0x09, 0xda, 0x3c, 0x19, 0x71,
    0xd9, 0x86, 0xa4, 0x5b, 0x92, 0xf2, 0xfa, 0x0d,
    0x2d, 0x15, 0x51, 0x83, 0x73, 0x0d, 0x21, 0xd7,
    0x1e, 0xd8, 0xe2, 0x28, 0x4e, 0xc3, 0x08, 0xe3,
};

const byte test_aes256_gcm_VECTOR_2_NONCE_BYTES[] = {
    0x78, 0xbe, 0xf6, 0x55, 0xdf, 0xd8, 0x99, 0x0b,
    0x04, 0xd2, 0xa2, 0x56
};

const byte test_aes256_gcm_VECTOR_2_ADD_BYTES[] = {
    0x9d, 0x8c, 0x67, 0x34, 0x54, 0x67, 0x97, 0xc5,
    0x81, 0xb9, 0xb1, 0xd0, 0xd4, 0xf0, 0x5b, 0x27,
    0xfe, 0x05, 0x39, 0xbd, 0x01, 0x65, 0x5d, 0x2d,
    0x1a, 0x8a, 0x14, 0x89, 0xcd, 0xf8, 0x04, 0x22,
    0x87, 0x53, 0xd7, 0x72, 0x72, 0xbf, 0x6d, 0xed,
    0x19, 0xd4, 0x7a, 0x6a, 0xbd, 0x62, 0x81, 0xea,
    0x95, 0x91, 0xd4, 0xbc, 0xc1, 0xbe, 0x22, 0x23,
    0x05, 0xfd, 0xf6, 0x89, 0xc5, 0xfa, 0xa4, 0xc1,
    0x13, 0x31, 0xcf, 0xfb, 0xf4, 0x22, 0x15, 0x46,
    0x9b, 0x81, 0xf6, 0x1b, 0x40, 0x41, 0x5d, 0x81,
    0xcc, 0x37, 0x16, 0x1e, 0x5c, 0x02, 0x58, 0xa6,
    0x76, 0x42, 0xb9, 0xb8, 0xac, 0x62, 0x7d, 0x6e,
    0x39, 0xf4, 0x3e, 0x48, 0x5e, 0x1f, 0xf5, 0x22,
    0xac, 0x74, 0x2a, 0x07, 0xde, 0xfa, 0x35, 0x69,
    0xae, 0xb5, 0x99, 0x90, 0xcb, 0x44, 0xc4, 0xf3,
    0xd9, 0x52, 0xf8, 0x11, 0x9f, 0xf1, 0x11, 0x1d,
};


const byte test_aes256_gcm_VECTOR_2_AUTH_TAG_BYTES[] = {
    0xE7, 0x01, 0x09, 0x53, 0xAB, 0x26, 0xEB, 0xF9,
    0x58, 0x82, 0x99, 0x8E, 0x70, 0x32, 0x1B, 0xAC,
};


const vsc_data_t test_aes256_gcm_VECTOR_2_KEY = {
    test_aes256_gcm_VECTOR_2_KEY_BYTES, sizeof(test_aes256_gcm_VECTOR_2_KEY_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_2_DATA = {(const byte *)0xDEADBEAF, 0};

const vsc_data_t test_aes256_gcm_VECTOR_2_NONCE = {
    test_aes256_gcm_VECTOR_2_NONCE_BYTES, sizeof(test_aes256_gcm_VECTOR_2_NONCE_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_2_ADD = {
    test_aes256_gcm_VECTOR_2_ADD_BYTES, sizeof(test_aes256_gcm_VECTOR_2_ADD_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_2_ENC = {(const byte *)0xDEADBEAF, 0};

const vsc_data_t test_aes256_gcm_VECTOR_2_AUTH_TAG = {
    test_aes256_gcm_VECTOR_2_AUTH_TAG_BYTES, sizeof(test_aes256_gcm_VECTOR_2_AUTH_TAG_BYTES)
};


//
//  Test vector 3
//  AES-GCM NIST Validation (AES-256,128,1024,1024,128) #0
//
const byte test_aes256_gcm_VECTOR_3_KEY_BYTES[] = {
    0x29, 0x07, 0x2a, 0xb5, 0xba, 0xd2, 0xc1, 0x42,
    0x5c, 0xa8, 0xdd, 0x0a, 0xe5, 0x6f, 0x27, 0xe9,
    0x3f, 0x8d, 0x26, 0xb3, 0x20, 0xb0, 0x8f, 0x77,
    0xb8, 0xbd, 0x3f, 0xa9, 0xd0, 0x3e, 0xdc, 0x6c,
};

const byte test_aes256_gcm_VECTOR_3_DATA_BYTES[] = {
    0x3c, 0x7a, 0xfc, 0x5c, 0xfc, 0x5a, 0x1e, 0x14,
    0x15, 0x87, 0xe9, 0x3f, 0xef, 0x84, 0x27, 0xd4,
    0xf2, 0x1d, 0x89, 0x2b, 0x98, 0x3b, 0x7c, 0x9b,
    0x6e, 0x9d, 0xe3, 0xee, 0x16, 0x88, 0x37, 0xa1,
    0x53, 0x38, 0x47, 0xc8, 0xa2, 0xe2, 0xab, 0x07,
    0x06, 0xac, 0x14, 0x74, 0xe9, 0xaa, 0x54, 0xab,
    0x57, 0xe7, 0x86, 0x0b, 0xca, 0x9e, 0xbb, 0x83,
    0xbd, 0x6d, 0x3a, 0xe2, 0x6c, 0xa5, 0x38, 0x7a,
    0xbd, 0xb9, 0xa6, 0x0c, 0x4a, 0x99, 0x28, 0x48,
    0x47, 0x42, 0xa9, 0x12, 0x94, 0xb1, 0x3a, 0xb8,
    0xf5, 0x1e, 0xb4, 0xf5, 0x99, 0xa3, 0x0e, 0x9c,
    0xb1, 0x89, 0x4a, 0xca, 0x32, 0xa6, 0x2a, 0x4c,
    0x27, 0x93, 0xee, 0x67, 0x93, 0xdf, 0x47, 0x3f,
    0x43, 0x23, 0x4c, 0x9e, 0xaf, 0xb4, 0x4d, 0x58,
    0x5a, 0x7d, 0x92, 0xa5, 0x0a, 0xeb, 0xef, 0x80,
    0xc7, 0x3c, 0x86, 0xef, 0x67, 0xf5, 0xb5, 0xa4,
};

const byte test_aes256_gcm_VECTOR_3_NONCE_BYTES[] = {
    0x02, 0x01, 0xed, 0xf8, 0x04, 0x75, 0xd2, 0xf9,
    0x69, 0xa9, 0x08, 0x48
};

const byte test_aes256_gcm_VECTOR_3_ADD_BYTES[] = {
    0x4c, 0x8f, 0xf3, 0xed, 0xea, 0xa6, 0x8e, 0x47,
    0xbb, 0xc8, 0x72, 0x4b, 0x37, 0x82, 0x22, 0x16,
    0xd4, 0x2e, 0x26, 0x69, 0xca, 0x12, 0x7d, 0xa1,
    0x4b, 0x7b, 0x48, 0x8f, 0xde, 0x31, 0xa4, 0x9c,
    0x7d, 0x35, 0x7f, 0xb9, 0xae, 0xcc, 0x19, 0x91,
    0xb3, 0xc6, 0xf6, 0x3a, 0x4c, 0xe4, 0x39, 0x59,
    0xa2, 0x2d, 0xe7, 0x05, 0x45, 0xe6, 0xae, 0xe8,
    0x67, 0x4d, 0x81, 0x2e, 0xca, 0xae, 0xf9, 0x3a,
    0xd0, 0x3b, 0x5d, 0x4c, 0x99, 0xbd, 0xef, 0x6d,
    0x52, 0xf2, 0x1f, 0xc7, 0xfd, 0xbe, 0xb1, 0xc5,
    0x62, 0x9a, 0x76, 0xdf, 0x59, 0x62, 0x0a, 0xae,
    0xfd, 0xa8, 0x1a, 0x8e, 0x73, 0xce, 0xbe, 0x4c,
    0x64, 0x6b, 0xef, 0xfd, 0x7f, 0x4a, 0x98, 0xa5,
    0x28, 0x3c, 0xc7, 0xbc, 0x5e, 0x78, 0xb2, 0xa7,
    0x0f, 0x43, 0xe0, 0xca, 0xb0, 0xb7, 0x77, 0x2e,
    0x03, 0xa5, 0xf0, 0x48, 0xec, 0x75, 0x08, 0x1a,
};

const byte test_aes256_gcm_VECTOR_3_ENC_BYTES[] = {
    0x75, 0xA7, 0x63, 0xE3, 0x8F, 0xD4, 0x35, 0xCF,
    0x51, 0xD2, 0x9B, 0x02, 0x2B, 0xD3, 0xDC, 0x99,
    0x22, 0xAA, 0x91, 0x31, 0xA3, 0x3F, 0x05, 0xA7,
    0x84, 0x68, 0x4C, 0x11, 0xA1, 0xEF, 0x28, 0xD2,
    0xCE, 0xED, 0xF4, 0xEC, 0xE4, 0x21, 0x0B, 0xA5,
    0x0F, 0x32, 0x68, 0xFE, 0x5A, 0x1B, 0xC2, 0xF7,
    0xCC, 0xCC, 0x42, 0x5D, 0x27, 0xDE, 0xAD, 0x96,
    0x00, 0xF3, 0xB1, 0x78, 0x05, 0x6D, 0x76, 0xC0,
    0x06, 0x9D, 0x5A, 0xF5, 0x9E, 0x99, 0xEE, 0x28,
    0xAE, 0x72, 0xFC, 0x97, 0xA2, 0x8E, 0x65, 0x99,
    0x35, 0xFC, 0x50, 0x0D, 0x3F, 0x8D, 0x0F, 0x66,
    0x11, 0x2A, 0x61, 0x9D, 0x1A, 0xAC, 0x73, 0xE5,
    0xCA, 0x2E, 0x46, 0xE5, 0x70, 0xF6, 0xD7, 0x96,
    0xFB, 0x01, 0x68, 0xA5, 0x58, 0xF6, 0xB9, 0x7B,
    0xA1, 0x22, 0xB7, 0x0C, 0xB2, 0xD0, 0x70, 0x0C,
    0x87, 0xF7, 0xD7, 0x41, 0x0B, 0x3E, 0xE6, 0x5E,
};

const byte test_aes256_gcm_VECTOR_3_AUTH_TAG_BYTES[] = {
    0xA0, 0xB2, 0x68, 0xA9, 0x66, 0x67, 0xBE, 0xB7,
    0x7F, 0xC5, 0x56, 0x02, 0x64, 0x23, 0x06, 0xCA,
};

const byte test_aes256_gcm_VECTOR_3_ENC_PLUS_AUTH_TAG_BYTES[] = {
    0xf3, 0x75, 0x5a, 0xae, 0x68, 0x13, 0xe4, 0xe4,
    0xb8, 0x4a, 0x08, 0x9c, 0xa1, 0x49, 0x65, 0x64,
    0x67, 0x66, 0x55, 0xba, 0x3c, 0x94, 0xe5, 0x9c,
    0x5f, 0x68, 0x2a, 0xdb, 0xbf, 0xed, 0x21, 0xe7,
    0x6a, 0xed, 0x0d, 0xb7, 0x83, 0x90, 0x25, 0x8c,
    0xf5, 0xfb, 0xf1, 0x5f, 0x06, 0xc6, 0xb6, 0x46,
    0x84, 0x14, 0xcb, 0x64, 0x93, 0xc8, 0xb9, 0xb9,
    0x53, 0xb4, 0x95, 0x4e, 0xca, 0xf0, 0x7e, 0xca,
    0xf8, 0x58, 0x6a, 0xe0, 0x01, 0x71, 0x0d, 0x40,
    0x69, 0xda, 0x6d, 0x21, 0x81, 0x0b, 0xcd, 0xcb,
    0xb8, 0x31, 0xf7, 0x04, 0x1c, 0xdb, 0xb9, 0x84,
    0xb7, 0xc5, 0x58, 0x78, 0x59, 0x8a, 0x66, 0x58,
    0x88, 0x31, 0x78, 0xdc, 0xc0, 0xfa, 0x03, 0x39,
    0x45, 0x19, 0xb8, 0xb9, 0xc3, 0xbe, 0xd0, 0xe5,
    0xc0, 0x73, 0x42, 0x9f, 0x5d, 0xd0, 0x71, 0xa9,
    0x18, 0x4b, 0x01, 0x5c, 0xbb, 0xbc, 0x62, 0xe1,
};


const vsc_data_t test_aes256_gcm_VECTOR_3_KEY = {
    test_aes256_gcm_VECTOR_3_KEY_BYTES, sizeof(test_aes256_gcm_VECTOR_3_KEY_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_DATA = {
    test_aes256_gcm_VECTOR_3_DATA_BYTES, sizeof(test_aes256_gcm_VECTOR_3_DATA_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_NONCE = {
    test_aes256_gcm_VECTOR_3_NONCE_BYTES, sizeof(test_aes256_gcm_VECTOR_3_NONCE_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_ADD = {
    test_aes256_gcm_VECTOR_3_ADD_BYTES, sizeof(test_aes256_gcm_VECTOR_3_ADD_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_ENC = {
    test_aes256_gcm_VECTOR_3_ENC_BYTES, sizeof(test_aes256_gcm_VECTOR_3_ENC_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_AUTH_TAG = {
    test_aes256_gcm_VECTOR_3_AUTH_TAG_BYTES, sizeof(test_aes256_gcm_VECTOR_3_AUTH_TAG_BYTES)
};

const vsc_data_t test_aes256_gcm_VECTOR_3_ENC_PLUS_AUTH_TAG = {
    test_aes256_gcm_VECTOR_3_ENC_PLUS_AUTH_TAG_BYTES, sizeof(test_aes256_gcm_VECTOR_3_ENC_PLUS_AUTH_TAG_BYTES)
};
