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


#include "test_data_pkcs5_pbkdf2.h"

// P = "password" (8 octets)
static const byte PASSWORD_BYTES[] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64
};

// P = "pass0word" (8 octets)
static const byte PASS_ZERO_WORD_BYTES[] = {
    0x70, 0x61, 0x73, 0x73, 0x00, 0x77, 0x6F, 0x72, 0x64
};

// S = "salt" (4 octets)
static const byte SALT_BYTES[] = {
    0x73, 0x61, 0x6C, 0x74
};

// S = "salt" (4 octets)
static const byte SA_ZERO_LT_BYTES[] = {
    0x73, 0x61, 0x00, 0x6C, 0x74
};


//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 1
//      dkLen = 20
//  Output:
//      DK = 12 0f b6 cf fc f8 b3 2c 43 e7 22 52 56 c4 f8 37 a8 65 48 c9
//
static byte test_pkcs5_pbkdf2_VECTOR_1_BYTES[] = {
    0x12, 0x0F, 0xB6, 0xCF, 0xFC, 0xF8, 0xB3, 0x2C,
    0x43, 0xE7, 0x22, 0x52, 0x56, 0xC4, 0xF8, 0x37,
    0xA8, 0x65, 0x48, 0xC9
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1 = {
    test_pkcs5_pbkdf2_VECTOR_1_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_1_BYTES)
};


const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1_KEY = {
    PASSWORD_BYTES, sizeof(PASSWORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_1_SALT = {
    SALT_BYTES, sizeof(SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_1_ITERATION_COUNT = 1;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 2
//      dkLen = 20
//  Output:
//      DK = ae 4d 0c 95 af 6b 46 d3 2d 0a df f9 28 f0 6d d0 2a 30 3f 8e
//
static const byte test_pkcs5_pbkdf2_VECTOR_2_BYTES[] = {
    0xAE, 0x4D, 0x0C, 0x95, 0xAF, 0x6B, 0x46, 0xD3,
    0x2D, 0x0A, 0xDF, 0xF9, 0x28, 0xF0, 0x6D, 0xD0,
    0x2A, 0x30, 0x3F, 0x8E
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2 = {
    test_pkcs5_pbkdf2_VECTOR_2_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_2_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2_KEY = {
    PASSWORD_BYTES, sizeof(PASSWORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_2_SALT = {
    SALT_BYTES, sizeof(SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_2_ITERATION_COUNT = 2;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 4096
//      dkLen = 20
//  Output:
//      DK = c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0
//
static const byte test_pkcs5_pbkdf2_VECTOR_3_BYTES[] = {
    0xC5, 0xE4, 0x78, 0xD5, 0x92, 0x88, 0xC8, 0x41,
    0xAA, 0x53, 0x0D, 0xB6, 0x84, 0x5C, 0x4C, 0x8D,
    0x96, 0x28, 0x93, 0xA0
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3 = {
    test_pkcs5_pbkdf2_VECTOR_3_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_3_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3_KEY = {
    PASSWORD_BYTES, sizeof(PASSWORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_3_SALT = {
    SALT_BYTES, sizeof(SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_3_ITERATION_COUNT = 4096;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 16777216
//      dkLen = 20
//  Output:
//      DK = cf 81 c6 6f e8 cf c0 4d 1f 31 ec b6 5d ab 40 89 f7 f1 79 e8
//
static const byte test_pkcs5_pbkdf2_VECTOR_4_BYTES[] = {
    0xCF, 0x81, 0xC6, 0x6F, 0xE8, 0xCF, 0xC0, 0x4D,
    0x1F, 0x31, 0xEC, 0xB6, 0x5D, 0xAB, 0x40, 0x89,
    0xF7, 0xF1, 0x79, 0xE8
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4 = {
    test_pkcs5_pbkdf2_VECTOR_4_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_4_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4_KEY = {
    PASSWORD_BYTES, sizeof(PASSWORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_4_SALT = {
    SALT_BYTES, sizeof(SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_4_ITERATION_COUNT = 16777216;

//
//  Input:
//      P = "passwordPASSWORDpassword" (24 octets)
//      S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
//      c = 4096
//      dkLen = 25
//  Output:
//      DK = 34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf
//       2b 17 34 7e bc 18 00 18 1c
//
static const byte test_pkcs5_pbkdf2_VECTOR_5_BYTES[] = {
    0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
    0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
    0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
    0x1C
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5 = {
    test_pkcs5_pbkdf2_VECTOR_5_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_5_BYTES)
};

static const byte test_pkcs5_pbkdf2_VECTOR_5_KEY_BYTES[] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64,
    0x50, 0x41, 0x53, 0x53, 0x57, 0x4F, 0x52, 0x44,
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64,
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5_KEY = {
    test_pkcs5_pbkdf2_VECTOR_5_KEY_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_5_KEY_BYTES)
};

static const byte test_pkcs5_pbkdf2_VECTOR_5_SALT_BYTES[] = {
    0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
    0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
    0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
    0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
    0x73, 0x61, 0x6C, 0x74
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_5_SALT = {
    test_pkcs5_pbkdf2_VECTOR_5_SALT_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_5_SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_5_ITERATION_COUNT = 4096;

//
//  Input:
//      P = "pass\0word" (9 octets)
//      S = "sa\0lt" (5 octets)
//      c = 4096
//      dkLen = 16
//  Output:
//      DK = 89 b6 9d 05 16 f8 29 89 3c 69 62 26 65 0a 86 87
//
const byte test_pkcs5_pbkdf2_VECTOR_6_BYTES[] = {
    0x89, 0xB6, 0x9D, 0x05, 0x16, 0xF8, 0x29, 0x89,
    0x3C, 0x69, 0x62, 0x26, 0x65, 0x0A, 0x86, 0x87,
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6 = {
    test_pkcs5_pbkdf2_VECTOR_6_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_6_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6_KEY = {
    PASS_ZERO_WORD_BYTES, sizeof(PASS_ZERO_WORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_6_SALT = {
    SA_ZERO_LT_BYTES, sizeof(SA_ZERO_LT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_6_ITERATION_COUNT = 4096;

//
//  Input:
//      P = "password" (8 octets)
//      S = "salt" (4 octets)
//      c = 4096
//      dkLen = 100
//  Output:
//      DK = c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d
//           96 28 93 a0 01 ce 4e 11 a4 96 38 73 aa 98 13 4a
//           f7 ad 98 c1 b4 58 ce 3f d7 4c a3 5b eb a3 cd a7
//           b8 d1 03 8d 6a 87 07 1b 91 8f 83 74 05 f3 fe 77
//           28 ff e7 f0 97 6f c3 5d d8 2f c0 e5 e4 6c e9 ce
//           26 a7 88 b2 c7 d1 83 fa 5b f8 d9 60 7e ec d7 1d
//           01 b4 f1 19
//
const byte test_pkcs5_pbkdf2_VECTOR_7_BYTES[] = {
    0xC5, 0xE4, 0x78, 0xD5, 0x92, 0x88, 0xC8, 0x41,
    0xAA, 0x53, 0x0D, 0xB6, 0x84, 0x5C, 0x4C, 0x8D,
    0x96, 0x28, 0x93, 0xA0, 0x01, 0xCE, 0x4E, 0x11,
    0xA4, 0x96, 0x38, 0x73, 0xAA, 0x98, 0x13, 0x4A,
    0xF7, 0xAD, 0x98, 0xC1, 0xB4, 0x58, 0xCE, 0x3F,
    0xD7, 0x4C, 0xA3, 0x5B, 0xEB, 0xA3, 0xCD, 0xA7,
    0xB8, 0xD1, 0x03, 0x8D, 0x6A, 0x87, 0x07, 0x1B,
    0x91, 0x8F, 0x83, 0x74, 0x05, 0xF3, 0xFE, 0x77,
    0x28, 0xFF, 0xE7, 0xF0, 0x97, 0x6F, 0xC3, 0x5D,
    0xD8, 0x2F, 0xC0, 0xE5, 0xE4, 0x6C, 0xE9, 0xCE,
    0x26, 0xA7, 0x88, 0xB2, 0xC7, 0xD1, 0x83, 0xFA,
    0x5B, 0xF8, 0xD9, 0x60, 0x7E, 0xEC, 0xD7, 0x1D,
    0x01, 0xB4, 0xF1, 0x19
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7 = {
    test_pkcs5_pbkdf2_VECTOR_7_BYTES, sizeof(test_pkcs5_pbkdf2_VECTOR_7_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7_KEY = {
    PASSWORD_BYTES, sizeof(PASSWORD_BYTES)
};

const vsc_data_t test_pkcs5_pbkdf2_VECTOR_7_SALT = {
    SALT_BYTES, sizeof(SALT_BYTES)
};

const size_t test_pkcs5_pbkdf2_VECTOR_7_ITERATION_COUNT = 4096;
