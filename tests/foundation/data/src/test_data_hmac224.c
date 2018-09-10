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


#include "test_data_sha224.h"

//
//  Test Vector 1
//
const byte test_hmac224_KEY_1_INPUT_BYTES[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b,
};

const vsc_data_t test_hmac224_KEY_1_INPUT = {
    test_hmac224_KEY_1_INPUT_BYTES, sizeof(test_hmac224_KEY_1_INPUT_BYTES)
};
const byte test_hmac224_VECTOR_1_INPUT_BYTES[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };

const vsc_data_t test_hmac224_VECTOR_1_INPUT = {
    test_hmac224_VECTOR_1_INPUT_BYTES, sizeof(test_hmac224_VECTOR_1_INPUT_BYTES)
};

const byte test_hmac224_VECTOR_1_DIGEST_BYTES[] = {
    0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19,
    0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
    0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f,
    0x53, 0x68, 0x4b, 0x22,
};

const vsc_data_t test_hmac224_VECTOR_1_DIGEST = {
    test_hmac224_VECTOR_1_DIGEST_BYTES, sizeof(test_hmac224_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_hmac224_KEY_2_INPUT_BYTES[] = {
    0x4a, 0x65, 0x66, 0x65,
};

const vsc_data_t test_hmac224_KEY_2_INPUT = {
    test_hmac224_KEY_2_INPUT_BYTES, sizeof(test_hmac224_KEY_2_INPUT_BYTES)
};
const byte test_hmac224_VECTOR_2_INPUT_BYTES[] = {
    0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
    0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
    0x69, 0x6e, 0x67, 0x3f };

const vsc_data_t test_hmac224_VECTOR_2_INPUT = {
    test_hmac224_VECTOR_2_INPUT_BYTES, sizeof(test_hmac224_VECTOR_2_INPUT_BYTES)
};

const byte test_hmac224_VECTOR_2_DIGEST_BYTES[] = {
    0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf,
    0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e, 0x6d, 0x0f,
    0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00,
    0x8f, 0xd0, 0x5e, 0x44,
};

const vsc_data_t test_hmac224_VECTOR_2_DIGEST = {
    test_hmac224_VECTOR_2_DIGEST_BYTES, sizeof(test_hmac224_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_hmac224_KEY_3_INPUT_BYTES[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
};

const vsc_data_t test_hmac224_KEY_3_INPUT = {
    test_hmac224_KEY_3_INPUT_BYTES, sizeof(test_hmac224_KEY_3_INPUT_BYTES)
};
const byte test_hmac224_VECTOR_3_INPUT_BYTES[] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd,
};

const vsc_data_t test_hmac224_VECTOR_3_INPUT = {
    test_hmac224_VECTOR_3_INPUT_BYTES, sizeof(test_hmac224_VECTOR_3_INPUT_BYTES)
};

const byte test_hmac224_VECTOR_3_DIGEST_BYTES[] = {
    0x7f, 0xb3, 0xcb, 0x35, 0x88, 0xc6, 0xc1, 0xf6,
    0xff, 0xa9, 0x69, 0x4d, 0x7d, 0x6a, 0xd2, 0x64,
    0x93, 0x65, 0xb0, 0xc1, 0xf6, 0x5d, 0x69, 0xd1,
    0xec, 0x83, 0x33, 0xea,
};

const vsc_data_t test_hmac224_VECTOR_3_DIGEST = {
    test_hmac224_VECTOR_3_DIGEST_BYTES, sizeof(test_hmac224_VECTOR_3_DIGEST_BYTES)
};


