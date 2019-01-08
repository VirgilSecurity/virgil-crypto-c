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


#include "test_data_sha256.h"

//
//  Test Vector 1
//
const vsc_data_t test_sha256_VECTOR_1_INPUT = {(const byte *)0xDEADBEAF, 0};

const byte test_sha256_VECTOR_1_DIGEST_BYTES[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

const vsc_data_t test_sha256_VECTOR_1_DIGEST = {
    test_sha256_VECTOR_1_DIGEST_BYTES, sizeof(test_sha256_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_sha256_VECTOR_2_INPUT_BYTES[] = { 0xbd };

const vsc_data_t test_sha256_VECTOR_2_INPUT = {
    test_sha256_VECTOR_2_INPUT_BYTES, sizeof(test_sha256_VECTOR_2_INPUT_BYTES)
};

const byte test_sha256_VECTOR_2_DIGEST_BYTES[] = {
    0x68, 0x32, 0x57, 0x20, 0xaa, 0xbd, 0x7c, 0x82,
    0xf3, 0x0f, 0x55, 0x4b, 0x31, 0x3d, 0x05, 0x70,
    0xc9, 0x5a, 0xcc, 0xbb, 0x7d, 0xc4, 0xb5, 0xaa,
    0xe1, 0x12, 0x04, 0xc0, 0x8f, 0xfe, 0x73, 0x2b,
};

const vsc_data_t test_sha256_VECTOR_2_DIGEST = {
    test_sha256_VECTOR_2_DIGEST_BYTES, sizeof(test_sha256_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_sha256_VECTOR_3_INPUT_BYTES[] = { 0x5f, 0xd4 };

const vsc_data_t test_sha256_VECTOR_3_INPUT = {
    test_sha256_VECTOR_3_INPUT_BYTES, sizeof(test_sha256_VECTOR_3_INPUT_BYTES)
};

const byte test_sha256_VECTOR_3_DIGEST_BYTES[] = {
    0x7c, 0x4f, 0xbf, 0x48, 0x44, 0x98, 0xd2, 0x1b,
    0x48, 0x7b, 0x9d, 0x61, 0xde, 0x89, 0x14, 0xb2,
    0xea, 0xda, 0xf2, 0x69, 0x87, 0x12, 0x93, 0x6d,
    0x47, 0xc3, 0xad, 0xa2, 0x55, 0x8f, 0x67, 0x88,
};

const vsc_data_t test_sha256_VECTOR_3_DIGEST = {
    test_sha256_VECTOR_3_DIGEST_BYTES, sizeof(test_sha256_VECTOR_3_DIGEST_BYTES)
};

