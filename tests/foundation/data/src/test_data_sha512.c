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


#include "test_data_sha512.h"

//
//  Test Vector 1
//
const byte test_sha512_VECTOR_1_INPUT_BYTES[] = {};

const vsc_data_t test_sha512_VECTOR_1_INPUT = {
    test_sha512_VECTOR_1_INPUT_BYTES, sizeof(test_sha512_VECTOR_1_INPUT_BYTES)
};

const byte test_sha512_VECTOR_1_DIGEST_BYTES[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
};

const vsc_data_t test_sha512_VECTOR_1_DIGEST = {
    test_sha512_VECTOR_1_DIGEST_BYTES, sizeof(test_sha512_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_sha512_VECTOR_2_INPUT_BYTES[] = { 0x8f };

const vsc_data_t test_sha512_VECTOR_2_INPUT = {
    test_sha512_VECTOR_2_INPUT_BYTES, sizeof(test_sha512_VECTOR_2_INPUT_BYTES)
};

const byte test_sha512_VECTOR_2_DIGEST_BYTES[] = {
    0xe4, 0xcd, 0x2d, 0x19, 0x93, 0x1b, 0x5a, 0xad,
    0x9c, 0x92, 0x0f, 0x45, 0xf5, 0x6f, 0x6c, 0xe3,
    0x4e, 0x3d, 0x38, 0xc6, 0xd3, 0x19, 0xa6, 0xe1,
    0x1d, 0x05, 0x88, 0xab, 0x8b, 0x83, 0x85, 0x76,
    0xd6, 0xce, 0x6d, 0x68, 0xee, 0xa7, 0xc8, 0x30,
    0xde, 0x66, 0xe2, 0xbd, 0x96, 0x45, 0x8b, 0xfa,
    0x7a, 0xaf, 0xbc, 0xbe, 0xc9, 0x81, 0xd4, 0xed,
    0x04, 0x04, 0x98, 0xc3, 0xdd, 0x95, 0xf2, 0x2a,
};

const vsc_data_t test_sha512_VECTOR_2_DIGEST = {
    test_sha512_VECTOR_2_DIGEST_BYTES, sizeof(test_sha512_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_sha512_VECTOR_3_INPUT_BYTES[] = { 0xe7, 0x24 };

const vsc_data_t test_sha512_VECTOR_3_INPUT = {
    test_sha512_VECTOR_3_INPUT_BYTES, sizeof(test_sha512_VECTOR_3_INPUT_BYTES)
};

const byte test_sha512_VECTOR_3_DIGEST_BYTES[] = {
    0x7d, 0xbb, 0x52, 0x02, 0x21, 0xa7, 0x02, 0x87,
    0xb2, 0x3d, 0xbc, 0xf6, 0x2b, 0xfc, 0x1b, 0x73,
    0x13, 0x6d, 0x85, 0x8e, 0x86, 0x26, 0x67, 0x32,
    0xa7, 0xff, 0xfa, 0x87, 0x5e, 0xca, 0xa2, 0xc1,
    0xb8, 0xf6, 0x73, 0xb5, 0xc0, 0x65, 0xd3, 0x60,
    0xc5, 0x63, 0xa7, 0xb9, 0x53, 0x93, 0x49, 0xf5,
    0xf5, 0x9b, 0xef, 0x8c, 0x0c, 0x59, 0x3f, 0x95,
    0x87, 0xe3, 0xcd, 0x50, 0xbb, 0x26, 0xa2, 0x31,
};

const vsc_data_t test_sha512_VECTOR_3_DIGEST = {
    test_sha512_VECTOR_3_DIGEST_BYTES, sizeof(test_sha512_VECTOR_3_DIGEST_BYTES)
};

