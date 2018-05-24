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


#include "bench_data_kdf2.h"

//
//  Test Vector 1
//
const byte test_kdf2_VECTOR_1_DATA[] = {};

const byte test_kdf2_VECTOR_1_KEY[] = {
    0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
    0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
    0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
    0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
    0xb4, 0x07, 0x11, 0xa8, 0x8c, 0x70, 0x39, 0x75,
};

const size_t test_kdf2_VECTOR_1_DATA_LEN = sizeof (test_kdf2_VECTOR_1_DATA);
const size_t test_kdf2_VECTOR_1_KEY_LEN = sizeof (test_kdf2_VECTOR_1_KEY);

//
//  Test Vector 2
//
const byte test_kdf2_VECTOR_2_DATA[] = {
    0xbd
};

const byte test_kdf2_VECTOR_2_KEY[] = {
    0xa7, 0x59, 0xb8, 0x60, 0xb3, 0x7f, 0xe7, 0x78,
    0x47, 0x40, 0x6f, 0x26, 0x6b, 0x7d, 0x7f, 0x1e,
    0x83, 0x8d, 0x81, 0x4a, 0xdd, 0xf2, 0x71, 0x6e,
    0xcf, 0x4d, 0x82, 0x4d, 0xc8, 0xb5, 0x6f, 0x71,
    0x82, 0x3b, 0xfa, 0xe3, 0xb6, 0xe7, 0xcd, 0x29,
};

const size_t test_kdf2_VECTOR_2_DATA_LEN = sizeof (test_kdf2_VECTOR_2_DATA);
const size_t test_kdf2_VECTOR_2_KEY_LEN = sizeof (test_kdf2_VECTOR_2_KEY);

//
//  Test Vector 3
//
const byte test_kdf2_VECTOR_3_DATA[] = {
    0x5f, 0xd4
};

const byte test_kdf2_VECTOR_3_KEY[] = {
    0xc6, 0x06, 0x77, 0x22, 0xee, 0x56, 0x61, 0x13,
    0x1d, 0x53, 0x43, 0x7e, 0x64, 0x9e, 0xd1, 0x22,
    0x08, 0x58, 0xf8, 0x81, 0x64, 0x81, 0x9b, 0xb8,
    0x67, 0xd6, 0x47, 0x87, 0x14, 0xf8, 0xf3, 0xc8,
    0x00, 0x24, 0x22, 0xaf, 0xdd, 0x96, 0xbf, 0x48,
};

const size_t test_kdf2_VECTOR_3_DATA_LEN = sizeof (test_kdf2_VECTOR_3_DATA);
const size_t test_kdf2_VECTOR_3_KEY_LEN = sizeof (test_kdf2_VECTOR_3_KEY);
