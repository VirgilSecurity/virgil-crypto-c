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


#include "test_data_sha384.h"

//
//  Test Vector 1
//
const vsc_data_t test_sha384_VECTOR_1_INPUT = {(const byte *)0xDEADBEAF, 0};

const byte test_sha384_VECTOR_1_DIGEST_BYTES[] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
};

const vsc_data_t test_sha384_VECTOR_1_DIGEST = {
    test_sha384_VECTOR_1_DIGEST_BYTES, sizeof(test_sha384_VECTOR_1_DIGEST_BYTES)
};


//
//  Test Vector 2
//
const byte test_sha384_VECTOR_2_INPUT_BYTES[] = { 0xab };

const vsc_data_t test_sha384_VECTOR_2_INPUT = {
    test_sha384_VECTOR_2_INPUT_BYTES, sizeof(test_sha384_VECTOR_2_INPUT_BYTES)
};

const byte test_sha384_VECTOR_2_DIGEST_BYTES[] = {
    0xfb, 0x94, 0xd5, 0xbe, 0x11, 0x88, 0x65, 0xf6,
    0xfc, 0xbc, 0x97, 0x8b, 0x82, 0x5d, 0xa8, 0x2c,
    0xff, 0x18, 0x8f, 0xae, 0xc2, 0xf6, 0x6c, 0xb8,
    0x4b, 0x25, 0x37, 0xd7, 0x4b, 0x49, 0x38, 0x46,
    0x98, 0x54, 0xb0, 0xca, 0x89, 0xe6, 0x6f, 0xa2,
    0xe1, 0x82, 0x83, 0x47, 0x36, 0x62, 0x9f, 0x3d,
};

const vsc_data_t test_sha384_VECTOR_2_DIGEST = {
    test_sha384_VECTOR_2_DIGEST_BYTES, sizeof(test_sha384_VECTOR_2_DIGEST_BYTES)
};


//
//  Test Vector 3
//
const byte test_sha384_VECTOR_3_INPUT_BYTES[] = { 0x7c, 0x27 };

const vsc_data_t test_sha384_VECTOR_3_INPUT = {
    test_sha384_VECTOR_3_INPUT_BYTES, sizeof(test_sha384_VECTOR_3_INPUT_BYTES)
};

const byte test_sha384_VECTOR_3_DIGEST_BYTES[] = {
    0x3d, 0x80, 0xbe, 0x46, 0x7d, 0xf8, 0x6d, 0x63,
    0xab, 0xb9, 0xea, 0x1d, 0x3f, 0x9c, 0xb3, 0x9c,
    0xd1, 0x98, 0x90, 0xe7, 0xf2, 0xc5, 0x3a, 0x62,
    0x00, 0xbe, 0xdc, 0x50, 0x06, 0x84, 0x2b, 0x35,
    0xe8, 0x20, 0xdc, 0x4e, 0x0c, 0xa9, 0x0c, 0xa9,
    0xb9, 0x7a, 0xb2, 0x3e, 0xf0, 0x70, 0x80, 0xfc,
};

const vsc_data_t test_sha384_VECTOR_3_DIGEST = {
    test_sha384_VECTOR_3_DIGEST_BYTES, sizeof(test_sha384_VECTOR_3_DIGEST_BYTES)
};

