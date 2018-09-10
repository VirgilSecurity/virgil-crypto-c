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


#include "test_data_kdf2.h"

//
//  Test Vector 1
//
const byte test_kdf2_VECTOR_1_DATA_BYTES[] = {};

const vsc_data_t test_kdf2_VECTOR_1_DATA = {
    test_kdf2_VECTOR_1_DATA_BYTES, sizeof(test_kdf2_VECTOR_1_DATA_BYTES)
};

const byte test_kdf2_VECTOR_1_KEY_BYTES[] = {
    0xb4, 0x07, 0x11, 0xa8, 0x8c, 0x70, 0x39, 0x75,
    0x6f, 0xb8, 0xa7, 0x38, 0x27, 0xea, 0xbe, 0x2c,
    0x0f, 0xe5, 0xa0, 0x34, 0x6c, 0xa7, 0xe0, 0xa1,
    0x04, 0xad, 0xc0, 0xfc, 0x76, 0x4f, 0x52, 0x8d,
    0x43, 0x3e, 0xbf, 0x5b, 0xc0, 0x3d, 0xff, 0xa3,
};

const vsc_data_t test_kdf2_VECTOR_1_KEY = {
    test_kdf2_VECTOR_1_KEY_BYTES, sizeof(test_kdf2_VECTOR_1_KEY_BYTES)
};


//
//  Test Vector 2
//
const byte test_kdf2_VECTOR_2_DATA_BYTES[] = {
    0xbd
};

const vsc_data_t test_kdf2_VECTOR_2_DATA = {
    test_kdf2_VECTOR_2_DATA_BYTES, sizeof(test_kdf2_VECTOR_2_DATA_BYTES)
};

const byte test_kdf2_VECTOR_2_KEY_BYTES[] = {
    0x82, 0x3b, 0xfa, 0xe3, 0xb6, 0xe7, 0xcd, 0x29,
    0x5c, 0xd2, 0x24, 0x76, 0x1d, 0x17, 0x19, 0xaa,
    0xad, 0x13, 0x08, 0xe4, 0x56, 0x2b, 0x94, 0x91,
    0x73, 0xee, 0xfc, 0xec, 0xd4, 0xb2, 0xcb, 0x17,
    0x06, 0x1f, 0x09, 0x7e, 0xd2, 0x0c, 0x33, 0x23,
};

const vsc_data_t test_kdf2_VECTOR_2_KEY = {
    test_kdf2_VECTOR_2_KEY_BYTES, sizeof(test_kdf2_VECTOR_2_KEY_BYTES)
};


//
//  Test Vector 3
//
const byte test_kdf2_VECTOR_3_DATA_BYTES[] = {
    0x5f, 0xd4
};

const vsc_data_t test_kdf2_VECTOR_3_DATA = {
    test_kdf2_VECTOR_3_DATA_BYTES, sizeof(test_kdf2_VECTOR_3_DATA_BYTES)
};

const byte test_kdf2_VECTOR_3_KEY_BYTES[] = {
    0x00, 0x24, 0x22, 0xaf, 0xdd, 0x96, 0xbf, 0x48,
    0x3d, 0x5d, 0x76, 0x1f, 0x73, 0x44, 0x40, 0x46,
    0x0c, 0x79, 0x8f, 0xaa, 0x55, 0x78, 0xea, 0x3b,
    0x13, 0x3e, 0x57, 0x0e, 0x09, 0x46, 0x0f, 0x65,
    0x67, 0x7b, 0xd0, 0x8b, 0xd7, 0xa9, 0xcb, 0xcb,
};

const vsc_data_t test_kdf2_VECTOR_3_KEY = {
    test_kdf2_VECTOR_3_KEY_BYTES, sizeof(test_kdf2_VECTOR_3_KEY_BYTES)
};

