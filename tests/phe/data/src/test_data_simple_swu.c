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

#include "test_data_simple_swu.h"

const byte test_simple_swu_hash1_BYTES[] = {
        0xa1, 0x88, 0x8a, 0xf8, 0x14, 0xf6, 0x66, 0x68,
        0x23, 0x90, 0x14, 0x7d, 0xe3, 0x85, 0xcd, 0xd5,
        0x4d, 0xf2, 0x0b, 0x62, 0xd1, 0x08, 0x6a, 0xcf,
        0x73, 0xbe, 0xfb, 0x51, 0x3d, 0x21, 0xe6, 0x77,
};

const byte test_simple_swu_x1_BYTES[] = {
        0xf1, 0x14, 0x2a, 0x93, 0xfa, 0xd2, 0x28, 0x32,
        0x91, 0x07, 0x44, 0x7d, 0x88, 0x7c, 0xe8, 0x16,
        0x76, 0xe1, 0x50, 0xd8, 0xac, 0xa8, 0xb8, 0x45,
        0x20, 0x74, 0x20, 0x20, 0x8d, 0xdc, 0x00, 0x0f,
};

const byte test_simple_swu_y1_BYTES[] = {
        0x69, 0xd7, 0xc2, 0xe3, 0xf7, 0x44, 0x8f, 0x5f,
        0x8f, 0x69, 0x28, 0xf3, 0xdc, 0x26, 0x64, 0x14,
        0xc4, 0x90, 0x37, 0xea, 0xf1, 0x6d, 0x79, 0x4d,
        0x45, 0xab, 0x0d, 0x99, 0x19, 0x1d, 0x23, 0x74,
};

const byte test_simple_swu_hash2_BYTES[] = {
};

const byte test_simple_swu_x2_BYTES[] = {
};

const byte test_simple_swu_y2_BYTES[] = {
};

const vsc_data_t test_simple_swu_hash1 = {
        test_simple_swu_hash1_BYTES, sizeof(test_simple_swu_hash1_BYTES)
};

const vsc_data_t test_simple_swu_x1 = {
        test_simple_swu_x1_BYTES, sizeof(test_simple_swu_x1_BYTES)
};

const vsc_data_t test_simple_swu_y1 = {
        test_simple_swu_y1_BYTES, sizeof(test_simple_swu_y1_BYTES)
};

const vsc_data_t test_simple_swu_hash2 = {
        test_simple_swu_hash2_BYTES, sizeof(test_simple_swu_hash2_BYTES)
};

const vsc_data_t test_simple_swu_x2 = {
        test_simple_swu_x2_BYTES, sizeof(test_simple_swu_x2_BYTES)
};

const vsc_data_t test_simple_swu_y2 = {
        test_simple_swu_y2_BYTES, sizeof(test_simple_swu_y2_BYTES)
};
