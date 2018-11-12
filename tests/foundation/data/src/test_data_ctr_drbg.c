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


#include "test_data_ctr_drbg.h"

//
//  Random set 1
//
const byte test_ctr_drbg_RANDOM_SET_1_BYTES[] = {
    0xDF, 0xB7, 0x56, 0x24, 0x71, 0xBC, 0x87, 0x33,
    0x26, 0x30, 0x67, 0x39, 0x3A, 0x7F, 0x76, 0x2D,
    0x11, 0x83, 0x09, 0x16, 0x68, 0xC3, 0x9B, 0x8D,
    0xB5, 0xC6, 0x76, 0xCD, 0xE7, 0x0A, 0xBA, 0xF2,
    0xE1, 0x11, 0x99, 0xB7, 0xCD, 0x2F, 0x37, 0x8C,
    0x15, 0xBE, 0x83, 0x83, 0x55, 0x88, 0xD3, 0x4E,
    0xE7, 0x25, 0x89, 0xDD, 0x29, 0x7A, 0x40, 0x88,
    0x5B, 0xEC, 0x6C, 0xB5, 0xC7, 0xB9, 0x28, 0x8A,
    0x65, 0x79, 0xA1, 0xEE, 0x4F, 0xCE, 0x70, 0xBC,
    0xCC, 0x78, 0x8F, 0x87, 0x39, 0x72, 0x79, 0x52,
    0x6D, 0xCD, 0xC4, 0x29, 0x78, 0x9C, 0x52, 0x79,
    0x7B, 0x5F, 0x38, 0x60, 0x5F, 0x4B, 0x86, 0x4F,
    0x98, 0xF5, 0xD2, 0x65, 0xD5, 0xDC, 0xE8, 0x75,
    0xC2, 0x58, 0xDF, 0x0B, 0xE4, 0x07, 0xB3, 0xEC,
    0x9B, 0x51, 0xF1, 0x9B, 0xD6, 0x2D, 0xE6, 0x92,
    0xF8, 0x8A, 0x3B, 0xE9, 0x53, 0xAD, 0x88, 0xF0,
};

const vsc_data_t test_ctr_drbg_RANDOM_SET_1 = {
    test_ctr_drbg_RANDOM_SET_1_BYTES, sizeof(test_ctr_drbg_RANDOM_SET_1_BYTES)
};
