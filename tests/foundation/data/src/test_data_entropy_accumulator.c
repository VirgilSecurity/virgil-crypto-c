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


#include "test_data_entropy_accumulator.h"

//
//  Random set 1
//
const byte test_entropy_accumulator_ENTROPY_SET_1_BYTES[] = {
    0x2A, 0xB1, 0x32, 0x70, 0xC4, 0x6F, 0x49, 0xCB,
    0x84, 0x86, 0xDE, 0x92, 0xC9, 0x99, 0x9B, 0x6B,
    0x6C, 0xFF, 0x08, 0xB2, 0x09, 0x3A, 0x77, 0xC6,
    0xC9, 0x84, 0xE2, 0xF2, 0x4F, 0xA0, 0x5D, 0x7D,
    0x8D, 0x70, 0xC0, 0x4A, 0xAC, 0x3B, 0xE1, 0x05,
    0xB3, 0x8B, 0x94, 0x7B, 0x7C, 0x9A, 0x15, 0xB2,
    0x0E, 0xDA, 0x3A, 0x22, 0x89, 0x9B, 0xE0, 0x5F,
    0x95, 0x09, 0x53, 0x2E, 0x3F, 0x2F, 0xA4, 0x92,
};

const vsc_data_t test_entropy_accumulator_ENTROPY_SET_1 = {
    test_entropy_accumulator_ENTROPY_SET_1_BYTES, sizeof(test_entropy_accumulator_ENTROPY_SET_1_BYTES)
};
