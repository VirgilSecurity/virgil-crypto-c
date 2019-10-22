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

#include "test_data_compound_key.h"


// ==========================================================================
static const byte MESSAGE[] = {
    0x56, 0x69, 0x72, 0x67, 0x69, 0x6C, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20,
    0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x43, 0x21, 0x21, 0x21
};

const vsc_data_t test_data_compound_key_MESSAGE = {
    MESSAGE, sizeof(MESSAGE)
};

// ==========================================================================
//  Message to be signed!
static const byte MESSAGE_TBS[] = {
    0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x69,
    0x67, 0x6e, 0x65, 0x64, 0x21
};

const vsc_data_t test_data_compound_key_MESSAGE_TBS = {
    MESSAGE_TBS, sizeof(MESSAGE_TBS)
};

static const byte MESSAGE_TBS_SHA512_DIGEST[] = {
    0x90, 0x3B, 0xAB, 0x5C, 0xAB, 0x04, 0xFE, 0x9D, 0x7E, 0x65, 0xAB, 0xF9, 0x83, 0xD9, 0x87, 0xE5,
    0x71, 0xFB, 0x26, 0x16, 0x0D, 0x18, 0xDD, 0xA0, 0x6C, 0xFD, 0xE6, 0xE6, 0x7D, 0x38, 0x91, 0xE4,
    0xF8, 0x4F, 0x65, 0xFA, 0x38, 0x0B, 0xC7, 0xF0, 0xF3, 0x0D, 0x64, 0xA1, 0x35, 0xA9, 0x61, 0x03,
    0xDB, 0xA8, 0xE9, 0xBA, 0x24, 0x6E, 0x31, 0x41, 0x2C, 0xE9, 0xD5, 0x88, 0x80, 0x1D, 0x5A, 0x7A
};

const vsc_data_t test_data_compound_key_MESSAGE_TBS_SHA512_DIGEST = {
    MESSAGE_TBS_SHA512_DIGEST, sizeof(MESSAGE_TBS_SHA512_DIGEST)
};
