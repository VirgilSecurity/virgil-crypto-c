//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "test_data_jwt.h"

static byte JWT_API_PUBLIC_KEY[] = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x3D, 0x59, 0x7A, 0xB4,
    0x16, 0x7C, 0x3A, 0x44, 0x88, 0x78, 0xAC, 0x7F, 0x68, 0x3E, 0x53, 0x20, 0x3C, 0xCD, 0xDD, 0x6B,
    0xA7, 0x53, 0x40, 0x4E, 0x2C, 0x9C, 0x5C, 0xF4, 0x54, 0x57, 0x79, 0xA3
};

const vsc_data_t test_data_JWT_API_PUBLIC_KEY = {
    JWT_API_PUBLIC_KEY, sizeof(JWT_API_PUBLIC_KEY)
};

static byte JWT_API_KEY[] = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x08, 0x1A, 0x9F, 0x66, 0xE5, 0xAF, 0xCA, 0x6B, 0xB5, 0x1B, 0x30, 0x2E, 0x0B, 0xB8, 0xE1, 0x8C,
    0xEC, 0x79, 0x0C, 0xE0, 0x77, 0x16, 0xB6, 0x1D, 0xEB, 0x2E, 0x43, 0x97, 0x50, 0x48, 0xCC, 0xE6,
};

const vsc_data_t test_data_JWT_API_KEY = {
    JWT_API_KEY, sizeof(JWT_API_KEY)
};
