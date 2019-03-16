//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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


#include "test_data_pkcs5_pbes2.h"


const byte test_pkcs5_pbes2_CIPHER_NONCE_BYTES[] = {
    0x4A, 0x2D, 0xDB, 0xD1, 0x69, 0x79, 0x95, 0x4B,
    0x6B, 0xEF, 0x5A, 0x63
};

vsc_data_t test_pkcs5_pbes2_CIPHER_NONCE = {
    test_pkcs5_pbes2_CIPHER_NONCE_BYTES, sizeof(test_pkcs5_pbes2_CIPHER_NONCE_BYTES)
};

const byte test_pkcs5_pbes2_PBKDF2_SALT_BYTES[] = {
    0x73, 0x61, 0x6C, 0x74
};

vsc_data_t test_pkcs5_pbes2_PBKDF2_SALT = {
    test_pkcs5_pbes2_PBKDF2_SALT_BYTES, sizeof(test_pkcs5_pbes2_PBKDF2_SALT_BYTES)
};

const byte test_pkcs5_pbes2_PASSWORD_BYTES[] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64
};

vsc_data_t test_pkcs5_pbes2_PASSWORD = {
    test_pkcs5_pbes2_PASSWORD_BYTES, sizeof(test_pkcs5_pbes2_PASSWORD_BYTES)
};

const byte test_pkcs5_pbes2_DATA_BYTES[] = {
    0x74, 0x65, 0x78, 0x74, 0x20, 0x6D, 0x65, 0x73,
    0x73, 0x61, 0x67, 0x65
};

vsc_data_t test_pkcs5_pbes2_DATA = {
    test_pkcs5_pbes2_DATA_BYTES, sizeof(test_pkcs5_pbes2_DATA_BYTES)
};

const byte test_pkcs5_pbes2_ENCRYPTED_DATA_BYTES[] = {
    0xF2, 0x4F, 0xF0, 0xC0, 0x66, 0x20, 0xB1, 0x8B,
    0xC9, 0x9C, 0x8A, 0x83, 0x16, 0x39, 0x84, 0x01,
    0xCC, 0xD1, 0xD6, 0xDC, 0xEB, 0x2C, 0xC8, 0x9B,
    0xA8, 0x0A, 0x0B, 0xC3
};

vsc_data_t test_pkcs5_pbes2_ENCRYPTED_DATA = {
    test_pkcs5_pbes2_ENCRYPTED_DATA_BYTES, sizeof(test_pkcs5_pbes2_ENCRYPTED_DATA_BYTES)
};


size_t test_pkcs5_pbes2_PBKDF2_ITERATION_COUNT = 1024;
