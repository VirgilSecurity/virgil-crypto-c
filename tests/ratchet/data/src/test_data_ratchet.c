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

#include "test_data_ratchet.h"

const byte test_ratchet_plain_text1_BYTES[] = "Hello, this is first test message";

const byte test_ratchet_plain_text2_BYTES[] = "Test message number two";

const vsc_data_t test_ratchet_plain_text1 = {
        test_ratchet_plain_text1_BYTES, sizeof(test_ratchet_plain_text1_BYTES)
};

const vsc_data_t test_ratchet_plain_text2 = {
        test_ratchet_plain_text2_BYTES, sizeof(test_ratchet_plain_text2_BYTES)
};

const byte test_ratchet_kdf_info_root_BYTES[] = {
        0x31, 0xe0, 0x20, 0x5a,
};

const byte test_ratchet_kdf_info_ratchet_BYTES[] = {
        0xbf, 0x49, 0xc6, 0x1f,
};

const byte test_ratchet_kdf_info_cipher_BYTES[] = {
        0xd6, 0xc9, 0x97, 0x9c,
};

const byte test_ratchet_shared_secret_BYTES[] = {
        0x9b, 0x5b, 0xb8, 0xf5, 0x2b, 0xb9, 0x42, 0x41,
        0x7f, 0x2d, 0x4f, 0x5c, 0x6e, 0xe6, 0xfa, 0xd2,
        0x07, 0xee, 0xa7, 0xa4, 0xae, 0x66, 0xcd, 0xef,
        0x93, 0xdf, 0xb4, 0x18, 0x81, 0x9f, 0x64, 0x71,
        0x8f, 0x0d, 0x6c, 0x71, 0xfb, 0x43, 0x7a, 0x3d,
        0x35, 0x9b, 0xf7, 0xb7, 0x74, 0x41, 0xea, 0xd0,
        0xa2, 0xbb, 0x40, 0x7e, 0x47, 0x39, 0x2a, 0x55,
        0xc6, 0xbb, 0x53, 0x5d, 0x1c, 0xa6, 0x6e, 0xb2,
        0x7b, 0xbb, 0xea, 0x7f, 0x10, 0x1a, 0xfe, 0x09,
        0xb7, 0xa1, 0x8c, 0x2b, 0xdb, 0xf2, 0xef, 0xe2,
        0xaa, 0x90, 0xa8, 0x45, 0xd8, 0xdc, 0x5d, 0xde,
        0x0f, 0xda, 0x8d, 0xb7, 0x7a, 0xed, 0xc8, 0x3c,
};

const byte test_ratchet_ratchet_private_key_BYTES[] = {
        0x63, 0xc4, 0x8b, 0x44, 0xe8, 0xf9, 0x46, 0x16,
        0xa8, 0x38, 0x89, 0x5b, 0x7f, 0xb7, 0x87, 0x1b,
        0x03, 0x78, 0xfd, 0xa3, 0xcd, 0xb7, 0x0f, 0x3f,
        0x3f, 0x98, 0x19, 0x9a, 0x0e, 0xc3, 0x5c, 0x4f,
};

const vsc_data_t test_ratchet_kdf_info_root = {
        test_ratchet_kdf_info_root_BYTES, sizeof(test_ratchet_kdf_info_root_BYTES)
};

const vsc_data_t test_ratchet_kdf_info_ratchet = {
        test_ratchet_kdf_info_ratchet_BYTES, sizeof(test_ratchet_kdf_info_ratchet_BYTES)
};

const vsc_data_t test_ratchet_kdf_info_cipher = {
        test_ratchet_kdf_info_cipher_BYTES, sizeof(test_ratchet_kdf_info_cipher_BYTES)
};

const vsc_data_t test_ratchet_shared_secret = {
        test_ratchet_shared_secret_BYTES, sizeof(test_ratchet_shared_secret_BYTES)
};

const vsc_data_t test_ratchet_ratchet_private_key = {
        test_ratchet_ratchet_private_key_BYTES, sizeof(test_ratchet_ratchet_private_key_BYTES)
};
