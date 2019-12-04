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

#include "test_data_alg_info_der.h"


const byte test_alg_info_SHA256_DER_BYTES[] = {
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01
};

const vsc_data_t test_alg_info_SHA256_DER = {
    test_alg_info_SHA256_DER_BYTES, sizeof(test_alg_info_SHA256_DER_BYTES)
};

const byte test_alg_info_SHA256_DER_V2_COMPAT_BYTES[] = {
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00
};

const vsc_data_t test_alg_info_SHA256_DER_V2_COMPAT = {
    test_alg_info_SHA256_DER_V2_COMPAT_BYTES, sizeof(test_alg_info_SHA256_DER_V2_COMPAT_BYTES)
};

const byte test_alg_info_KDF1_SHA256_DER_BYTES[] = {
    0x30, 0x16, 0x06, 0x07, 0x28, 0x81, 0x8C, 0x71,
    0x02, 0x05, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};

const vsc_data_t test_alg_info_KDF1_SHA256_DER = {
    test_alg_info_KDF1_SHA256_DER_BYTES, sizeof(test_alg_info_KDF1_SHA256_DER_BYTES)
};

const byte test_alg_info_KDF1_SHA256_DER_V2_COMPAT_BYTES[] = {
    0x30, 0x18, 0x06, 0x07, 0x28, 0x81, 0x8C, 0x71,
    0x02, 0x05, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00
};

const vsc_data_t test_alg_info_KDF1_SHA256_DER_V2_COMPAT = {
    test_alg_info_KDF1_SHA256_DER_V2_COMPAT_BYTES, sizeof(test_alg_info_KDF1_SHA256_DER_V2_COMPAT_BYTES)
};

const byte test_alg_info_AES256_GCM_DER_BYTES[] = {
    0x30, 0x1E, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x01, 0x2E, 0x30, 0x11, 0x04,
    0x0C, 0xC3, 0x75, 0x6D, 0xC3, 0x22, 0x3C, 0x47,
    0x57, 0x35, 0x05, 0xBF, 0x59, 0x02, 0x01, 0x0C,
};

const vsc_data_t test_alg_info_AES256_GCM_DER = {
    test_alg_info_AES256_GCM_DER_BYTES, sizeof(test_alg_info_AES256_GCM_DER_BYTES)
};

const byte test_alg_info_AES256_GCM_DER_V2_COMPAT_BYTES[] = {
    0x30, 0x19, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x01, 0x2E, 0x04, 0x0C, 0xC3,
    0x75, 0x6D, 0xC3, 0x22, 0x3C, 0x47, 0x57, 0x35,
    0x05, 0xBF, 0x59
};

const vsc_data_t test_alg_info_AES256_GCM_DER_V2_COMPAT = {
    test_alg_info_AES256_GCM_DER_V2_COMPAT_BYTES, sizeof(test_alg_info_AES256_GCM_DER_V2_COMPAT_BYTES)
};

const byte test_alg_info_AES256_GCM_NONCE_BYTES[] = {
    0xC3, 0x75, 0x6D, 0xC3, 0x22, 0x3C, 0x47, 0x57,
    0x35, 0x05, 0xBF, 0x59
};

const vsc_data_t test_alg_info_AES256_GCM_NONCE = {
    test_alg_info_AES256_GCM_NONCE_BYTES, sizeof(test_alg_info_AES256_GCM_NONCE_BYTES)
};

const byte test_alg_info_PADDING_CIPHER_WITH_RANDOM_PADDING_AND_AES256_GCM_BYTES[] = {
    0x30, 0x37, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x05, 0x30, 0x29,
    0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xAC, 0x1B, 0x01, 0x03, 0x30, 0x19,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E, 0x04, 0x0C, 0xC3, 0x75, 0x6D,
    0xC3, 0x22, 0x3C, 0x47, 0x57, 0x35, 0x05, 0xBF, 0x59
};

const vsc_data_t test_alg_info_PADDING_CIPHER_WITH_RANDOM_PADDING_AND_AES256_GCM = {
    test_alg_info_PADDING_CIPHER_WITH_RANDOM_PADDING_AND_AES256_GCM_BYTES, sizeof(test_alg_info_PADDING_CIPHER_WITH_RANDOM_PADDING_AND_AES256_GCM_BYTES)
};
