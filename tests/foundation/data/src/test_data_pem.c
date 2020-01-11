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


#include "test_data_pem.h"

const char test_pem_TITLE[] = "PUBLIC KEY";

const size_t test_pem_TITLE_LEN = sizeof(test_pem_TITLE) - 1;

const char test_pem_NO_HEADER_STR[] =
        "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBTfMfo+0sJdXOfP/YT0BqY\n"
        "1QOeuFnA/YsB33KmNnPvrRIcM3RvKhwb5DmZz8VF+riXVpExrn63YBPoesMnB6nJ\n"
        "EPE6p5jPoF54cRtxa7XI86cLrdN+k3Ws91LB0Jap77rthIRyHp67CGX9DFVHCUYX\n"
        "1xP4b5KjL0PW/TtS1YVcc4RQSq1/35XO/++Aau1rdevWULcz7u7qU0ee849ZxfaC\n"
        "kHJKYu3QE9u27qVm/Vy0TnrNwCfkj322IN5+yrGHwxSYe63ky+HRndQ7DIbv+QDr\n"
        "TuH3k+jQM9lFmxRqr/mXHcHHJ0COlyKpHSeuO7MVHpeux/NgViKg44uLtOpG5hDr\n"
        "AgMBAAE=\n"
        "-----END PUBLIC KEY-----";
const vsc_data_t test_pem_NO_HEADER = {
    (const byte*)test_pem_NO_HEADER_STR, sizeof(test_pem_NO_HEADER_STR) - 1
};

const char test_pem_HEADER_WITHOUT_TRAILING_DASHES_STR[] =
        "-----BEGIN PUBLIC KEY\n"
        "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBTfMfo+0sJdXOfP/YT0BqY\n"
        "1QOeuFnA/YsB33KmNnPvrRIcM3RvKhwb5DmZz8VF+riXVpExrn63YBPoesMnB6nJ\n"
        "EPE6p5jPoF54cRtxa7XI86cLrdN+k3Ws91LB0Jap77rthIRyHp67CGX9DFVHCUYX\n"
        "1xP4b5KjL0PW/TtS1YVcc4RQSq1/35XO/++Aau1rdevWULcz7u7qU0ee849ZxfaC\n"
        "kHJKYu3QE9u27qVm/Vy0TnrNwCfkj322IN5+yrGHwxSYe63ky+HRndQ7DIbv+QDr\n"
        "TuH3k+jQM9lFmxRqr/mXHcHHJ0COlyKpHSeuO7MVHpeux/NgViKg44uLtOpG5hDr\n"
        "AgMBAAE=\n"
        "-----END PUBLIC KEY-----";
const vsc_data_t test_pem_HEADER_WITHOUT_TRAILING_DASHES = {
    (const byte*)test_pem_HEADER_WITHOUT_TRAILING_DASHES_STR, sizeof(test_pem_HEADER_WITHOUT_TRAILING_DASHES_STR) - 1
};

const char test_pem_NO_FOOTER_STR[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBTfMfo+0sJdXOfP/YT0BqY\n"
        "1QOeuFnA/YsB33KmNnPvrRIcM3RvKhwb5DmZz8VF+riXVpExrn63YBPoesMnB6nJ\n"
        "EPE6p5jPoF54cRtxa7XI86cLrdN+k3Ws91LB0Jap77rthIRyHp67CGX9DFVHCUYX\n"
        "1xP4b5KjL0PW/TtS1YVcc4RQSq1/35XO/++Aau1rdevWULcz7u7qU0ee849ZxfaC\n"
        "kHJKYu3QE9u27qVm/Vy0TnrNwCfkj322IN5+yrGHwxSYe63ky+HRndQ7DIbv+QDr\n"
        "TuH3k+jQM9lFmxRqr/mXHcHHJ0COlyKpHSeuO7MVHpeux/NgViKg44uLtOpG5hDr\n"
        "AgMBAAE=";
const vsc_data_t test_pem_NO_FOOTER = {
    (const byte*)test_pem_NO_FOOTER_STR, sizeof(test_pem_NO_FOOTER_STR) - 1
};

const char test_pem_FOOTER_WITHOUT_TRAILING_DASHES_STR[] =
        "-----BEGIN PUBLIC KEY-----\n"
       "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBTfMfo+0sJdXOfP/YT0BqY\n"
       "1QOeuFnA/YsB33KmNnPvrRIcM3RvKhwb5DmZz8VF+riXVpExrn63YBPoesMnB6nJ\n"
       "EPE6p5jPoF54cRtxa7XI86cLrdN+k3Ws91LB0Jap77rthIRyHp67CGX9DFVHCUYX\n"
       "1xP4b5KjL0PW/TtS1YVcc4RQSq1/35XO/++Aau1rdevWULcz7u7qU0ee849ZxfaC\n"
       "kHJKYu3QE9u27qVm/Vy0TnrNwCfkj322IN5+yrGHwxSYe63ky+HRndQ7DIbv+QDr\n"
       "TuH3k+jQM9lFmxRqr/mXHcHHJ0COlyKpHSeuO7MVHpeux/NgViKg44uLtOpG5hDr\n"
       "AgMBAAE=\n"
       "-----END PUBLIC KEY";
const vsc_data_t test_pem_FOOTER_WITHOUT_TRAILING_DASHES = {
    (const byte*)test_pem_FOOTER_WITHOUT_TRAILING_DASHES_STR, sizeof(test_pem_FOOTER_WITHOUT_TRAILING_DASHES_STR) - 1
};

const char test_pem_wrapped_ONELINE_STR[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
        "-----END PUBLIC KEY-----";
const vsc_data_t test_pem_wrapped_ONELINE = {
    (const byte*)test_pem_wrapped_ONELINE_STR, sizeof(test_pem_wrapped_ONELINE_STR) - 1
};

const byte test_pem_unwrapped_ONELINE_BYTES[] = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
    0x70, 0x03, 0x21, 0x00, 0x19, 0xBF, 0x44, 0x09,
    0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1,
    0x67, 0xDC, 0x3B, 0x96, 0xC8, 0x50, 0x86, 0xAA,
    0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD,
    0x70, 0x31, 0x66, 0xE1
};

const vsc_data_t test_pem_unwrapped_ONELINE = {
    test_pem_unwrapped_ONELINE_BYTES, sizeof(test_pem_unwrapped_ONELINE_BYTES)
};

const char test_pem_wrapped_MULTILINE_STR[] =
        "-----BEGIN PUBLIC KEY-----\n"
      "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBTfMfo+0sJdXOfP/YT0BqY\n"
      "1QOeuFnA/YsB33KmNnPvrRIcM3RvKhwb5DmZz8VF+riXVpExrn63YBPoesMnB6nJ\n"
      "EPE6p5jPoF54cRtxa7XI86cLrdN+k3Ws91LB0Jap77rthIRyHp67CGX9DFVHCUYX\n"
      "1xP4b5KjL0PW/TtS1YVcc4RQSq1/35XO/++Aau1rdevWULcz7u7qU0ee849ZxfaC\n"
      "kHJKYu3QE9u27qVm/Vy0TnrNwCfkj322IN5+yrGHwxSYe63ky+HRndQ7DIbv+QDr\n"
      "TuH3k+jQM9lFmxRqr/mXHcHHJ0COlyKpHSeuO7MVHpeux/NgViKg44uLtOpG5hDr\n"
      "AgMBAAE=\n"
      "-----END PUBLIC KEY-----";
const vsc_data_t test_pem_wrapped_MULTILINE = {
    (const byte*)test_pem_wrapped_MULTILINE_STR, sizeof(test_pem_wrapped_MULTILINE_STR) - 1
};

const byte test_pem_unwrapped_MULTILINE_BYTES[] = {
    0x30, 0x82, 0x01, 0x21, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0e, 0x00,
    0x30, 0x82, 0x01, 0x09, 0x02, 0x82, 0x01, 0x00,
    0x53, 0x7c, 0xc7, 0xe8, 0xfb, 0x4b, 0x09, 0x75,
    0x73, 0x9f, 0x3f, 0xf6, 0x13, 0xd0, 0x1a, 0x98,
    0xd5, 0x03, 0x9e, 0xb8, 0x59, 0xc0, 0xfd, 0x8b,
    0x01, 0xdf, 0x72, 0xa6, 0x36, 0x73, 0xef, 0xad,
    0x12, 0x1c, 0x33, 0x74, 0x6f, 0x2a, 0x1c, 0x1b,
    0xe4, 0x39, 0x99, 0xcf, 0xc5, 0x45, 0xfa, 0xb8,
    0x97, 0x56, 0x91, 0x31, 0xae, 0x7e, 0xb7, 0x60,
    0x13, 0xe8, 0x7a, 0xc3, 0x27, 0x07, 0xa9, 0xc9,
    0x10, 0xf1, 0x3a, 0xa7, 0x98, 0xcf, 0xa0, 0x5e,
    0x78, 0x71, 0x1b, 0x71, 0x6b, 0xb5, 0xc8, 0xf3,
    0xa7, 0x0b, 0xad, 0xd3, 0x7e, 0x93, 0x75, 0xac,
    0xf7, 0x52, 0xc1, 0xd0, 0x96, 0xa9, 0xef, 0xba,
    0xed, 0x84, 0x84, 0x72, 0x1e, 0x9e, 0xbb, 0x08,
    0x65, 0xfd, 0x0c, 0x55, 0x47, 0x09, 0x46, 0x17,
    0xd7, 0x13, 0xf8, 0x6f, 0x92, 0xa3, 0x2f, 0x43,
    0xd6, 0xfd, 0x3b, 0x52, 0xd5, 0x85, 0x5c, 0x73,
    0x84, 0x50, 0x4a, 0xad, 0x7f, 0xdf, 0x95, 0xce,
    0xff, 0xef, 0x80, 0x6a, 0xed, 0x6b, 0x75, 0xeb,
    0xd6, 0x50, 0xb7, 0x33, 0xee, 0xee, 0xea, 0x53,
    0x47, 0x9e, 0xf3, 0x8f, 0x59, 0xc5, 0xf6, 0x82,
    0x90, 0x72, 0x4a, 0x62, 0xed, 0xd0, 0x13, 0xdb,
    0xb6, 0xee, 0xa5, 0x66, 0xfd, 0x5c, 0xb4, 0x4e,
    0x7a, 0xcd, 0xc0, 0x27, 0xe4, 0x8f, 0x7d, 0xb6,
    0x20, 0xde, 0x7e, 0xca, 0xb1, 0x87, 0xc3, 0x14,
    0x98, 0x7b, 0xad, 0xe4, 0xcb, 0xe1, 0xd1, 0x9d,
    0xd4, 0x3b, 0x0c, 0x86, 0xef, 0xf9, 0x00, 0xeb,
    0x4e, 0xe1, 0xf7, 0x93, 0xe8, 0xd0, 0x33, 0xd9,
    0x45, 0x9b, 0x14, 0x6a, 0xaf, 0xf9, 0x97, 0x1d,
    0xc1, 0xc7, 0x27, 0x40, 0x8e, 0x97, 0x22, 0xa9,
    0x1d, 0x27, 0xae, 0x3b, 0xb3, 0x15, 0x1e, 0x97,
    0xae, 0xc7, 0xf3, 0x60, 0x56, 0x22, 0xa0, 0xe3,
    0x8b, 0x8b, 0xb4, 0xea, 0x46, 0xe6, 0x10, 0xeb,
    0x02, 0x03, 0x01, 0x00, 0x01
};

const vsc_data_t test_pem_unwrapped_MULTILINE = {
    test_pem_unwrapped_MULTILINE_BYTES, sizeof(test_pem_unwrapped_MULTILINE_BYTES)
};
