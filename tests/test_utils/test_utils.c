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

//
//  Initial code was taken form the MbedTLS test.
//  See https://github.com/ARMmbed/mbedtls.

#include "test_utils.h"

#include "unity.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>


// --------------------------------------------------------------------------
//  HEX utils
// --------------------------------------------------------------------------

size_t
unhexify(const char *hex_str, uint8_t *data) {
    uint8_t c, c2;
    size_t len = strlen(hex_str) / 2;
    assert(strlen(hex_str) % 2 == 0); /* must be even number of uint8_ts */

    while (*hex_str != 0) {
        c = *hex_str++;
        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'a' && c <= 'f') {
            c -= 'a' - 10;
        } else if (c >= 'A' && c <= 'F') {
            c -= 'A' - 10;
        } else {
            assert(0);
        }

        c2 = *hex_str++;
        if (c2 >= '0' && c2 <= '9') {
            c2 -= '0';
        } else if (c2 >= 'a' && c2 <= 'f') {
            c2 -= 'a' - 10;
        } else if (c2 >= 'A' && c2 <= 'F') {
            c2 -= 'A' - 10;
        } else {
            assert(0);
        }

        *data++ = (c << 4) | c2;
    }

    return len;
}

void
hexify(const uint8_t *data, size_t data_len, char *hex_str) {
    uint8_t l, h;

    while (data_len != 0) {
        h = *data / 16;
        l = *data % 16;

        if (h < 10) {
            *hex_str++ = '0' + h;
        } else {
            *hex_str++ = 'a' + h - 10;
        }

        if (l < 10) {
            *hex_str++ = '0' + l;
        } else {
            *hex_str++ = 'a' + l - 10;
        }

        ++data;
        --data_len;
    }
}

void
print_bytes(const byte *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; ++i) {
        fprintf(stdout, "%02X", bytes[i]);
    }
    fprintf(stdout, "\r\n");
}

void
print_bytes_formatted(const byte *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; ++i) {
        fprintf(stdout, "%02X%s", bytes[i], (i + 1) % 16 == 0 ? "\r\n" : " ");
    }
    fprintf(stdout, "\r\n");
}

// --------------------------------------------------------------------------
//  Assertion utils
// --------------------------------------------------------------------------

mock_assert_result_t g_mock_assert_result = {false, NULL, NULL, 0};

void
mock_assert_handler(const char *message, const char *file, int line) {
    g_mock_assert_result.handled = true;
    g_mock_assert_result.message = message;
    g_mock_assert_result.file = file;
    g_mock_assert_result.line = line;
}

void
mock_assert_reset(void) {
    memset(&g_mock_assert_result, 0x00, sizeof(mock_assert_result_t));
}


// --------------------------------------------------------------------------
//  Usefull stubs
// --------------------------------------------------------------------------

void
test__nothing__feature_disabled__must_be_ignored(void) {
    TEST_IGNORE();
}


// --------------------------------------------------------------------------
//  Data & buffer utils
// --------------------------------------------------------------------------

//
//  Print data
//
void
print_data(vsc_data_t data) {
    print_bytes(data.bytes, data.len);
}

//
//  Print buffer
//
void
print_buffer(vsc_buffer_t *buffer) {
    print_data(vsc_buffer_data(buffer));
}
