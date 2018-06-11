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

#ifndef TEST_UTILS_H_INCLUDED
#define TEST_UTILS_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// --------------------------------------------------------------------------
//  HEX utils
// --------------------------------------------------------------------------

//
//  Takes string with HEX data and converts to the byte array.
//  Return data length.
//  Precondition: string length must be even.
//  Precondition: data length must be at least half of the hex string length.
//
size_t unhexify(const char *hex_str, uint8_t *data);

//
//  Takes byte array and represents it as HEX string.
//  Precondition: string length must be at least doubled of the data length.
//
void hexify(const uint8_t *data, size_t data_len, char *hex_str);


// --------------------------------------------------------------------------
//  Assertion utils
// --------------------------------------------------------------------------

//
//  Handles assertion info.
//
typedef struct {
    bool handled;
    const char* message;
    const char* file;
    int line;
} mock_assert_result_t;

//
//  Global object that handles assertion info.
//
extern mock_assert_result_t g_mock_assert_result;

//
//  Set 'g_mock_assert_result' object to the initial state.
//
void mock_assert_reset(void);

//
//  Assertion handler that fills g_mock_assert_result in case of assertion.
//
void mock_assert_handler (const char* message, const char* file, int line);

#endif /* TEST_UTILS_H_INCLUDED */
