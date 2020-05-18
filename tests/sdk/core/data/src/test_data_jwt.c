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


// ==========================================================================
const size_t test_data_jwt_ISSUED_AT = 1589814415;
const size_t test_data_jwt_EXPIRES_AT = 1589815315;

// ==========================================================================
static const char IDENTITY[] = "alice";

const vsc_str_t test_data_jwt_IDENTITY = {
    IDENTITY, sizeof(IDENTITY) - 1
};


// ==========================================================================
static const char APP_ID[] = "97a4852c857447b63d5a1eeb7282e3f1";

const vsc_str_t test_data_jwt_APP_ID = {
    APP_ID, sizeof(APP_ID) - 1
};


// ==========================================================================
static const char APP_KEY_ID[] = "b7126c3a784524a5";

const vsc_str_t test_data_jwt_APP_KEY_ID = {
    APP_KEY_ID, sizeof(APP_KEY_ID) - 1
};

// ==========================================================================
static byte APP_PUBLIC_KEY[] = {
    0X30, 0X2A, 0X30, 0X05, 0X06, 0X03, 0X2B, 0X65, 0X70, 0X03, 0X21, 0X00, 0XCA, 0X25, 0X25, 0XAD,
    0X13, 0X8C, 0X5D, 0X81, 0X2E, 0X36, 0X4B, 0X33, 0XF6, 0X9D, 0XFA, 0XA8, 0X32, 0X7A, 0X4F, 0X3D,
    0XA1, 0X00, 0XA6, 0X34, 0XC6, 0XED, 0XC0, 0X7F, 0XCE, 0X89, 0XBD, 0X7F
};

const vsc_data_t test_data_jwt_APP_PUBLIC_KEY = {
    APP_PUBLIC_KEY, sizeof(APP_PUBLIC_KEY)
};

// ==========================================================================
static byte APP_KEY[] = {
    0X30, 0X2E, 0X02, 0X01, 0X00, 0X30, 0X05, 0X06, 0X03, 0X2B, 0X65, 0X70, 0X04, 0X22, 0X04, 0X20,
    0X41, 0X23, 0X87, 0X60, 0XE8, 0X44, 0X3C, 0X79, 0XBA, 0X0B, 0XE8, 0XAD, 0XFF, 0XDF, 0X84, 0XBF,
    0XC6, 0XAA, 0X01, 0XF4, 0XF3, 0XA4, 0X57, 0XC5, 0X66, 0XFB, 0X12, 0XCF, 0X6A, 0X3F, 0X53, 0X83,
};

const vsc_data_t test_data_jwt_APP_KEY = {
    APP_KEY, sizeof(APP_KEY)
};

// ==========================================================================
static const char HEADER_VALID[] =
    "eyJraWQiOiJiNzEyNmMzYTc4NDUyNGE1IiwiY3R5IjoidmlyZ2lsLWp3dDt2PTEiLCJ0eXAiOiJKV1QiLCJhbGciOiJWRURTNTEyIn0";

const vsc_str_t test_data_jwt_HEADER_VALID = {
    HEADER_VALID, sizeof(HEADER_VALID) - 1
};


// ==========================================================================
static const char PAYLOAD_VALID[] =
    "eyJpc3MiOiJ2aXJnaWwtOTdhNDg1MmM4NTc0NDdiNjNkNWExZWViNzI4MmUzZjEiLCJzdWIiOiJpZGVudGl0eS1hbGljZSIsImlhdCI6MTU4OTgxNDQxNSwiZXhwIjoxNTg5ODE1MzE1fQ";

const vsc_str_t test_data_jwt_PAYLOAD_VALID = {
    PAYLOAD_VALID, sizeof(PAYLOAD_VALID) - 1
};

// ==========================================================================
static const char SIGNATURE_VALID[] =
    "MFEwDQYJYIZIAWUDBAIDBQAEQJsVj-P-trG19Gv8-_fI5sf9H4fji9uywAacR0VQP8kuSKfZhXuIBWzCXp2_1_WBmIwL5RRb4nEloyCqIm58_wg";

const vsc_str_t test_data_jwt_SIGNATURE_VALID = {
    SIGNATURE_VALID, sizeof(SIGNATURE_VALID) - 1
};

// ==========================================================================
static const char VALID[] =
    "eyJraWQiOiJiNzEyNmMzYTc4NDUyNGE1IiwiY3R5IjoidmlyZ2lsLWp3dDt2PTEiLCJ0eXAiOiJKV1QiLCJhbGciOiJWRURTNTEyIn0."
    "eyJpc3MiOiJ2aXJnaWwtOTdhNDg1MmM4NTc0NDdiNjNkNWExZWViNzI4MmUzZjEiLCJzdWIiOiJpZGVudGl0eS1hbGljZSIsImlhdCI6MTU4OTgxNDQxNSwiZXhwIjoxNTg5ODE1MzE1fQ."
    "FEwDQYJYIZIAWUDBAIDBQAEQJsVj-P-trG19Gv8-_fI5sf9H4fji9uywAacR0VQP8kuSKfZhXuIBWzCXp2_1_WBmIwL5RRb4nEloyCqIm58_wg";

const vsc_str_t test_data_jwt_VALID = {
    VALID, sizeof(VALID) - 1
};
