//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#include "test_data_virgil_http_client.h"


// ==========================================================================
static const char JWT[] =
    "eyJraWQiOiI2NmY2MDFmY2IyYjI0ZWUxMjYxZWRhMThjMDZlYzljYiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiJ9."
    "eyJpc3MiOiJ2aXJnaWwtYjNkOGFlOGM5M2ZlNGQ4NmE0YjRiN2NhMDM0MDVkNTIiLCJzdWIiOiJpZGVudGl0eS01NjBhZGVjOC0xNTI4LTRjNWYtYjc4ZC1lMzNmMTQ4MTQ0OTciLCJpYXQiOjE1OTA0OTkxMjUsImV4cCI6MTU5MDUwMjcyNX0."
    "MFEwDQYJYIZIAWUDBAIDBQAEQDRH_ksg6Xd39dLoXmCRa56Px4ylZCCqQvH3ieK0E0zGG9Xvw7B0F2ZUpfVlIHo5JMMaKfuEuGpRLbICC5ILhQg";


const vsc_str_t test_data_virgil_http_client_JWT = {
    JWT, sizeof(JWT) - 1
};

// ==========================================================================
static const char HTTP_URL[] = "https://api.virgilsecurity.com/pythia/v1/brainkey";

const vsc_str_t test_data_virgil_http_client_HTTP_URL = {
    HTTP_URL, sizeof(HTTP_URL) - 1
};

// ==========================================================================
static const char HTTP_BODY[] =
    "{\"blinded_password\":\"AwOI9HIrKzoXMCL7SWAUJTgpPubbXC5zxD+pBhSQsz1me6g0YppFQwxZl9amrhXK3Q==\",\"brainkey_id\":\"BRAIN_KEY_ID_1\"}";

const vsc_str_t test_data_virgil_http_client_HTTP_BODY = {
    HTTP_BODY, sizeof(HTTP_BODY) - 1
};

// ==========================================================================
const size_t test_data_virgil_http_client_RESPONSE_STATUS_CODE = 401;

// ==========================================================================
const size_t test_data_virgil_http_client_RESPONSE_SERVICE_ERROR_CODE = 20304;

// ==========================================================================
static const char RESPONSE_SERVICE_ERROR_DESRIPTION[] = "JWT is expired";

const vsc_str_t test_data_virgil_http_client_RESPONSE_SERVICE_ERROR_DESRIPTION = {
    RESPONSE_SERVICE_ERROR_DESRIPTION, sizeof(RESPONSE_SERVICE_ERROR_DESRIPTION) - 1
};
