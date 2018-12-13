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

#ifndef VIRGIL_CRYPTO_C_TOP_TEST_DATA_PHE_SERVER_H
#define VIRGIL_CRYPTO_C_TOP_TEST_DATA_PHE_SERVER_H

#include "vsc_data.h"

extern const vsc_data_t test_phe_server_rnd;
extern const vsc_data_t test_phe_server_private_key;
extern const vsc_data_t test_phe_server_public_key;
extern const vsc_data_t test_phe_client_private_key;
extern const vsc_data_t test_phe_server_enrollment_response;
extern const vsc_data_t test_phe_client_password;
extern const vsc_data_t test_phe_client_enrollment_record;
extern const vsc_data_t test_phe_client_record_key;
extern const vsc_data_t test_phe_client_verify_password_req;
extern const vsc_data_t test_phe_server_verify_password_resp;
extern const vsc_data_t test_phe_client_bad_password;
extern const vsc_data_t test_phe_client_verify_bad_password_req;
extern const vsc_data_t test_phe_server_verify_bad_password_resp;

#endif //VIRGIL_CRYPTO_C_TOP_TEST_DATA_PHE_SERVER_H
