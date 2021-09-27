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

#ifndef VIRGIL_INTEGRATION_TEST_ENV_H_INCLUDED
#define VIRGIL_INTEGRATION_TEST_ENV_H_INCLUDED


#include <virgil/crypto/common/vsc_data.h>
#include <virgil/crypto/common/vsc_str.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/sdk/core/vssc_jwt.h>


typedef struct {
    vsc_str_t url;
    vsc_str_t app_id;
    vsc_str_t app_key_id;
    vsc_data_t app_key_data;
    vsc_data_t app_public_key_data;
    vsc_data_t virgil_public_key_data;
    const vscf_impl_t *app_key;
    const vscf_impl_t *app_public_key;
    const vscf_impl_t *random;
    const vscf_impl_t *virgil_public_key;
    const vssc_jwt_t *jwt;
    const vssc_jwt_t *jwt2;
    const void *inner;
} test_env_t;


//
//  Load test environment.
//  Return non-zero if error.
//
int
test_env_load(void);

//
//  Release test environment.
//
void
test_env_release(void);

//
//  Return loaded test environment.
//
const test_env_t *
test_env_get(void);

#endif // VIRGIL_INTEGRATION_TEST_ENV_H_INCLUDED
