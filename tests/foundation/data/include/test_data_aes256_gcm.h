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


#include "vsc_data.h"

//
//  Test vector 1
//  AES-GCM NIST Validation (AES-256,128,0,0,128) #0
//
extern const vsc_data_t test_aes256_gcm_VECTOR_1_KEY;
extern const vsc_data_t test_aes256_gcm_VECTOR_1_DATA;
extern const vsc_data_t test_aes256_gcm_VECTOR_1_NONCE;
extern const vsc_data_t test_aes256_gcm_VECTOR_1_ENC;
extern const vsc_data_t test_aes256_gcm_VECTOR_1_AUTH_TAG;
extern const vsc_data_t test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG;

//
//  Test vector 2
//  AES-GCM NIST Validation (AES-256,128,0,1024,128) #0
//
extern const vsc_data_t test_aes256_gcm_VECTOR_2_KEY;
extern const vsc_data_t test_aes256_gcm_VECTOR_2_DATA;
extern const vsc_data_t test_aes256_gcm_VECTOR_2_NONCE;
extern const vsc_data_t test_aes256_gcm_VECTOR_2_ADD;
extern const vsc_data_t test_aes256_gcm_VECTOR_2_ENC;
extern const vsc_data_t test_aes256_gcm_VECTOR_2_AUTH_TAG;

//
//  Test vector 3
//  AES-GCM NIST Validation (AES-256,128,1024,1024,128) #0
//
extern const vsc_data_t test_aes256_gcm_VECTOR_3_KEY;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_DATA;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_NONCE;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_ADD;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_ENC;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_AUTH_TAG;
extern const vsc_data_t test_aes256_gcm_VECTOR_3_ENC_PLUS_AUTH_TAG;
