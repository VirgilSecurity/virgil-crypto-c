//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off

#include "vsce_const.h"

#define COMMON_PREFIX 0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45

const byte k_dhc0[] = {
        COMMON_PREFIX, 0x31
};

const byte k_dhc1[] = {
        COMMON_PREFIX, 0x32
};

const byte k_dhs0[] = {
        COMMON_PREFIX, 0x33
};

const byte k_dhs1[] = {
        COMMON_PREFIX, 0x34
};

static const byte k_proof_ok_BYTES[] = {
        COMMON_PREFIX, 0x35
};

static const byte k_proof_error_BYTES[] = {
        COMMON_PREFIX, 0x36
};

static const byte k_encrypt_BYTES[] = {
        COMMON_PREFIX, 0x37

};

static const byte k_kdf_info_z_BYTES[] = {
        COMMON_PREFIX, 0x38
};

static const byte k_kdf_info_client_key_BYTES[] = {
        COMMON_PREFIX, 0x39
};

const vsc_data_t k_proof_ok = {
        k_proof_ok_BYTES, sizeof(k_proof_ok_BYTES)
};

const vsc_data_t k_proof_error = {
        k_proof_error_BYTES, sizeof(k_proof_error_BYTES)
};

const vsc_data_t k_encrypt = {
        k_encrypt_BYTES, sizeof(k_encrypt_BYTES)
};

const vsc_data_t k_kdf_info_z = {
        k_kdf_info_z_BYTES, sizeof(k_kdf_info_z_BYTES)
};

const vsc_data_t k_kdf_info_client_key = {
        k_kdf_info_client_key_BYTES, sizeof(k_kdf_info_client_key_BYTES)
};
