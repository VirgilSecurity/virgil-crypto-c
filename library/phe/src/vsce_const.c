//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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


//  @description
// --------------------------------------------------------------------------
//  Internal constants for PHE library.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_const.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

#define COMMON_PREFIX 0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45

VSCE_PUBLIC const byte k_dhc0[8] = {
    COMMON_PREFIX,
    0x31
};

VSCE_PUBLIC const byte k_dhc1[8] = {
    COMMON_PREFIX,
    0x32
};

VSCE_PUBLIC const byte k_dhs0[8] = {
    COMMON_PREFIX,
    0x33
};

VSCE_PUBLIC const byte k_dhs1[8] = {
    COMMON_PREFIX,
    0x34
};

static const byte k_proof_ok_bytes[] = {
    COMMON_PREFIX,
    0x35
};

static const byte k_proof_error_bytes[] = {
    COMMON_PREFIX,
    0x36
};

static const byte k_encrypt_bytes[] = {
    COMMON_PREFIX,
    0x37
};

static const byte k_kdf_info_z_bytes[] = {
    COMMON_PREFIX,
    0x38
};

static const byte k_kdf_info_client_key_bytes[] = {
    COMMON_PREFIX,
    0x39
};

static const byte k_kdf_info_uokms_key_bytes[] = {
    COMMON_PREFIX,
    0x40
};

VSCE_PUBLIC const vsc_data_t k_proof_ok = {
    k_proof_ok_bytes,
    sizeof(k_proof_ok_bytes)
};

VSCE_PUBLIC const vsc_data_t k_proof_error = {
    k_proof_error_bytes,
    sizeof(k_proof_error_bytes)
};

VSCE_PUBLIC const vsc_data_t k_encrypt = {
    k_encrypt_bytes,
    sizeof(k_encrypt_bytes)
};

VSCE_PUBLIC const vsc_data_t k_kdf_info_z = {
    k_kdf_info_z_bytes,
    sizeof(k_kdf_info_z_bytes)
};

VSCE_PUBLIC const vsc_data_t k_kdf_info_client_key = {
    k_kdf_info_client_key_bytes,
    sizeof(k_kdf_info_client_key_bytes)
};

VSCE_PUBLIC const vsc_data_t k_kdf_info_uokms_key = {
    k_kdf_info_uokms_key_bytes,
    sizeof(k_kdf_info_uokms_key_bytes)
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
