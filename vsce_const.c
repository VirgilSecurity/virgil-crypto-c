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

static const byte dhc0_BYTES[] = {
        COMMON_PREFIX, 0x31
};

static const byte dhc1_BYTES[] = {
        COMMON_PREFIX, 0x32
};

static const byte dhs0_BYTES[] = {
        COMMON_PREFIX, 0x33
};

static const byte dhs1_BYTES[] = {
        COMMON_PREFIX, 0x34
};

static const byte proofOk_BYTES[] = {
        COMMON_PREFIX, 0x35
};

static const byte proofError_BYTES[] = {
        COMMON_PREFIX, 0x36
};

static const byte encrypt_BYTES[] = {
        COMMON_PREFIX, 0x37

};

static const byte kdfInfoZ_BYTES[] = {
        COMMON_PREFIX, 0x38
};

static const byte kdfInfoClientKey_BYTES[] = {
        COMMON_PREFIX, 0x39
};

const vsc_data_t k_dhc0 = {
        dhc0_BYTES, sizeof(dhc0_BYTES)
};

const vsc_data_t k_dhc1 = {
        dhc1_BYTES, sizeof(dhc1_BYTES)
};

const vsc_data_t k_dhs0 = {
        dhs0_BYTES, sizeof(dhs0_BYTES)
};

const vsc_data_t k_dhs1 = {
        dhs1_BYTES, sizeof(dhs1_BYTES)
};

const vsc_data_t k_proofOk = {
        proofOk_BYTES, sizeof(proofOk_BYTES)
};

const vsc_data_t k_proofError = {
        proofError_BYTES, sizeof(proofError_BYTES)
};

const vsc_data_t k_encrypt = {
        encrypt_BYTES, sizeof(encrypt_BYTES)
};

const vsc_data_t k_kdfInfoZ = {
        kdfInfoZ_BYTES, sizeof(kdfInfoZ_BYTES)
};

const vsc_data_t k_kdfInfoClientKey = {
        kdfInfoClientKey_BYTES, sizeof(kdfInfoClientKey_BYTES)
};
