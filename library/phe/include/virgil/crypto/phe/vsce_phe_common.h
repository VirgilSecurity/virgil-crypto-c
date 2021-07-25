//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#ifndef VSCE_PHE_COMMON_H_INCLUDED
#define VSCE_PHE_COMMON_H_INCLUDED

#include "vsce_library.h"

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Public integral constants.
//
enum {
    //
    //  PHE elliptic curve point binary length
    //
    vsce_phe_common_PHE_POINT_LENGTH = 65,
    //
    //  PHE max password length
    //
    vsce_phe_common_PHE_MAX_PASSWORD_LENGTH = 128,
    //
    //  PHE server identifier length
    //
    vsce_phe_common_PHE_SERVER_IDENTIFIER_LENGTH = 32,
    //
    //  PHE client identifier length
    //
    vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH = 32,
    //
    //  PHE account key length
    //
    vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH = 32,
    //
    //  PHE private key length
    //
    vsce_phe_common_PHE_PRIVATE_KEY_LENGTH = 32,
    //
    //  PHE public key length
    //
    vsce_phe_common_PHE_PUBLIC_KEY_LENGTH = 65,
    //
    //  PHE hash length
    //
    vsce_phe_common_PHE_HASH_LEN = 32,
    //
    //  Maximum data size to encrypt
    //
    vsce_phe_common_PHE_MAX_ENCRYPT_LEN = 1024 * 1024 - 64,
    //
    //  Maximum data size to decrypt
    //
    vsce_phe_common_PHE_MAX_DECRYPT_LEN = 1024 * 1024,
    //
    //  Maximum data to authenticate
    //
    vsce_phe_common_PHE_MAX_AUTH_LEN = 1024
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_COMMON_H_INCLUDED
//  @end
