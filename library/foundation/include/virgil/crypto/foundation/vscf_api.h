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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Create module with functionality common for all 'api' objects.
//  It is also enumerate all available interfaces within crypto libary.
// --------------------------------------------------------------------------

#ifndef VSCF_API_H_INCLUDED
#define VSCF_API_H_INCLUDED

#include "vscf_library.h"

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
//  Enumerates all possible interfaces within crypto library.
//
enum vscf_api_tag_t {
    vscf_api_tag_BEGIN = 0,
    vscf_api_tag_ALG,
    vscf_api_tag_ALG_INFO,
    vscf_api_tag_ALG_INFO_DESERIALIZER,
    vscf_api_tag_ALG_INFO_SERIALIZER,
    vscf_api_tag_ASN1_READER,
    vscf_api_tag_ASN1_WRITER,
    vscf_api_tag_AUTH_DECRYPT,
    vscf_api_tag_AUTH_ENCRYPT,
    vscf_api_tag_CIPHER,
    vscf_api_tag_CIPHER_AUTH,
    vscf_api_tag_CIPHER_AUTH_INFO,
    vscf_api_tag_CIPHER_INFO,
    vscf_api_tag_COMPUTE_SHARED_KEY,
    vscf_api_tag_DECRYPT,
    vscf_api_tag_DEFAULTS,
    vscf_api_tag_ENCRYPT,
    vscf_api_tag_ENTROPY_SOURCE,
    vscf_api_tag_GENERATE_EPHEMERAL_KEY,
    vscf_api_tag_GENERATE_KEY,
    vscf_api_tag_HASH,
    vscf_api_tag_KDF,
    vscf_api_tag_KEY,
    vscf_api_tag_KEY_DESERIALIZER,
    vscf_api_tag_KEY_SERIALIZER,
    vscf_api_tag_MAC,
    vscf_api_tag_MESSAGE_INFO_SERIALIZER,
    vscf_api_tag_PRIVATE_KEY,
    vscf_api_tag_PUBLIC_KEY,
    vscf_api_tag_RANDOM,
    vscf_api_tag_SALTED_KDF,
    vscf_api_tag_SIGN,
    vscf_api_tag_VERIFY,
    vscf_api_tag_END
};
typedef enum vscf_api_tag_t vscf_api_tag_t;

//
//  Generic type for any 'API' object.
//
typedef struct vscf_api_t vscf_api_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_API_H_INCLUDED
//  @end
