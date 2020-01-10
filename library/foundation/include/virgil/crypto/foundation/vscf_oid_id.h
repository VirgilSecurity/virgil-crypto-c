//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#ifndef VSCF_OID_ID_H_INCLUDED
#define VSCF_OID_ID_H_INCLUDED

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

enum vscf_oid_id_t {
    vscf_oid_id_NONE,
    vscf_oid_id_RSA,
    vscf_oid_id_ED25519,
    vscf_oid_id_CURVE25519,
    vscf_oid_id_SHA224,
    vscf_oid_id_SHA256,
    vscf_oid_id_SHA384,
    vscf_oid_id_SHA512,
    vscf_oid_id_KDF1,
    vscf_oid_id_KDF2,
    vscf_oid_id_AES256_GCM,
    vscf_oid_id_AES256_CBC,
    vscf_oid_id_PKCS5_PBKDF2,
    vscf_oid_id_PKCS5_PBES2,
    vscf_oid_id_CMS_DATA,
    vscf_oid_id_CMS_ENVELOPED_DATA,
    vscf_oid_id_HKDF_WITH_SHA256,
    vscf_oid_id_HKDF_WITH_SHA384,
    vscf_oid_id_HKDF_WITH_SHA512,
    vscf_oid_id_HMAC_WITH_SHA224,
    vscf_oid_id_HMAC_WITH_SHA256,
    vscf_oid_id_HMAC_WITH_SHA384,
    vscf_oid_id_HMAC_WITH_SHA512,
    vscf_oid_id_EC_GENERIC_KEY,
    vscf_oid_id_EC_DOMAIN_SECP256R1,
    vscf_oid_id_COMPOUND_KEY,
    vscf_oid_id_HYBRID_KEY,
    vscf_oid_id_FALCON,
    vscf_oid_id_ROUND5_ND_5KEM_5D,
    vscf_oid_id_RANDOM_PADDING
};
typedef enum vscf_oid_id_t vscf_oid_id_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_OID_ID_H_INCLUDED
//  @end
