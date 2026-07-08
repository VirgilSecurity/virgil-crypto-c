// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#pragma once

#include <cstdint>
#include <virgil/crypto/foundation/vscf_oid_id.h>

namespace virgil::crypto::foundation {

enum class OidId : int {
    None = 0,
    Rsa = 1,
    Ed25519 = 2,
    Curve25519 = 3,
    Sha224 = 4,
    Sha256 = 5,
    Sha384 = 6,
    Sha512 = 7,
    Kdf1 = 8,
    Kdf2 = 9,
    Aes256Gcm = 10,
    Aes256Cbc = 11,
    Aes128Kw = 12,
    Aes192Kw = 13,
    Aes256Kw = 14,
    Pkcs5Pbkdf2 = 15,
    Pkcs5Pbes2 = 16,
    CmsData = 17,
    CmsEnvelopedData = 18,
    HkdfWithSha256 = 19,
    HkdfWithSha384 = 20,
    HkdfWithSha512 = 21,
    HmacWithSha224 = 22,
    HmacWithSha256 = 23,
    HmacWithSha384 = 24,
    HmacWithSha512 = 25,
    EcGenericKey = 26,
    EcDomainSecp256r1 = 27,
    CompoundKey = 28,
    HybridKey = 29,
    Falcon = 30,
    RandomPadding = 31,
    MlKem768 = 32,
    MlDsa65 = 33,
    Aes256GcmChunked = 34,
};

}  // namespace virgil::crypto::foundation
