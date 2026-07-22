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
#include <virgil/crypto/foundation/vscf_alg_id.h>

namespace virgil::crypto::foundation {

/// Define implemented algorithm identificator.
enum class AlgId : int {
    None = 0,
    Sha224 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
    Kdf1 = 5,
    Kdf2 = 6,
    Rsa = 7,
    Ed25519 = 8,
    Curve25519 = 9,
    Secp256r1 = 10,
    Aes256Gcm = 11,
    Aes256Cbc = 12,
    Aes128Kw = 13,
    Aes192Kw = 14,
    Aes256Kw = 15,
    Hmac = 16,
    Hkdf = 17,
    Pkcs5Pbkdf2 = 18,
    Pkcs5Pbes2 = 19,
    CompoundKey = 20,
    HybridKey = 21,
    Falcon = 22,
    RandomPadding = 23,
    MlKem768 = 24,
    MlDsa65 = 25,
    Aes256GcmChunked = 26,
};

}  // namespace virgil::crypto::foundation
