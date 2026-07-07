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

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/foundation/context.hpp>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/auth_encrypt.hpp>
#include <virgil/crypto/foundation/auth_decrypt.hpp>

namespace virgil::crypto::foundation {

/// Result of CipherAuth::finish_auth_encryption().
struct CipherAuthFinishAuthEncryptionResult {
    std::vector<uint8_t> out;
    std::vector<uint8_t> tag;
};

/// Mix-in interface that provides specific functionality to authenticated
/// encryption and decryption (AEAD ciphers).
class CipherAuth : virtual public Context, virtual public Cipher, virtual public AuthEncrypt, virtual public AuthDecrypt {
public:
    ~CipherAuth() override = default;

    /// Set additional data for for AEAD ciphers.
    virtual void set_auth_data(std::span<const uint8_t> auth_data) = 0;

    /// Accomplish an authenticated encryption and place tag separately.
    ///
    /// Note, if authentication tag should be added to an encrypted data,
    /// method "finish" can be used.
    virtual tl::expected<CipherAuthFinishAuthEncryptionResult, Error> finish_auth_encryption() = 0;

    /// Accomplish an authenticated decryption with explicitly given tag.
    ///
    /// Note, if authentication tag is a part of an encrypted data then,
    /// method "finish" can be used for simplicity.
    virtual tl::expected<std::vector<uint8_t>, Error> finish_auth_decryption(std::span<const uint8_t> tag) = 0;

};

}  // namespace virgil::crypto::foundation
