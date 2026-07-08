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
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/foundation/context.hpp>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>

namespace virgil::crypto::foundation {

class PrivateKey;
class PublicKey;

/// Provide data encryption and decryption interface with asymmetric keys.
class KeyCipher : virtual public Context, virtual public KeyAlg {
public:
    ~KeyCipher() override = default;

    /// Check if algorithm can encrypt data with a given key.
    virtual bool can_encrypt(const PublicKey& public_key, std::size_t data_len) const = 0;

    /// Calculate required buffer length to hold the encrypted data.
    virtual std::size_t encrypted_len(const PublicKey& public_key, std::size_t data_len) const = 0;

    /// Encrypt data with a given public key.
    virtual tl::expected<std::vector<uint8_t>, Error> encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const = 0;

    /// Check if algorithm can decrypt data with a given key.
    /// However, success result of decryption is not guaranteed.
    virtual bool can_decrypt(const PrivateKey& private_key, std::size_t data_len) const = 0;

    /// Calculate required buffer length to hold the decrypted data.
    virtual std::size_t decrypted_len(const PrivateKey& private_key, std::size_t data_len) const = 0;

    /// Decrypt given data.
    virtual tl::expected<std::vector<uint8_t>, Error> decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const = 0;

};

}  // namespace virgil::crypto::foundation
