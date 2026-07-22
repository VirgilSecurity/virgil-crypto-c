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
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vsce_phe_cipher_t;

namespace virgil::crypto::phe {

/// Class for encryption using PHE account key
/// This class is thread-safe.
class PheCipher {
public:
    PheCipher();
    /// Adopt ownership of an existing C handle.
    explicit PheCipher(vsce_phe_cipher_t* c_ctx) noexcept;
    PheCipher(const PheCipher& other);
    PheCipher(PheCipher&& other) noexcept;
    PheCipher& operator=(const PheCipher& other);
    PheCipher& operator=(PheCipher&& other) noexcept;
    ~PheCipher();

    /// The underlying concrete C handle (non-owning).
    vsce_phe_cipher_t* c_ctx() const noexcept;

    void set_random(const virgil::crypto::foundation::Random& random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Returns buffer capacity needed to fit cipher text
    std::size_t encrypt_len(std::size_t plain_text_len);

    /// Returns buffer capacity needed to fit plain text
    std::size_t decrypt_len(std::size_t cipher_text_len);

    /// Encrypts data using account key
    tl::expected<std::vector<uint8_t>, Error> encrypt(std::span<const uint8_t> plain_text, std::span<const uint8_t> account_key);

    /// Decrypts data using account key
    tl::expected<std::vector<uint8_t>, Error> decrypt(std::span<const uint8_t> cipher_text, std::span<const uint8_t> account_key);

    /// Encrypts data (and authenticates additional data) using account key
    tl::expected<std::vector<uint8_t>, Error> auth_encrypt(std::span<const uint8_t> plain_text, std::span<const uint8_t> additional_data, std::span<const uint8_t> account_key);

    /// Decrypts data (and verifies additional data) using account key
    tl::expected<std::vector<uint8_t>, Error> auth_decrypt(std::span<const uint8_t> cipher_text, std::span<const uint8_t> additional_data, std::span<const uint8_t> account_key);

private:
    vsce_phe_cipher_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
