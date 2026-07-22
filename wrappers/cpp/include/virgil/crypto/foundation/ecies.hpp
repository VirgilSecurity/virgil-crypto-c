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
#include <virgil/crypto/foundation/error.hpp>

struct vscf_ecies_t;

namespace virgil::crypto::foundation {

class Cipher;
class Kdf;
class KeyAlg;
class Mac;
class PrivateKey;
class PublicKey;
class Random;

/// Virgil implementation of the ECIES algorithm.
class Ecies {
public:
    Ecies();
    /// Adopt ownership of an existing C handle.
    explicit Ecies(vscf_ecies_t* c_ctx) noexcept;
    Ecies(const Ecies& other);
    Ecies(Ecies&& other) noexcept;
    Ecies& operator=(const Ecies& other);
    Ecies& operator=(Ecies&& other) noexcept;
    ~Ecies();

    /// The underlying concrete C handle (non-owning).
    vscf_ecies_t* c_ctx() const noexcept;

    void set_random(const Random& random);

    void set_cipher(const Cipher& cipher);

    void set_mac(const Mac& mac);

    void set_kdf(const Kdf& kdf);

    void set_ephemeral_key(const PrivateKey& ephemeral_key);

    /// Set weak reference to the key algorithm.
    /// Key algorithm MUST support shared key computation as well.
    void set_key_alg(const KeyAlg& key_alg);

    /// Release weak reference to the key algorithm.
    void release_key_alg();

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults();

    /// Setup predefined values to the uninitialized class dependencies
    /// except random.
    void setup_defaults_no_random();

    /// Calculate required buffer length to hold the encrypted data.
    std::size_t encrypted_len(const PublicKey& public_key, std::size_t data_len) const;

    /// Encrypt data with a given public key.
    tl::expected<std::vector<uint8_t>, Error> encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const;

    /// Calculate required buffer length to hold the decrypted data.
    std::size_t decrypted_len(const PrivateKey& private_key, std::size_t data_len) const;

    /// Decrypt given data.
    tl::expected<std::vector<uint8_t>, Error> decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const;

private:
    vscf_ecies_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
