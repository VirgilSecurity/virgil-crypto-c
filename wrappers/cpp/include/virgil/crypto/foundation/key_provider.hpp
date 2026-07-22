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
#include <memory>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_key_provider_t;

namespace virgil::crypto::foundation {

class PrivateKey;
class PublicKey;
class Random;

/// Provide functionality for private key generation and importing that
/// relies on the software default implementations.
class KeyProvider {
public:
    KeyProvider();
    /// Adopt ownership of an existing C handle.
    explicit KeyProvider(vscf_key_provider_t* c_ctx) noexcept;
    KeyProvider(const KeyProvider& other);
    KeyProvider(KeyProvider&& other) noexcept;
    KeyProvider& operator=(const KeyProvider& other);
    KeyProvider& operator=(KeyProvider&& other) noexcept;
    ~KeyProvider();

    /// The underlying concrete C handle (non-owning).
    vscf_key_provider_t* c_ctx() const noexcept;

    void set_random(const Random& random);

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults();

    /// Setup parameters that is used during RSA key generation.
    void set_rsa_params(std::size_t bitlen);

    /// Generate new private key with a given algorithm.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_private_key(AlgId alg_id);

    /// Generate new post-quantum private key with default algorithms.
    /// Note, that a post-quantum key combines classic private keys
    /// alongside with post-quantum private keys.
    /// Current structure is "compound private key" is:
    /// - cipher private key is "hybrid private key" where:
    /// - first key is a classic private key;
    /// - second key is a post-quantum private key;
    /// - signer private key "hybrid private key" where:
    /// - first key is a classic private key;
    /// - second key is a post-quantum private key.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_post_quantum_private_key();

    /// Generate new compound private key with given algorithms.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_compound_private_key(AlgId cipher_alg_id, AlgId signer_alg_id);

    /// Generate new hybrid private key with given algorithms.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_hybrid_private_key(AlgId first_key_alg_id, AlgId second_key_alg_id);

    /// Generate new compound private key with nested hybrid private keys.
    ///
    /// Note, second key algorithm identifiers can be NONE, in this case,
    /// a regular key will be crated instead of a hybrid key.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_compound_hybrid_private_key(AlgId cipher_first_key_alg_id, AlgId cipher_second_key_alg_id, AlgId signer_first_key_alg_id, AlgId signer_second_key_alg_id);

    /// Import private key from the PKCS#8 format.
    tl::expected<std::unique_ptr<PrivateKey>, Error> import_private_key(std::span<const uint8_t> key_data);

    /// Import public key from the PKCS#8 format.
    tl::expected<std::unique_ptr<PublicKey>, Error> import_public_key(std::span<const uint8_t> key_data);

    /// Calculate buffer size enough to hold exported public key.
    ///
    /// Precondition: public key must be exportable.
    std::size_t exported_public_key_len(const PublicKey& public_key);

    /// Export given public key to the PKCS#8 DER format.
    ///
    /// Precondition: public key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> export_public_key(const PublicKey& public_key);

    /// Calculate buffer size enough to hold exported private key.
    ///
    /// Precondition: private key must be exportable.
    std::size_t exported_private_key_len(const PrivateKey& private_key);

    /// Export given private key to the PKCS#8 or SEC1 DER format.
    ///
    /// Precondition: private key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> export_private_key(const PrivateKey& private_key);

private:
    vscf_key_provider_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
