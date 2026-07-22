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
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/compute_shared_key.hpp>
#include <virgil/crypto/foundation/kem.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_ed25519_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class Ecies;
class Key;
class PrivateKey;
class PublicKey;
class Random;
class RawPrivateKey;
class RawPublicKey;

/// This is implementation of Ed25519 elliptic curve algorithms.
class Ed25519 : virtual public KeyAlg, virtual public KeyCipher, virtual public KeySigner, virtual public ComputeSharedKey, virtual public Kem {
public:
    Ed25519();
    /// Adopt ownership of an existing C handle.
    explicit Ed25519(vscf_ed25519_t* c_ctx) noexcept;
    Ed25519(const Ed25519& other);
    Ed25519(Ed25519&& other) noexcept;
    Ed25519& operator=(const Ed25519& other);
    Ed25519& operator=(Ed25519&& other) noexcept;
    ~Ed25519();

    /// The underlying concrete C handle (non-owning).
    vscf_ed25519_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    void set_random(const Random& random);

    void set_ecies(const Ecies& ecies);

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults();

    /// Generate new private key.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_key() const;

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_ephemeral_key(const Key& key) const override;

    /// Import public key from the raw binary format.
    ///
    /// Return public key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    tl::expected<std::unique_ptr<PublicKey>, Error> import_public_key(const RawPublicKey& raw_key) const override;

    /// Export public key to the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    tl::expected<RawPublicKey, Error> export_public_key(const PublicKey& public_key) const override;

    /// Import private key from the raw binary format.
    ///
    /// Return private key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.2.
    tl::expected<std::unique_ptr<PrivateKey>, Error> import_private_key(const RawPrivateKey& raw_key) const override;

    /// Export private key in the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be exported in format defined in
    /// RFC 3447 Appendix A.1.2.
    tl::expected<RawPrivateKey, Error> export_private_key(const PrivateKey& private_key) const override;

    /// Check if algorithm can encrypt data with a given key.
    bool can_encrypt(const PublicKey& public_key, std::size_t data_len) const override;

    /// Calculate required buffer length to hold the encrypted data.
    std::size_t encrypted_len(const PublicKey& public_key, std::size_t data_len) const override;

    /// Encrypt data with a given public key.
    tl::expected<std::vector<uint8_t>, Error> encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const override;

    /// Check if algorithm can decrypt data with a given key.
    /// However, success result of decryption is not guaranteed.
    bool can_decrypt(const PrivateKey& private_key, std::size_t data_len) const override;

    /// Calculate required buffer length to hold the decrypted data.
    std::size_t decrypted_len(const PrivateKey& private_key, std::size_t data_len) const override;

    /// Decrypt given data.
    tl::expected<std::vector<uint8_t>, Error> decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const override;

    /// Check if algorithm can sign data digest with a given key.
    bool can_sign(const PrivateKey& private_key) const override;

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    std::size_t signature_len(const PrivateKey& private_key) const override;

    /// Sign data digest with a given private key.
    tl::expected<std::vector<uint8_t>, Error> sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) const override;

    /// Check if algorithm can verify data digest with a given key.
    bool can_verify(const PublicKey& public_key) const override;

    /// Verify data digest with a given public key and signature.
    bool verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) const override;

    /// Compute shared key for 2 asymmetric keys.
    /// Note, computed shared key can be used only within symmetric cryptography.
    tl::expected<std::vector<uint8_t>, Error> compute_shared_key(const PublicKey& public_key, const PrivateKey& private_key) const override;

    /// Return number of bytes required to hold shared key.
    /// Expect Public Key or Private Key.
    std::size_t shared_key_len(const Key& key) const override;

    /// Return length in bytes required to hold encapsulated shared key.
    std::size_t kem_shared_key_len(const Key& key) const override;

    /// Return length in bytes required to hold encapsulated key.
    std::size_t kem_encapsulated_key_len(const PublicKey& public_key) const override;

    /// Generate a shared key and a key encapsulated message.
    tl::expected<KemKemEncapsulateResult, Error> kem_encapsulate(const PublicKey& public_key) const override;

    /// Decapsulate the shared key.
    tl::expected<std::vector<uint8_t>, Error> kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) const override;

private:
    vscf_ed25519_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
