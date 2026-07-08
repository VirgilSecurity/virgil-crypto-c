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
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_compound_key_alg_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class Key;
class PrivateKey;
class PublicKey;
class Random;
class RawPrivateKey;
class RawPublicKey;

/// Implements public key cryptography over compound keys.
///
/// Compound key contains 2 keys - one for encryption/decryption and
/// one for signing/verifying.
class CompoundKeyAlg : virtual public Alg, virtual public KeyAlg, virtual public KeyCipher, virtual public KeySigner {
public:
    CompoundKeyAlg();
    /// Adopt ownership of an existing C handle.
    explicit CompoundKeyAlg(vscf_compound_key_alg_t* c_ctx) noexcept;
    CompoundKeyAlg(const CompoundKeyAlg& other);
    CompoundKeyAlg(CompoundKeyAlg&& other) noexcept;
    CompoundKeyAlg& operator=(const CompoundKeyAlg& other);
    CompoundKeyAlg& operator=(CompoundKeyAlg&& other) noexcept;
    ~CompoundKeyAlg();

    /// The underlying concrete C handle (non-owning).
    vscf_compound_key_alg_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    void set_random(const Random& random);

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults();

    /// Make compound private key from given.
    ///
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> make_key(const PrivateKey& cipher_key, const PrivateKey& signer_key) const;

    /// Provide algorithm identificator.
    AlgId alg_id() const override;

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override;

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override;

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

private:
    vscf_compound_key_alg_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
