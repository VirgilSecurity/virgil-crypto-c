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
#include <virgil/crypto/foundation/vscf_ecc.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/compute_shared_key.hpp>
#include <virgil/crypto/foundation/kem.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/ecies.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Elliptic curve cryptography implementation.
/// Supported curves:
/// - secp256r1.
class Ecc : virtual public KeyAlg, virtual public KeyCipher, virtual public KeySigner, virtual public ComputeSharedKey, virtual public Kem {
public:
    Ecc() : c_ctx_(vscf_ecc_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Ecc(vscf_ecc_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Ecc(const Ecc& other) : c_ctx_(vscf_ecc_shallow_copy(other.c_ctx_)) {}
    Ecc(Ecc&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Ecc& operator=(const Ecc& other) {
        if (this != &other) {
            vscf_ecc_delete(c_ctx_);
            c_ctx_ = vscf_ecc_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Ecc& operator=(Ecc&& other) noexcept {
        if (this != &other) {
            vscf_ecc_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Ecc() { vscf_ecc_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_ecc_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_ecc_impl(c_ctx_); }

    void set_random(const Random& random) {
        vscf_ecc_release_random(c_ctx_);
        vscf_ecc_use_random(c_ctx_, random.impl());
    }

    void set_ecies(const Ecies& ecies) {
        vscf_ecc_release_ecies(c_ctx_);
        vscf_ecc_use_ecies(c_ctx_, ecies.c_ctx());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_ecc_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generate new private key.
    /// Supported algorithm ids:
    /// - secp256r1.
    ///
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_key(AlgId alg_id) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_generate_key(c_ctx_, static_cast<vscf_alg_id_t>(alg_id), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_ephemeral_key(const Key& key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_generate_ephemeral_key(c_ctx_, key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Import public key from the raw binary format.
    ///
    /// Return public key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    tl::expected<std::unique_ptr<PublicKey>, Error> import_public_key(const RawPublicKey& raw_key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_public_key(proxy_result);
    }

    /// Export public key to the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    tl::expected<RawPublicKey, Error> export_public_key(const PublicKey& public_key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_export_public_key(c_ctx_, public_key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPublicKey(proxy_result);
    }

    /// Import private key from the raw binary format.
    ///
    /// Return private key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.2.
    tl::expected<std::unique_ptr<PrivateKey>, Error> import_private_key(const RawPrivateKey& raw_key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Export private key in the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be exported in format defined in
    /// RFC 3447 Appendix A.1.2.
    tl::expected<RawPrivateKey, Error> export_private_key(const PrivateKey& private_key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ecc_export_private_key(c_ctx_, private_key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPrivateKey(proxy_result);
    }

    /// Check if algorithm can encrypt data with a given key.
    bool can_encrypt(const PublicKey& public_key, std::size_t data_len) override {
        auto proxy_result = vscf_ecc_can_encrypt(c_ctx_, public_key.impl(), data_len);
        return proxy_result;
    }

    /// Calculate required buffer length to hold the encrypted data.
    std::size_t encrypted_len(const PublicKey& public_key, std::size_t data_len) override {
        auto proxy_result = vscf_ecc_encrypted_len(c_ctx_, public_key.impl(), data_len);
        return proxy_result;
    }

    /// Encrypt data with a given public key.
    tl::expected<std::vector<uint8_t>, Error> encrypt(const PublicKey& public_key, std::span<const uint8_t> data) override {
        std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_ecc_encrypt(c_ctx_, public_key.impl(), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Check if algorithm can decrypt data with a given key.
    /// However, success result of decryption is not guaranteed.
    bool can_decrypt(const PrivateKey& private_key, std::size_t data_len) override {
        auto proxy_result = vscf_ecc_can_decrypt(c_ctx_, private_key.impl(), data_len);
        return proxy_result;
    }

    /// Calculate required buffer length to hold the decrypted data.
    std::size_t decrypted_len(const PrivateKey& private_key, std::size_t data_len) override {
        auto proxy_result = vscf_ecc_decrypted_len(c_ctx_, private_key.impl(), data_len);
        return proxy_result;
    }

    /// Decrypt given data.
    tl::expected<std::vector<uint8_t>, Error> decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) override {
        std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_ecc_decrypt(c_ctx_, private_key.impl(), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Check if algorithm can sign data digest with a given key.
    bool can_sign(const PrivateKey& private_key) override {
        auto proxy_result = vscf_ecc_can_sign(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    std::size_t signature_len(const PrivateKey& private_key) override {
        auto proxy_result = vscf_ecc_signature_len(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Sign data digest with a given private key.
    tl::expected<std::vector<uint8_t>, Error> sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) override {
        std::vector<uint8_t> signature(this->signature_len(private_key));
        vsc_buffer_t* signature_buf = vsc_buffer_new();
        vsc_buffer_use(signature_buf, signature.data(), signature.size());
        const vscf_status_t status = vscf_ecc_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), signature_buf);
        signature.resize(vsc_buffer_len(signature_buf));
        vsc_buffer_delete(signature_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return signature;
    }

    /// Check if algorithm can verify data digest with a given key.
    bool can_verify(const PublicKey& public_key) override {
        auto proxy_result = vscf_ecc_can_verify(c_ctx_, public_key.impl());
        return proxy_result;
    }

    /// Verify data digest with a given public key and signature.
    bool verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) override {
        auto proxy_result = vscf_ecc_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), vsc_data(signature.data(), signature.size()));
        return proxy_result;
    }

    /// Compute shared key for 2 asymmetric keys.
    /// Note, computed shared key can be used only within symmetric cryptography.
    tl::expected<std::vector<uint8_t>, Error> compute_shared_key(const PublicKey& public_key, const PrivateKey& private_key) override {
        std::vector<uint8_t> shared_key(this->shared_key_len(private_key));
        vsc_buffer_t* shared_key_buf = vsc_buffer_new();
        vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
        const vscf_status_t status = vscf_ecc_compute_shared_key(c_ctx_, public_key.impl(), private_key.impl(), shared_key_buf);
        shared_key.resize(vsc_buffer_len(shared_key_buf));
        vsc_buffer_delete(shared_key_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return shared_key;
    }

    /// Return number of bytes required to hold shared key.
    /// Expect Public Key or Private Key.
    std::size_t shared_key_len(const Key& key) override {
        auto proxy_result = vscf_ecc_shared_key_len(c_ctx_, key.impl());
        return proxy_result;
    }

    /// Return length in bytes required to hold encapsulated shared key.
    std::size_t kem_shared_key_len(const Key& key) override {
        auto proxy_result = vscf_ecc_kem_shared_key_len(c_ctx_, key.impl());
        return proxy_result;
    }

    /// Return length in bytes required to hold encapsulated key.
    std::size_t kem_encapsulated_key_len(const PublicKey& public_key) override {
        auto proxy_result = vscf_ecc_kem_encapsulated_key_len(c_ctx_, public_key.impl());
        return proxy_result;
    }

    /// Generate a shared key and a key encapsulated message.
    tl::expected<KemKemEncapsulateResult, Error> kem_encapsulate(const PublicKey& public_key) override {
        std::vector<uint8_t> shared_key(this->kem_shared_key_len(public_key));
        vsc_buffer_t* shared_key_buf = vsc_buffer_new();
        vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
        std::vector<uint8_t> encapsulated_key(this->kem_encapsulated_key_len(public_key));
        vsc_buffer_t* encapsulated_key_buf = vsc_buffer_new();
        vsc_buffer_use(encapsulated_key_buf, encapsulated_key.data(), encapsulated_key.size());
        const vscf_status_t status = vscf_ecc_kem_encapsulate(c_ctx_, public_key.impl(), shared_key_buf, encapsulated_key_buf);
        shared_key.resize(vsc_buffer_len(shared_key_buf));
        vsc_buffer_delete(shared_key_buf);
        encapsulated_key.resize(vsc_buffer_len(encapsulated_key_buf));
        vsc_buffer_delete(encapsulated_key_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return KemKemEncapsulateResult{.shared_key = std::move(shared_key), .encapsulated_key = std::move(encapsulated_key)};
    }

    /// Decapsulate the shared key.
    tl::expected<std::vector<uint8_t>, Error> kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) override {
        std::vector<uint8_t> shared_key(this->kem_shared_key_len(private_key));
        vsc_buffer_t* shared_key_buf = vsc_buffer_new();
        vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
        const vscf_status_t status = vscf_ecc_kem_decapsulate(c_ctx_, vsc_data(encapsulated_key.data(), encapsulated_key.size()), private_key.impl(), shared_key_buf);
        shared_key.resize(vsc_buffer_len(shared_key_buf));
        vsc_buffer_delete(shared_key_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return shared_key;
    }

private:
    vscf_ecc_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
