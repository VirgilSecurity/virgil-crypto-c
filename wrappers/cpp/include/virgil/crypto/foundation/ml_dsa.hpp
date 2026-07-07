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
#include <memory>
#include <virgil/crypto/foundation/vscf_ml_dsa.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Provide post-quantum signature based on ML-DSA-65 (mldsa-native).
/// For algorithm details check https://github.com/pq-code-package/mldsa-native
class MlDsa : virtual public Alg, virtual public KeyAlg, virtual public KeySigner {
public:
    MlDsa() : c_ctx_(vscf_ml_dsa_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MlDsa(vscf_ml_dsa_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MlDsa(const MlDsa& other) : c_ctx_(vscf_ml_dsa_shallow_copy(other.c_ctx_)) {}
    MlDsa(MlDsa&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MlDsa& operator=(const MlDsa& other) {
        if (this != &other) {
            vscf_ml_dsa_delete(c_ctx_);
            c_ctx_ = vscf_ml_dsa_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MlDsa& operator=(MlDsa&& other) noexcept {
        if (this != &other) {
            vscf_ml_dsa_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MlDsa() { vscf_ml_dsa_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_ml_dsa_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_ml_dsa_impl(c_ctx_); }

    static constexpr std::size_t SEED_LEN = 32;

    static constexpr std::size_t PUBLIC_KEY_LEN = 1952;

    static constexpr std::size_t SECRET_KEY_LEN = 4032;

    static constexpr std::size_t SIGNATURE_LEN = 3309;

    void set_random(const Random& random) {
        vscf_ml_dsa_release_random(c_ctx_);
        vscf_ml_dsa_use_random(c_ctx_, random.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_ml_dsa_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generate new private key.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_key() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_dsa_generate_key(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Provide algorithm identificator.
    AlgId alg_id() override {
        auto proxy_result = vscf_ml_dsa_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() override {
        auto proxy_result = vscf_ml_dsa_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_ml_dsa_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_ephemeral_key(const Key& key) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_dsa_generate_ephemeral_key(c_ctx_, key.impl(), &error);
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
        auto proxy_result = vscf_ml_dsa_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
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
        auto proxy_result = vscf_ml_dsa_export_public_key(c_ctx_, public_key.impl(), &error);
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
        auto proxy_result = vscf_ml_dsa_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
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
        auto proxy_result = vscf_ml_dsa_export_private_key(c_ctx_, private_key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPrivateKey(proxy_result);
    }

    /// Check if algorithm can sign data digest with a given key.
    bool can_sign(const PrivateKey& private_key) override {
        auto proxy_result = vscf_ml_dsa_can_sign(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    std::size_t signature_len(const PrivateKey& private_key) override {
        auto proxy_result = vscf_ml_dsa_signature_len(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Sign data digest with a given private key.
    tl::expected<std::vector<uint8_t>, Error> sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) override {
        std::vector<uint8_t> signature(this->signature_len(private_key));
        vsc_buffer_t* signature_buf = vsc_buffer_new();
        vsc_buffer_use(signature_buf, signature.data(), signature.size());
        const vscf_status_t status = vscf_ml_dsa_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), signature_buf);
        signature.resize(vsc_buffer_len(signature_buf));
        vsc_buffer_delete(signature_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return signature;
    }

    /// Check if algorithm can verify data digest with a given key.
    bool can_verify(const PublicKey& public_key) override {
        auto proxy_result = vscf_ml_dsa_can_verify(c_ctx_, public_key.impl());
        return proxy_result;
    }

    /// Verify data digest with a given public key and signature.
    bool verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) override {
        auto proxy_result = vscf_ml_dsa_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), vsc_data(signature.data(), signature.size()));
        return proxy_result;
    }

private:
    vscf_ml_dsa_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
