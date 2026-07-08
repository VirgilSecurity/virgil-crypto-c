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
#include <virgil/crypto/foundation/vscf_ml_kem.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/kem.hpp>
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

/// Provide post-quantum KEM based on ML-KEM-768 (mlkem-native).
/// For algorithm details check https://github.com/pq-code-package/mlkem-native
class MlKem : virtual public Alg, virtual public KeyAlg, virtual public Kem {
public:
    MlKem() : c_ctx_(vscf_ml_kem_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MlKem(vscf_ml_kem_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MlKem(const MlKem& other) : c_ctx_(vscf_ml_kem_shallow_copy(other.c_ctx_)) {}
    MlKem(MlKem&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MlKem& operator=(const MlKem& other) {
        if (this != &other) {
            vscf_ml_kem_delete(c_ctx_);
            c_ctx_ = vscf_ml_kem_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MlKem& operator=(MlKem&& other) noexcept {
        if (this != &other) {
            vscf_ml_kem_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MlKem() { vscf_ml_kem_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_ml_kem_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_ml_kem_impl(c_ctx_); }

    static constexpr std::size_t SEED_LEN = 64;

    static constexpr std::size_t ENC_SEED_LEN = 32;

    static constexpr std::size_t PUBLIC_KEY_LEN = 1184;

    static constexpr std::size_t SECRET_KEY_LEN = 2400;

    static constexpr std::size_t CIPHERTEXT_LEN = 1088;

    static constexpr std::size_t SHARED_KEY_LEN = 32;

    void set_random(const Random& random) {
        vscf_ml_kem_release_random(c_ctx_);
        vscf_ml_kem_use_random(c_ctx_, random.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_ml_kem_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generate new private key.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_key() const {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_generate_key(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Provide algorithm identificator.
    AlgId alg_id() const override {
        auto proxy_result = vscf_ml_kem_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override {
        auto proxy_result = vscf_ml_kem_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_ml_kem_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_ephemeral_key(const Key& key) const override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_generate_ephemeral_key(c_ctx_, key.impl(), &error);
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
    tl::expected<std::unique_ptr<PublicKey>, Error> import_public_key(const RawPublicKey& raw_key) const override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
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
    tl::expected<RawPublicKey, Error> export_public_key(const PublicKey& public_key) const override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_export_public_key(c_ctx_, public_key.impl(), &error);
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
    tl::expected<std::unique_ptr<PrivateKey>, Error> import_private_key(const RawPrivateKey& raw_key) const override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
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
    tl::expected<RawPrivateKey, Error> export_private_key(const PrivateKey& private_key) const override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_ml_kem_export_private_key(c_ctx_, private_key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPrivateKey(proxy_result);
    }

    /// Return length in bytes required to hold encapsulated shared key.
    std::size_t kem_shared_key_len(const Key& key) const override {
        auto proxy_result = vscf_ml_kem_kem_shared_key_len(c_ctx_, key.impl());
        return proxy_result;
    }

    /// Return length in bytes required to hold encapsulated key.
    std::size_t kem_encapsulated_key_len(const PublicKey& public_key) const override {
        auto proxy_result = vscf_ml_kem_kem_encapsulated_key_len(c_ctx_, public_key.impl());
        return proxy_result;
    }

    /// Generate a shared key and a key encapsulated message.
    tl::expected<KemKemEncapsulateResult, Error> kem_encapsulate(const PublicKey& public_key) const override {
        std::vector<uint8_t> shared_key(this->kem_shared_key_len(public_key));
        vsc_buffer_t* shared_key_buf = vsc_buffer_new();
        vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
        std::vector<uint8_t> encapsulated_key(this->kem_encapsulated_key_len(public_key));
        vsc_buffer_t* encapsulated_key_buf = vsc_buffer_new();
        vsc_buffer_use(encapsulated_key_buf, encapsulated_key.data(), encapsulated_key.size());
        const vscf_status_t status = vscf_ml_kem_kem_encapsulate(c_ctx_, public_key.impl(), shared_key_buf, encapsulated_key_buf);
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
    tl::expected<std::vector<uint8_t>, Error> kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) const override {
        std::vector<uint8_t> shared_key(this->kem_shared_key_len(private_key));
        vsc_buffer_t* shared_key_buf = vsc_buffer_new();
        vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
        const vscf_status_t status = vscf_ml_kem_kem_decapsulate(c_ctx_, vsc_data(encapsulated_key.data(), encapsulated_key.size()), private_key.impl(), shared_key_buf);
        shared_key.resize(vsc_buffer_len(shared_key_buf));
        vsc_buffer_delete(shared_key_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return shared_key;
    }

private:
    vscf_ml_kem_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
