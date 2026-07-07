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
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Provide functionality for private key generation and importing that
/// relies on the software default implementations.
class KeyProvider {
public:
    KeyProvider() : c_ctx_(vscf_key_provider_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit KeyProvider(vscf_key_provider_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    KeyProvider(const KeyProvider& other) : c_ctx_(vscf_key_provider_shallow_copy(other.c_ctx_)) {}
    KeyProvider(KeyProvider&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    KeyProvider& operator=(const KeyProvider& other) {
        if (this != &other) {
            vscf_key_provider_delete(c_ctx_);
            c_ctx_ = vscf_key_provider_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    KeyProvider& operator=(KeyProvider&& other) noexcept {
        if (this != &other) {
            vscf_key_provider_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~KeyProvider() { vscf_key_provider_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_key_provider_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const Random& random) {
        vscf_key_provider_release_random(c_ctx_);
        vscf_key_provider_use_random(c_ctx_, random.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_key_provider_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Setup parameters that is used during RSA key generation.
    void set_rsa_params(std::size_t bitlen) {
        vscf_key_provider_set_rsa_params(c_ctx_, bitlen);
    }

    /// Generate new private key with a given algorithm.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_private_key(AlgId alg_id) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_generate_private_key(c_ctx_, static_cast<vscf_alg_id_t>(alg_id), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

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
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_post_quantum_private_key() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_generate_post_quantum_private_key(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Generate new compound private key with given algorithms.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_compound_private_key(AlgId cipher_alg_id, AlgId signer_alg_id) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_generate_compound_private_key(c_ctx_, static_cast<vscf_alg_id_t>(cipher_alg_id), static_cast<vscf_alg_id_t>(signer_alg_id), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Generate new hybrid private key with given algorithms.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_hybrid_private_key(AlgId first_key_alg_id, AlgId second_key_alg_id) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_generate_hybrid_private_key(c_ctx_, static_cast<vscf_alg_id_t>(first_key_alg_id), static_cast<vscf_alg_id_t>(second_key_alg_id), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Generate new compound private key with nested hybrid private keys.
    ///
    /// Note, second key algorithm identifiers can be NONE, in this case,
    /// a regular key will be crated instead of a hybrid key.
    tl::expected<std::unique_ptr<PrivateKey>, Error> generate_compound_hybrid_private_key(AlgId cipher_first_key_alg_id, AlgId cipher_second_key_alg_id, AlgId signer_first_key_alg_id, AlgId signer_second_key_alg_id) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_generate_compound_hybrid_private_key(c_ctx_, static_cast<vscf_alg_id_t>(cipher_first_key_alg_id), static_cast<vscf_alg_id_t>(cipher_second_key_alg_id), static_cast<vscf_alg_id_t>(signer_first_key_alg_id), static_cast<vscf_alg_id_t>(signer_second_key_alg_id), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Import private key from the PKCS#8 format.
    tl::expected<std::unique_ptr<PrivateKey>, Error> import_private_key(std::span<const uint8_t> key_data) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_import_private_key(c_ctx_, vsc_data(key_data.data(), key_data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_private_key(proxy_result);
    }

    /// Import public key from the PKCS#8 format.
    tl::expected<std::unique_ptr<PublicKey>, Error> import_public_key(std::span<const uint8_t> key_data) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_provider_import_public_key(c_ctx_, vsc_data(key_data.data(), key_data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_public_key(proxy_result);
    }

    /// Calculate buffer size enough to hold exported public key.
    ///
    /// Precondition: public key must be exportable.
    std::size_t exported_public_key_len(const PublicKey& public_key) {
        auto proxy_result = vscf_key_provider_exported_public_key_len(c_ctx_, public_key.impl());
        return proxy_result;
    }

    /// Export given public key to the PKCS#8 DER format.
    ///
    /// Precondition: public key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> export_public_key(const PublicKey& public_key) {
        std::vector<uint8_t> out(this->exported_public_key_len(public_key));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_key_provider_export_public_key(c_ctx_, public_key.impl(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Calculate buffer size enough to hold exported private key.
    ///
    /// Precondition: private key must be exportable.
    std::size_t exported_private_key_len(const PrivateKey& private_key) {
        auto proxy_result = vscf_key_provider_exported_private_key_len(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Export given private key to the PKCS#8 or SEC1 DER format.
    ///
    /// Precondition: private key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> export_private_key(const PrivateKey& private_key) {
        std::vector<uint8_t> out(this->exported_private_key_len(private_key));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_key_provider_export_private_key(c_ctx_, private_key.impl(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_key_provider_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
