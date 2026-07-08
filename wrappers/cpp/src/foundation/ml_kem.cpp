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

#include <virgil/crypto/foundation/ml_kem.hpp>
#include <virgil/crypto/foundation/vscf_ml_kem.h>
#include <virgil/crypto/foundation/vscf_impl.h>
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
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

MlKem::MlKem() : c_ctx_(vscf_ml_kem_new()) {}

MlKem::MlKem(vscf_ml_kem_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

MlKem::MlKem(const MlKem& other) : c_ctx_(vscf_ml_kem_shallow_copy(other.c_ctx_)) {}

MlKem::MlKem(MlKem&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

MlKem& MlKem::operator=(const MlKem& other) {
    if (this != &other) {
        vscf_ml_kem_delete(c_ctx_);
        c_ctx_ = vscf_ml_kem_shallow_copy(other.c_ctx_);
    }
    return *this;
}

MlKem& MlKem::operator=(MlKem&& other) noexcept {
    if (this != &other) {
        vscf_ml_kem_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

MlKem::~MlKem() { vscf_ml_kem_delete(c_ctx_); }

vscf_ml_kem_t* MlKem::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* MlKem::impl() const noexcept { return vscf_ml_kem_impl(c_ctx_); }

void MlKem::set_random(const Random& random) {
    vscf_ml_kem_release_random(c_ctx_);
    vscf_ml_kem_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> MlKem::setup_defaults() {
    const vscf_status_t status = vscf_ml_kem_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> MlKem::generate_key() const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_generate_key(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

AlgId MlKem::alg_id() const {
    auto proxy_result = vscf_ml_kem_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> MlKem::produce_alg_info() const {
    auto proxy_result = vscf_ml_kem_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> MlKem::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_ml_kem_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> MlKem::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> MlKem::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> MlKem::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> MlKem::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> MlKem::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ml_kem_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

std::size_t MlKem::kem_shared_key_len(const Key& key) const {
    auto proxy_result = vscf_ml_kem_kem_shared_key_len(c_ctx_, key.impl());
    return proxy_result;
}

std::size_t MlKem::kem_encapsulated_key_len(const PublicKey& public_key) const {
    auto proxy_result = vscf_ml_kem_kem_encapsulated_key_len(c_ctx_, public_key.impl());
    return proxy_result;
}

tl::expected<KemKemEncapsulateResult, Error> MlKem::kem_encapsulate(const PublicKey& public_key) const {
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

tl::expected<std::vector<uint8_t>, Error> MlKem::kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) const {
    std::vector<uint8_t> shared_key(this->kem_shared_key_len(private_key));
    vsc_buffer_t* shared_key_buf = vsc_buffer_new();
    vsc_buffer_use(shared_key_buf, shared_key.data(), shared_key.size());
    const vscf_status_t status = vscf_ml_kem_kem_decapsulate(c_ctx_, encapsulated_key.empty() ? vsc_data_empty() : vsc_data(encapsulated_key.data(), encapsulated_key.size()), private_key.impl(), shared_key_buf);
    shared_key.resize(vsc_buffer_len(shared_key_buf));
    vsc_buffer_delete(shared_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return shared_key;
}

}  // namespace virgil::crypto::foundation
