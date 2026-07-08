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

#include <virgil/crypto/foundation/curve25519.hpp>
#include <virgil/crypto/foundation/vscf_curve25519.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/compute_shared_key.hpp>
#include <virgil/crypto/foundation/kem.hpp>
#include <virgil/crypto/foundation/ecies.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Curve25519::Curve25519() : c_ctx_(vscf_curve25519_new()) {}

Curve25519::Curve25519(vscf_curve25519_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Curve25519::Curve25519(const Curve25519& other) : c_ctx_(vscf_curve25519_shallow_copy(other.c_ctx_)) {}

Curve25519::Curve25519(Curve25519&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Curve25519& Curve25519::operator=(const Curve25519& other) {
    if (this != &other) {
        vscf_curve25519_delete(c_ctx_);
        c_ctx_ = vscf_curve25519_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Curve25519& Curve25519::operator=(Curve25519&& other) noexcept {
    if (this != &other) {
        vscf_curve25519_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Curve25519::~Curve25519() { vscf_curve25519_delete(c_ctx_); }

vscf_curve25519_t* Curve25519::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Curve25519::impl() const noexcept { return vscf_curve25519_impl(c_ctx_); }

void Curve25519::set_random(const Random& random) {
    vscf_curve25519_release_random(c_ctx_);
    vscf_curve25519_use_random(c_ctx_, random.impl());
}

void Curve25519::set_ecies(const Ecies& ecies) {
    vscf_curve25519_release_ecies(c_ctx_);
    vscf_curve25519_use_ecies(c_ctx_, ecies.c_ctx());
}

tl::expected<void, Error> Curve25519::setup_defaults() {
    const vscf_status_t status = vscf_curve25519_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Curve25519::generate_key() const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_generate_key(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Curve25519::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> Curve25519::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> Curve25519::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Curve25519::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> Curve25519::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_curve25519_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

bool Curve25519::can_encrypt(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_curve25519_can_encrypt(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

std::size_t Curve25519::encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_curve25519_encrypted_len(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Curve25519::encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_curve25519_encrypt(c_ctx_, public_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool Curve25519::can_decrypt(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_curve25519_can_decrypt(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

std::size_t Curve25519::decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_curve25519_decrypted_len(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Curve25519::decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_curve25519_decrypt(c_ctx_, private_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> Curve25519::compute_shared_key(const PublicKey& public_key, const PrivateKey& private_key) const {
    std::vector<uint8_t> shared_key(this->shared_key_len(private_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    const vscf_status_t status = vscf_curve25519_compute_shared_key(c_ctx_, public_key.impl(), private_key.impl(), &shared_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return shared_key;
}

std::size_t Curve25519::shared_key_len(const Key& key) const {
    auto proxy_result = vscf_curve25519_shared_key_len(c_ctx_, key.impl());
    return proxy_result;
}

std::size_t Curve25519::kem_shared_key_len(const Key& key) const {
    auto proxy_result = vscf_curve25519_kem_shared_key_len(c_ctx_, key.impl());
    return proxy_result;
}

std::size_t Curve25519::kem_encapsulated_key_len(const PublicKey& public_key) const {
    auto proxy_result = vscf_curve25519_kem_encapsulated_key_len(c_ctx_, public_key.impl());
    return proxy_result;
}

tl::expected<KemKemEncapsulateResult, Error> Curve25519::kem_encapsulate(const PublicKey& public_key) const {
    std::vector<uint8_t> shared_key(this->kem_shared_key_len(public_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    std::vector<uint8_t> encapsulated_key(this->kem_encapsulated_key_len(public_key));
    vsc_buffer_t encapsulated_key_buf;
    vsc_buffer_init(&encapsulated_key_buf);
    vsc_buffer_use(&encapsulated_key_buf, encapsulated_key.data(), encapsulated_key.size());
    const vscf_status_t status = vscf_curve25519_kem_encapsulate(c_ctx_, public_key.impl(), &shared_key_buf, &encapsulated_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    encapsulated_key.resize(vsc_buffer_len(&encapsulated_key_buf));
    vsc_buffer_cleanup(&encapsulated_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return KemKemEncapsulateResult{.shared_key = std::move(shared_key), .encapsulated_key = std::move(encapsulated_key)};
}

tl::expected<std::vector<uint8_t>, Error> Curve25519::kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) const {
    std::vector<uint8_t> shared_key(this->kem_shared_key_len(private_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    const vscf_status_t status = vscf_curve25519_kem_decapsulate(c_ctx_, encapsulated_key.empty() ? vsc_data_empty() : vsc_data(encapsulated_key.data(), encapsulated_key.size()), private_key.impl(), &shared_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return shared_key;
}

}  // namespace virgil::crypto::foundation
