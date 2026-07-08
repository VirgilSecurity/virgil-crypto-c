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

#include <virgil/crypto/foundation/rsa.hpp>
#include <virgil/crypto/foundation/vscf_rsa.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Rsa::Rsa() : c_ctx_(vscf_rsa_new()) {}

Rsa::Rsa(vscf_rsa_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Rsa::Rsa(const Rsa& other) : c_ctx_(vscf_rsa_shallow_copy(other.c_ctx_)) {}

Rsa::Rsa(Rsa&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Rsa& Rsa::operator=(const Rsa& other) {
    if (this != &other) {
        vscf_rsa_delete(c_ctx_);
        c_ctx_ = vscf_rsa_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Rsa& Rsa::operator=(Rsa&& other) noexcept {
    if (this != &other) {
        vscf_rsa_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Rsa::~Rsa() { vscf_rsa_delete(c_ctx_); }

vscf_rsa_t* Rsa::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Rsa::impl() const noexcept { return vscf_rsa_impl(c_ctx_); }

void Rsa::set_random(const Random& random) {
    vscf_rsa_release_random(c_ctx_);
    vscf_rsa_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> Rsa::setup_defaults() {
    const vscf_status_t status = vscf_rsa_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Rsa::generate_key(std::size_t bitlen) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_generate_key(c_ctx_, bitlen, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Rsa::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> Rsa::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> Rsa::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Rsa::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> Rsa::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_rsa_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

bool Rsa::can_encrypt(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_rsa_can_encrypt(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

std::size_t Rsa::encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_rsa_encrypted_len(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Rsa::encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_rsa_encrypt(c_ctx_, public_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool Rsa::can_decrypt(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_rsa_can_decrypt(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

std::size_t Rsa::decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_rsa_decrypted_len(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Rsa::decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_rsa_decrypt(c_ctx_, private_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool Rsa::can_sign(const PrivateKey& private_key) const {
    auto proxy_result = vscf_rsa_can_sign(c_ctx_, private_key.impl());
    return proxy_result;
}

std::size_t Rsa::signature_len(const PrivateKey& private_key) const {
    auto proxy_result = vscf_rsa_signature_len(c_ctx_, private_key.impl());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Rsa::sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) const {
    std::vector<uint8_t> signature(this->signature_len(private_key));
    vsc_buffer_t* signature_buf = vsc_buffer_new();
    vsc_buffer_use(signature_buf, signature.data(), signature.size());
    const vscf_status_t status = vscf_rsa_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), digest.empty() ? vsc_data_empty() : vsc_data(digest.data(), digest.size()), signature_buf);
    signature.resize(vsc_buffer_len(signature_buf));
    vsc_buffer_delete(signature_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return signature;
}

bool Rsa::can_verify(const PublicKey& public_key) const {
    auto proxy_result = vscf_rsa_can_verify(c_ctx_, public_key.impl());
    return proxy_result;
}

bool Rsa::verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) const {
    auto proxy_result = vscf_rsa_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), digest.empty() ? vsc_data_empty() : vsc_data(digest.data(), digest.size()), signature.empty() ? vsc_data_empty() : vsc_data(signature.data(), signature.size()));
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
