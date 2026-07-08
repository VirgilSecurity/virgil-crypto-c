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

#include <virgil/crypto/foundation/ecc.hpp>
#include <virgil/crypto/foundation/vscf_ecc.h>
#include <virgil/crypto/foundation/vscf_impl.h>
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
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Ecc::Ecc() : c_ctx_(vscf_ecc_new()) {}

Ecc::Ecc(vscf_ecc_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Ecc::Ecc(const Ecc& other) : c_ctx_(vscf_ecc_shallow_copy(other.c_ctx_)) {}

Ecc::Ecc(Ecc&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Ecc& Ecc::operator=(const Ecc& other) {
    if (this != &other) {
        vscf_ecc_delete(c_ctx_);
        c_ctx_ = vscf_ecc_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Ecc& Ecc::operator=(Ecc&& other) noexcept {
    if (this != &other) {
        vscf_ecc_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Ecc::~Ecc() { vscf_ecc_delete(c_ctx_); }

vscf_ecc_t* Ecc::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Ecc::impl() const noexcept { return vscf_ecc_impl(c_ctx_); }

void Ecc::set_random(const Random& random) {
    vscf_ecc_release_random(c_ctx_);
    vscf_ecc_use_random(c_ctx_, random.impl());
}

void Ecc::set_ecies(const Ecies& ecies) {
    vscf_ecc_release_ecies(c_ctx_);
    vscf_ecc_use_ecies(c_ctx_, ecies.c_ctx());
}

tl::expected<void, Error> Ecc::setup_defaults() {
    const vscf_status_t status = vscf_ecc_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Ecc::generate_key(AlgId alg_id) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_generate_key(c_ctx_, static_cast<vscf_alg_id_t>(alg_id), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Ecc::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> Ecc::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> Ecc::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Ecc::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> Ecc::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_ecc_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

bool Ecc::can_encrypt(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecc_can_encrypt(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

std::size_t Ecc::encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecc_encrypted_len(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecc::encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_ecc_encrypt(c_ctx_, public_key.impl(), vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool Ecc::can_decrypt(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecc_can_decrypt(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

std::size_t Ecc::decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecc_decrypted_len(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecc::decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_ecc_decrypt(c_ctx_, private_key.impl(), vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool Ecc::can_sign(const PrivateKey& private_key) const {
    auto proxy_result = vscf_ecc_can_sign(c_ctx_, private_key.impl());
    return proxy_result;
}

std::size_t Ecc::signature_len(const PrivateKey& private_key) const {
    auto proxy_result = vscf_ecc_signature_len(c_ctx_, private_key.impl());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecc::sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) const {
    std::vector<uint8_t> signature(this->signature_len(private_key));
    vsc_buffer_t signature_buf;
    vsc_buffer_init(&signature_buf);
    vsc_buffer_use(&signature_buf, signature.data(), signature.size());
    const vscf_status_t status = vscf_ecc_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), &signature_buf);
    signature.resize(vsc_buffer_len(&signature_buf));
    vsc_buffer_cleanup(&signature_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return signature;
}

bool Ecc::can_verify(const PublicKey& public_key) const {
    auto proxy_result = vscf_ecc_can_verify(c_ctx_, public_key.impl());
    return proxy_result;
}

bool Ecc::verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) const {
    auto proxy_result = vscf_ecc_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), vsc_data(signature.data(), signature.size()));
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecc::compute_shared_key(const PublicKey& public_key, const PrivateKey& private_key) const {
    std::vector<uint8_t> shared_key(this->shared_key_len(private_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    const vscf_status_t status = vscf_ecc_compute_shared_key(c_ctx_, public_key.impl(), private_key.impl(), &shared_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return shared_key;
}

std::size_t Ecc::shared_key_len(const Key& key) const {
    auto proxy_result = vscf_ecc_shared_key_len(c_ctx_, key.impl());
    return proxy_result;
}

std::size_t Ecc::kem_shared_key_len(const Key& key) const {
    auto proxy_result = vscf_ecc_kem_shared_key_len(c_ctx_, key.impl());
    return proxy_result;
}

std::size_t Ecc::kem_encapsulated_key_len(const PublicKey& public_key) const {
    auto proxy_result = vscf_ecc_kem_encapsulated_key_len(c_ctx_, public_key.impl());
    return proxy_result;
}

tl::expected<KemKemEncapsulateResult, Error> Ecc::kem_encapsulate(const PublicKey& public_key) const {
    std::vector<uint8_t> shared_key(this->kem_shared_key_len(public_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    std::vector<uint8_t> encapsulated_key(this->kem_encapsulated_key_len(public_key));
    vsc_buffer_t encapsulated_key_buf;
    vsc_buffer_init(&encapsulated_key_buf);
    vsc_buffer_use(&encapsulated_key_buf, encapsulated_key.data(), encapsulated_key.size());
    const vscf_status_t status = vscf_ecc_kem_encapsulate(c_ctx_, public_key.impl(), &shared_key_buf, &encapsulated_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    encapsulated_key.resize(vsc_buffer_len(&encapsulated_key_buf));
    vsc_buffer_cleanup(&encapsulated_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return KemKemEncapsulateResult{.shared_key = std::move(shared_key), .encapsulated_key = std::move(encapsulated_key)};
}

tl::expected<std::vector<uint8_t>, Error> Ecc::kem_decapsulate(std::span<const uint8_t> encapsulated_key, const PrivateKey& private_key) const {
    std::vector<uint8_t> shared_key(this->kem_shared_key_len(private_key));
    vsc_buffer_t shared_key_buf;
    vsc_buffer_init(&shared_key_buf);
    vsc_buffer_use(&shared_key_buf, shared_key.data(), shared_key.size());
    const vscf_status_t status = vscf_ecc_kem_decapsulate(c_ctx_, vsc_data(encapsulated_key.data(), encapsulated_key.size()), private_key.impl(), &shared_key_buf);
    shared_key.resize(vsc_buffer_len(&shared_key_buf));
    vsc_buffer_cleanup(&shared_key_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return shared_key;
}

}  // namespace virgil::crypto::foundation
