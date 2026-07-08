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

#include <virgil/crypto/foundation/compound_key_alg.hpp>
#include <virgil/crypto/foundation/vscf_compound_key_alg.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
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
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

CompoundKeyAlg::CompoundKeyAlg() : c_ctx_(vscf_compound_key_alg_new()) {}

CompoundKeyAlg::CompoundKeyAlg(vscf_compound_key_alg_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

CompoundKeyAlg::CompoundKeyAlg(const CompoundKeyAlg& other) : c_ctx_(vscf_compound_key_alg_shallow_copy(other.c_ctx_)) {}

CompoundKeyAlg::CompoundKeyAlg(CompoundKeyAlg&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

CompoundKeyAlg& CompoundKeyAlg::operator=(const CompoundKeyAlg& other) {
    if (this != &other) {
        vscf_compound_key_alg_delete(c_ctx_);
        c_ctx_ = vscf_compound_key_alg_shallow_copy(other.c_ctx_);
    }
    return *this;
}

CompoundKeyAlg& CompoundKeyAlg::operator=(CompoundKeyAlg&& other) noexcept {
    if (this != &other) {
        vscf_compound_key_alg_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

CompoundKeyAlg::~CompoundKeyAlg() { vscf_compound_key_alg_delete(c_ctx_); }

vscf_compound_key_alg_t* CompoundKeyAlg::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* CompoundKeyAlg::impl() const noexcept { return vscf_compound_key_alg_impl(c_ctx_); }

void CompoundKeyAlg::set_random(const Random& random) {
    vscf_compound_key_alg_release_random(c_ctx_);
    vscf_compound_key_alg_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> CompoundKeyAlg::setup_defaults() {
    const vscf_status_t status = vscf_compound_key_alg_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> CompoundKeyAlg::make_key(const PrivateKey& cipher_key, const PrivateKey& signer_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_make_key(c_ctx_, cipher_key.impl(), signer_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

AlgId CompoundKeyAlg::alg_id() const {
    auto proxy_result = vscf_compound_key_alg_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> CompoundKeyAlg::produce_alg_info() const {
    auto proxy_result = vscf_compound_key_alg_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> CompoundKeyAlg::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_compound_key_alg_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> CompoundKeyAlg::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> CompoundKeyAlg::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> CompoundKeyAlg::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> CompoundKeyAlg::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> CompoundKeyAlg::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_compound_key_alg_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

bool CompoundKeyAlg::can_encrypt(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_compound_key_alg_can_encrypt(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

std::size_t CompoundKeyAlg::encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_compound_key_alg_encrypted_len(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> CompoundKeyAlg::encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_compound_key_alg_encrypt(c_ctx_, public_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool CompoundKeyAlg::can_decrypt(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_compound_key_alg_can_decrypt(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

std::size_t CompoundKeyAlg::decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_compound_key_alg_decrypted_len(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> CompoundKeyAlg::decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_compound_key_alg_decrypt(c_ctx_, private_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool CompoundKeyAlg::can_sign(const PrivateKey& private_key) const {
    auto proxy_result = vscf_compound_key_alg_can_sign(c_ctx_, private_key.impl());
    return proxy_result;
}

std::size_t CompoundKeyAlg::signature_len(const PrivateKey& private_key) const {
    auto proxy_result = vscf_compound_key_alg_signature_len(c_ctx_, private_key.impl());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> CompoundKeyAlg::sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) const {
    std::vector<uint8_t> signature(this->signature_len(private_key));
    vsc_buffer_t signature_buf;
    vsc_buffer_init(&signature_buf);
    vsc_buffer_use(&signature_buf, signature.data(), signature.size());
    const vscf_status_t status = vscf_compound_key_alg_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), digest.empty() ? vsc_data_empty() : vsc_data(digest.data(), digest.size()), &signature_buf);
    signature.resize(vsc_buffer_len(&signature_buf));
    vsc_buffer_cleanup(&signature_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return signature;
}

bool CompoundKeyAlg::can_verify(const PublicKey& public_key) const {
    auto proxy_result = vscf_compound_key_alg_can_verify(c_ctx_, public_key.impl());
    return proxy_result;
}

bool CompoundKeyAlg::verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) const {
    auto proxy_result = vscf_compound_key_alg_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), digest.empty() ? vsc_data_empty() : vsc_data(digest.data(), digest.size()), signature.empty() ? vsc_data_empty() : vsc_data(signature.data(), signature.size()));
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
