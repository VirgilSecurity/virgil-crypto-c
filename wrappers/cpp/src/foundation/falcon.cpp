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

#include <virgil/crypto/foundation/falcon.hpp>
#include <virgil/crypto/foundation/vscf_falcon.h>
#include <virgil/crypto/foundation/vscf_impl.h>
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
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Falcon::Falcon() : c_ctx_(vscf_falcon_new()) {}

Falcon::Falcon(vscf_falcon_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Falcon::Falcon(const Falcon& other) : c_ctx_(vscf_falcon_shallow_copy(other.c_ctx_)) {}

Falcon::Falcon(Falcon&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Falcon& Falcon::operator=(const Falcon& other) {
    if (this != &other) {
        vscf_falcon_delete(c_ctx_);
        c_ctx_ = vscf_falcon_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Falcon& Falcon::operator=(Falcon&& other) noexcept {
    if (this != &other) {
        vscf_falcon_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Falcon::~Falcon() { vscf_falcon_delete(c_ctx_); }

vscf_falcon_t* Falcon::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Falcon::impl() const noexcept { return vscf_falcon_impl(c_ctx_); }

void Falcon::set_random(const Random& random) {
    vscf_falcon_release_random(c_ctx_);
    vscf_falcon_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> Falcon::setup_defaults() {
    const vscf_status_t status = vscf_falcon_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Falcon::generate_key() const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_generate_key(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

AlgId Falcon::alg_id() const {
    auto proxy_result = vscf_falcon_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Falcon::produce_alg_info() const {
    auto proxy_result = vscf_falcon_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Falcon::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_falcon_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Falcon::generate_ephemeral_key(const Key& key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_generate_ephemeral_key(c_ctx_, key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<std::unique_ptr<PublicKey>, Error> Falcon::import_public_key(const RawPublicKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_import_public_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_public_key(proxy_result);
}

tl::expected<RawPublicKey, Error> Falcon::export_public_key(const PublicKey& public_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_export_public_key(c_ctx_, public_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<std::unique_ptr<PrivateKey>, Error> Falcon::import_private_key(const RawPrivateKey& raw_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_import_private_key(c_ctx_, raw_key.c_ctx(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return FoundationImplementation::wrap_private_key(proxy_result);
}

tl::expected<RawPrivateKey, Error> Falcon::export_private_key(const PrivateKey& private_key) const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_falcon_export_private_key(c_ctx_, private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

bool Falcon::can_sign(const PrivateKey& private_key) const {
    auto proxy_result = vscf_falcon_can_sign(c_ctx_, private_key.impl());
    return proxy_result;
}

std::size_t Falcon::signature_len(const PrivateKey& private_key) const {
    auto proxy_result = vscf_falcon_signature_len(c_ctx_, private_key.impl());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Falcon::sign_hash(const PrivateKey& private_key, AlgId hash_id, std::span<const uint8_t> digest) const {
    std::vector<uint8_t> signature(this->signature_len(private_key));
    vsc_buffer_t signature_buf;
    vsc_buffer_init(&signature_buf);
    vsc_buffer_use(&signature_buf, signature.data(), signature.size());
    const vscf_status_t status = vscf_falcon_sign_hash(c_ctx_, private_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), &signature_buf);
    signature.resize(vsc_buffer_len(&signature_buf));
    vsc_buffer_cleanup(&signature_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return signature;
}

bool Falcon::can_verify(const PublicKey& public_key) const {
    auto proxy_result = vscf_falcon_can_verify(c_ctx_, public_key.impl());
    return proxy_result;
}

bool Falcon::verify_hash(const PublicKey& public_key, AlgId hash_id, std::span<const uint8_t> digest, std::span<const uint8_t> signature) const {
    auto proxy_result = vscf_falcon_verify_hash(c_ctx_, public_key.impl(), static_cast<vscf_alg_id_t>(hash_id), vsc_data(digest.data(), digest.size()), vsc_data(signature.data(), signature.size()));
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
