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

#include <virgil/crypto/foundation/pkcs5_pbkdf2.hpp>
#include <virgil/crypto/foundation/vscf_pkcs5_pbkdf2.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/salted_kdf.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Pkcs5Pbkdf2::Pkcs5Pbkdf2() : c_ctx_(vscf_pkcs5_pbkdf2_new()) {}

Pkcs5Pbkdf2::Pkcs5Pbkdf2(vscf_pkcs5_pbkdf2_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Pkcs5Pbkdf2::Pkcs5Pbkdf2(const Pkcs5Pbkdf2& other) : c_ctx_(vscf_pkcs5_pbkdf2_shallow_copy(other.c_ctx_)) {}

Pkcs5Pbkdf2::Pkcs5Pbkdf2(Pkcs5Pbkdf2&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Pkcs5Pbkdf2& Pkcs5Pbkdf2::operator=(const Pkcs5Pbkdf2& other) {
    if (this != &other) {
        vscf_pkcs5_pbkdf2_delete(c_ctx_);
        c_ctx_ = vscf_pkcs5_pbkdf2_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Pkcs5Pbkdf2& Pkcs5Pbkdf2::operator=(Pkcs5Pbkdf2&& other) noexcept {
    if (this != &other) {
        vscf_pkcs5_pbkdf2_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Pkcs5Pbkdf2::~Pkcs5Pbkdf2() { vscf_pkcs5_pbkdf2_delete(c_ctx_); }

vscf_pkcs5_pbkdf2_t* Pkcs5Pbkdf2::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Pkcs5Pbkdf2::impl() const noexcept { return vscf_pkcs5_pbkdf2_impl(c_ctx_); }

void Pkcs5Pbkdf2::set_hmac(const Mac& hmac) {
    vscf_pkcs5_pbkdf2_release_hmac(c_ctx_);
    vscf_pkcs5_pbkdf2_use_hmac(c_ctx_, hmac.impl());
}

void Pkcs5Pbkdf2::setup_defaults() {
    vscf_pkcs5_pbkdf2_setup_defaults(c_ctx_);
}

AlgId Pkcs5Pbkdf2::alg_id() const {
    auto proxy_result = vscf_pkcs5_pbkdf2_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Pkcs5Pbkdf2::produce_alg_info() const {
    auto proxy_result = vscf_pkcs5_pbkdf2_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Pkcs5Pbkdf2::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_pkcs5_pbkdf2_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::vector<uint8_t> Pkcs5Pbkdf2::derive(std::span<const uint8_t> data, std::size_t key_len) {
    std::vector<uint8_t> key(key_len);
    vsc_buffer_t* key_buf = vsc_buffer_new();
    vsc_buffer_use(key_buf, key.data(), key.size());
    vscf_pkcs5_pbkdf2_derive(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), key_len, key_buf);
    key.resize(vsc_buffer_len(key_buf));
    vsc_buffer_delete(key_buf);
    return key;
}

void Pkcs5Pbkdf2::reset(std::span<const uint8_t> salt, std::size_t iteration_count) {
    vscf_pkcs5_pbkdf2_reset(c_ctx_, salt.empty() ? vsc_data_empty() : vsc_data(salt.data(), salt.size()), iteration_count);
}

void Pkcs5Pbkdf2::set_info(std::span<const uint8_t> info) {
    vscf_pkcs5_pbkdf2_set_info(c_ctx_, info.empty() ? vsc_data_empty() : vsc_data(info.data(), info.size()));
}

}  // namespace virgil::crypto::foundation
