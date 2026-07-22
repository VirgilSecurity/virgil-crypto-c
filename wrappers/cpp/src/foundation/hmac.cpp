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

#include <virgil/crypto/foundation/hmac.hpp>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Hmac::Hmac() : c_ctx_(vscf_hmac_new()) {}

Hmac::Hmac(vscf_hmac_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Hmac::Hmac(const Hmac& other) : c_ctx_(vscf_hmac_shallow_copy(other.c_ctx_)) {}

Hmac::Hmac(Hmac&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Hmac& Hmac::operator=(const Hmac& other) {
    if (this != &other) {
        vscf_hmac_delete(c_ctx_);
        c_ctx_ = vscf_hmac_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Hmac& Hmac::operator=(Hmac&& other) noexcept {
    if (this != &other) {
        vscf_hmac_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Hmac::~Hmac() { vscf_hmac_delete(c_ctx_); }

vscf_hmac_t* Hmac::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Hmac::impl() const noexcept { return vscf_hmac_impl(c_ctx_); }

void Hmac::set_hash(const Hash& hash) {
    vscf_hmac_release_hash(c_ctx_);
    vscf_hmac_use_hash(c_ctx_, hash.impl());
}

AlgId Hmac::alg_id() const {
    auto proxy_result = vscf_hmac_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Hmac::produce_alg_info() const {
    auto proxy_result = vscf_hmac_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Hmac::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_hmac_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t Hmac::digest_len() {
    auto proxy_result = vscf_hmac_digest_len(c_ctx_);
    return proxy_result;
}

std::vector<uint8_t> Hmac::mac(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    std::vector<uint8_t> mac(this->digest_len());
    vsc_buffer_t* mac_buf = vsc_buffer_new();
    vsc_buffer_use(mac_buf, mac.data(), mac.size());
    vscf_hmac_mac(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), mac_buf);
    mac.resize(vsc_buffer_len(mac_buf));
    vsc_buffer_delete(mac_buf);
    return mac;
}

void Hmac::start(std::span<const uint8_t> key) {
    vscf_hmac_start(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()));
}

void Hmac::update(std::span<const uint8_t> data) {
    vscf_hmac_update(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()));
}

std::vector<uint8_t> Hmac::finish() {
    std::vector<uint8_t> mac(this->digest_len());
    vsc_buffer_t* mac_buf = vsc_buffer_new();
    vsc_buffer_use(mac_buf, mac.data(), mac.size());
    vscf_hmac_finish(c_ctx_, mac_buf);
    mac.resize(vsc_buffer_len(mac_buf));
    vsc_buffer_delete(mac_buf);
    return mac;
}

void Hmac::reset() {
    vscf_hmac_reset(c_ctx_);
}

}  // namespace virgil::crypto::foundation
