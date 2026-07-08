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

#include <virgil/crypto/foundation/shamir.hpp>
#include <virgil/crypto/foundation/vscf_shamir.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Shamir::Shamir() : c_ctx_(vscf_shamir_new()) {}

Shamir::Shamir(vscf_shamir_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Shamir::Shamir(const Shamir& other) : c_ctx_(vscf_shamir_shallow_copy(other.c_ctx_)) {}

Shamir::Shamir(Shamir&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Shamir& Shamir::operator=(const Shamir& other) {
    if (this != &other) {
        vscf_shamir_delete(c_ctx_);
        c_ctx_ = vscf_shamir_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Shamir& Shamir::operator=(Shamir&& other) noexcept {
    if (this != &other) {
        vscf_shamir_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Shamir::~Shamir() { vscf_shamir_delete(c_ctx_); }

vscf_shamir_t* Shamir::c_ctx() const noexcept { return c_ctx_; }

void Shamir::set_random(const Random& random) {
    vscf_shamir_release_random(c_ctx_);
    vscf_shamir_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> Shamir::setup_defaults() {
    const vscf_status_t status = vscf_shamir_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t Shamir::share_len(std::size_t secret_len) const {
    auto proxy_result = vscf_shamir_share_len(c_ctx_, secret_len);
    return proxy_result;
}

std::size_t Shamir::shares_len(std::size_t secret_len, std::size_t share_count) const {
    auto proxy_result = vscf_shamir_shares_len(c_ctx_, secret_len, share_count);
    return proxy_result;
}

std::size_t Shamir::recovered_secret_len(std::size_t shares_len, std::size_t share_count) const {
    auto proxy_result = vscf_shamir_recovered_secret_len(c_ctx_, shares_len, share_count);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Shamir::split(std::span<const uint8_t> secret, std::size_t threshold, std::size_t share_count) {
    std::vector<uint8_t> out(this->shares_len(secret.size(), share_count));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_shamir_split(c_ctx_, secret.empty() ? vsc_data_empty() : vsc_data(secret.data(), secret.size()), threshold, share_count, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> Shamir::combine(std::span<const uint8_t> shares, std::size_t share_count) const {
    std::vector<uint8_t> secret(this->recovered_secret_len(shares.size(), share_count));
    vsc_buffer_t secret_buf;
    vsc_buffer_init(&secret_buf);
    vsc_buffer_use(&secret_buf, secret.data(), secret.size());
    const vscf_status_t status = vscf_shamir_combine(c_ctx_, shares.empty() ? vsc_data_empty() : vsc_data(shares.data(), shares.size()), share_count, &secret_buf);
    secret.resize(vsc_buffer_len(&secret_buf));
    vsc_buffer_cleanup(&secret_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return secret;
}

}  // namespace virgil::crypto::foundation
