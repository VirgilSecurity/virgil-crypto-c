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

#include <virgil/crypto/foundation/aes256_kw.hpp>
#include <virgil/crypto/foundation/vscf_aes256_kw.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_wrap.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Aes256Kw::Aes256Kw() : c_ctx_(vscf_aes256_kw_new()) {}

Aes256Kw::Aes256Kw(vscf_aes256_kw_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Aes256Kw::Aes256Kw(const Aes256Kw& other) : c_ctx_(vscf_aes256_kw_shallow_copy(other.c_ctx_)) {}

Aes256Kw::Aes256Kw(Aes256Kw&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Aes256Kw& Aes256Kw::operator=(const Aes256Kw& other) {
    if (this != &other) {
        vscf_aes256_kw_delete(c_ctx_);
        c_ctx_ = vscf_aes256_kw_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Aes256Kw& Aes256Kw::operator=(Aes256Kw&& other) noexcept {
    if (this != &other) {
        vscf_aes256_kw_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Aes256Kw::~Aes256Kw() { vscf_aes256_kw_delete(c_ctx_); }

vscf_aes256_kw_t* Aes256Kw::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Aes256Kw::impl() const noexcept { return vscf_aes256_kw_impl(c_ctx_); }

AlgId Aes256Kw::alg_id() const {
    auto proxy_result = vscf_aes256_kw_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Aes256Kw::produce_alg_info() const {
    auto proxy_result = vscf_aes256_kw_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Aes256Kw::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_aes256_kw_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t Aes256Kw::wrapped_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_kw_wrapped_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Kw::unwrapped_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_kw_unwrapped_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Kw::wrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->wrapped_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_kw_wrap(c_ctx_, kek.empty() ? vsc_data_empty() : vsc_data(kek.data(), kek.size()), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Kw::unwrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->unwrapped_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_kw_unwrap(c_ctx_, kek.empty() ? vsc_data_empty() : vsc_data(kek.data(), kek.size()), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
