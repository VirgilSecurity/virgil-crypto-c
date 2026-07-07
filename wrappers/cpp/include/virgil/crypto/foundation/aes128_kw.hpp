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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_aes128_kw.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/key_wrap.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Implementation of AES-128 Key Wrap algorithm (RFC 3394).
class Aes128Kw : virtual public Alg, virtual public KeyWrap {
public:
    Aes128Kw() : c_ctx_(vscf_aes128_kw_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Aes128Kw(vscf_aes128_kw_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Aes128Kw(const Aes128Kw& other) : c_ctx_(vscf_aes128_kw_shallow_copy(other.c_ctx_)) {}
    Aes128Kw(Aes128Kw&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Aes128Kw& operator=(const Aes128Kw& other) {
        if (this != &other) {
            vscf_aes128_kw_delete(c_ctx_);
            c_ctx_ = vscf_aes128_kw_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Aes128Kw& operator=(Aes128Kw&& other) noexcept {
        if (this != &other) {
            vscf_aes128_kw_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Aes128Kw() { vscf_aes128_kw_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_aes128_kw_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_aes128_kw_impl(c_ctx_); }

    /// Provide algorithm identificator.
    AlgId alg_id() override {
        auto proxy_result = vscf_aes128_kw_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() override {
        auto proxy_result = vscf_aes128_kw_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_aes128_kw_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Return buffer length required to hold a wrapped key for the given plain key length.
    std::size_t wrapped_len(std::size_t data_len) override {
        auto proxy_result = vscf_aes128_kw_wrapped_len(c_ctx_, data_len);
        return proxy_result;
    }

    /// Return buffer length required to hold an unwrapped key for the given wrapped key length.
    std::size_t unwrapped_len(std::size_t data_len) override {
        auto proxy_result = vscf_aes128_kw_unwrapped_len(c_ctx_, data_len);
        return proxy_result;
    }

    /// Wrap given key data using the Key Encryption Key (KEK).
    tl::expected<std::vector<uint8_t>, Error> wrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) override {
        std::vector<uint8_t> out(this->wrapped_len(data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_aes128_kw_wrap(c_ctx_, vsc_data(kek.data(), kek.size()), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Unwrap given key data using the Key Encryption Key (KEK).
    tl::expected<std::vector<uint8_t>, Error> unwrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) override {
        std::vector<uint8_t> out(this->unwrapped_len(data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_aes128_kw_unwrap(c_ctx_, vsc_data(kek.data(), kek.size()), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_aes128_kw_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
