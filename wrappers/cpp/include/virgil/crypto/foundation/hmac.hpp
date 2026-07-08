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
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_hmac.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
class Hmac : virtual public Alg, virtual public Mac {
public:
    Hmac() : c_ctx_(vscf_hmac_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Hmac(vscf_hmac_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Hmac(const Hmac& other) : c_ctx_(vscf_hmac_shallow_copy(other.c_ctx_)) {}
    Hmac(Hmac&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Hmac& operator=(const Hmac& other) {
        if (this != &other) {
            vscf_hmac_delete(c_ctx_);
            c_ctx_ = vscf_hmac_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Hmac& operator=(Hmac&& other) noexcept {
        if (this != &other) {
            vscf_hmac_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Hmac() { vscf_hmac_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_hmac_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_hmac_impl(c_ctx_); }

    void set_hash(const Hash& hash) {
        vscf_hmac_release_hash(c_ctx_);
        vscf_hmac_use_hash(c_ctx_, hash.impl());
    }

    /// Provide algorithm identificator.
    AlgId alg_id() const override {
        auto proxy_result = vscf_hmac_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override {
        auto proxy_result = vscf_hmac_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_hmac_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Size of the digest (mac output) in bytes.
    std::size_t digest_len() override {
        auto proxy_result = vscf_hmac_digest_len(c_ctx_);
        return proxy_result;
    }

    /// Calculate MAC over given data.
    std::vector<uint8_t> mac(std::span<const uint8_t> key, std::span<const uint8_t> data) override {
        std::vector<uint8_t> mac(this->digest_len());
        vsc_buffer_t* mac_buf = vsc_buffer_new();
        vsc_buffer_use(mac_buf, mac.data(), mac.size());
        vscf_hmac_mac(c_ctx_, vsc_data(key.data(), key.size()), vsc_data(data.data(), data.size()), mac_buf);
        mac.resize(vsc_buffer_len(mac_buf));
        vsc_buffer_delete(mac_buf);
        return mac;
    }

    /// Start a new MAC.
    void start(std::span<const uint8_t> key) override {
        vscf_hmac_start(c_ctx_, vsc_data(key.data(), key.size()));
    }

    /// Add given data to the MAC.
    void update(std::span<const uint8_t> data) override {
        vscf_hmac_update(c_ctx_, vsc_data(data.data(), data.size()));
    }

    /// Accomplish MAC and return it's result (a message digest).
    std::vector<uint8_t> finish() override {
        std::vector<uint8_t> mac(this->digest_len());
        vsc_buffer_t* mac_buf = vsc_buffer_new();
        vsc_buffer_use(mac_buf, mac.data(), mac.size());
        vscf_hmac_finish(c_ctx_, mac_buf);
        mac.resize(vsc_buffer_len(mac_buf));
        vsc_buffer_delete(mac_buf);
        return mac;
    }

    /// Prepare to authenticate a new message with the same key
    /// as the previous MAC operation.
    void reset() override {
        vscf_hmac_reset(c_ctx_);
    }

private:
    vscf_hmac_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
