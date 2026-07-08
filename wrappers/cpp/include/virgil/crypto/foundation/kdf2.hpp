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
#include <virgil/crypto/foundation/vscf_kdf2.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Virgil Security implementation of the KDF2 (ISO-18033-2) algorithm.
class Kdf2 : virtual public Alg, virtual public Kdf {
public:
    Kdf2() : c_ctx_(vscf_kdf2_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Kdf2(vscf_kdf2_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Kdf2(const Kdf2& other) : c_ctx_(vscf_kdf2_shallow_copy(other.c_ctx_)) {}
    Kdf2(Kdf2&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Kdf2& operator=(const Kdf2& other) {
        if (this != &other) {
            vscf_kdf2_delete(c_ctx_);
            c_ctx_ = vscf_kdf2_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Kdf2& operator=(Kdf2&& other) noexcept {
        if (this != &other) {
            vscf_kdf2_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Kdf2() { vscf_kdf2_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_kdf2_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_kdf2_impl(c_ctx_); }

    void set_hash(const Hash& hash) {
        vscf_kdf2_release_hash(c_ctx_);
        vscf_kdf2_use_hash(c_ctx_, hash.impl());
    }

    /// Provide algorithm identificator.
    AlgId alg_id() const override {
        auto proxy_result = vscf_kdf2_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override {
        auto proxy_result = vscf_kdf2_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_kdf2_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Derive key of the requested length from the given data.
    std::vector<uint8_t> derive(std::span<const uint8_t> data, std::size_t key_len) override {
        std::vector<uint8_t> key(key_len);
        vsc_buffer_t* key_buf = vsc_buffer_new();
        vsc_buffer_use(key_buf, key.data(), key.size());
        vscf_kdf2_derive(c_ctx_, vsc_data(data.data(), data.size()), key_len, key_buf);
        key.resize(vsc_buffer_len(key_buf));
        vsc_buffer_delete(key_buf);
        return key;
    }

private:
    vscf_kdf2_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
