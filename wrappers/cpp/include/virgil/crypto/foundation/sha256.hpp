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
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// This is MbedTLS implementation of SHA256.
class Sha256 : virtual public Alg, virtual public Hash {
public:
    Sha256() : c_ctx_(vscf_sha256_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Sha256(vscf_sha256_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Sha256(const Sha256& other) : c_ctx_(vscf_sha256_shallow_copy(other.c_ctx_)) {}
    Sha256(Sha256&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Sha256& operator=(const Sha256& other) {
        if (this != &other) {
            vscf_sha256_delete(c_ctx_);
            c_ctx_ = vscf_sha256_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Sha256& operator=(Sha256&& other) noexcept {
        if (this != &other) {
            vscf_sha256_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Sha256() { vscf_sha256_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_sha256_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_sha256_impl(c_ctx_); }

    static constexpr std::size_t DIGEST_LEN = 32;

    static constexpr std::size_t BLOCK_LEN = 64;

    /// Provide algorithm identificator.
    AlgId alg_id() override {
        auto proxy_result = vscf_sha256_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() override {
        auto proxy_result = vscf_sha256_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_sha256_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Calculate hash over given data.
    std::vector<uint8_t> hash(std::span<const uint8_t> data) override {
        std::vector<uint8_t> digest(Sha256::DIGEST_LEN);
        vsc_buffer_t* digest_buf = vsc_buffer_new();
        vsc_buffer_use(digest_buf, digest.data(), digest.size());
        vscf_sha256_hash(vsc_data(data.data(), data.size()), digest_buf);
        digest.resize(vsc_buffer_len(digest_buf));
        vsc_buffer_delete(digest_buf);
        return digest;
    }

    /// Start a new hashing.
    void start() override {
        vscf_sha256_start(c_ctx_);
    }

    /// Add given data to the hash.
    void update(std::span<const uint8_t> data) override {
        vscf_sha256_update(c_ctx_, vsc_data(data.data(), data.size()));
    }

    /// Accompilsh hashing and return it's result (a message digest).
    std::vector<uint8_t> finish() override {
        std::vector<uint8_t> digest(this->DIGEST_LEN);
        vsc_buffer_t* digest_buf = vsc_buffer_new();
        vsc_buffer_use(digest_buf, digest.data(), digest.size());
        vscf_sha256_finish(c_ctx_, digest_buf);
        digest.resize(vsc_buffer_len(digest_buf));
        vsc_buffer_delete(digest_buf);
        return digest;
    }

private:
    vscf_sha256_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
