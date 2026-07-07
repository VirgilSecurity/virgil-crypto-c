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
#include <virgil/crypto/foundation/vscf_fake_random.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/entropy_source.hpp>

namespace virgil::crypto::foundation {

/// Random number generator that is used for test purposes only.
class FakeRandom : virtual public Random, virtual public EntropySource {
public:
    FakeRandom() : c_ctx_(vscf_fake_random_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit FakeRandom(vscf_fake_random_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    FakeRandom(const FakeRandom& other) : c_ctx_(vscf_fake_random_shallow_copy(other.c_ctx_)) {}
    FakeRandom(FakeRandom&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    FakeRandom& operator=(const FakeRandom& other) {
        if (this != &other) {
            vscf_fake_random_delete(c_ctx_);
            c_ctx_ = vscf_fake_random_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    FakeRandom& operator=(FakeRandom&& other) noexcept {
        if (this != &other) {
            vscf_fake_random_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~FakeRandom() { vscf_fake_random_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_fake_random_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_fake_random_impl(c_ctx_); }

    /// Configure random number generator to generate sequence filled with given byte.
    void setup_source_byte(uint8_t byte_source) {
        vscf_fake_random_setup_source_byte(c_ctx_, byte_source);
    }

    /// Configure random number generator to generate random sequence from given data.
    /// Note, that given data is used as circular source.
    void setup_source_data(std::span<const uint8_t> data_source) {
        vscf_fake_random_setup_source_data(c_ctx_, vsc_data(data_source.data(), data_source.size()));
    }

    /// Generate random bytes.
    /// All RNG implementations must be thread-safe.
    tl::expected<std::vector<uint8_t>, Error> random(std::size_t data_len) override {
        std::vector<uint8_t> data(data_len);
        vsc_buffer_t* data_buf = vsc_buffer_new();
        vsc_buffer_use(data_buf, data.data(), data.size());
        const vscf_status_t status = vscf_fake_random_random(c_ctx_, data_len, data_buf);
        data.resize(vsc_buffer_len(data_buf));
        vsc_buffer_delete(data_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return data;
    }

    /// Retrieve new seed data from the entropy sources.
    tl::expected<void, Error> reseed() override {
        const vscf_status_t status = vscf_fake_random_reseed(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Defines that implemented source is strong.
    bool is_strong() override {
        auto proxy_result = vscf_fake_random_is_strong(c_ctx_);
        return proxy_result;
    }

    /// Gather entropy of the requested length.
    tl::expected<std::vector<uint8_t>, Error> gather(std::size_t len) override {
        std::vector<uint8_t> out(len);
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_fake_random_gather(c_ctx_, len, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_fake_random_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
