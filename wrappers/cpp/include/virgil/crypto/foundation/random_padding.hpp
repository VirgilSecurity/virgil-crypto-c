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
#include <virgil/crypto/foundation/vscf_random_padding.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/padding.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/padding_params.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Append a random number of padding bytes to a data.
class RandomPadding : virtual public Alg, virtual public Padding {
public:
    RandomPadding() : c_ctx_(vscf_random_padding_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit RandomPadding(vscf_random_padding_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    RandomPadding(const RandomPadding& other) : c_ctx_(vscf_random_padding_shallow_copy(other.c_ctx_)) {}
    RandomPadding(RandomPadding&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    RandomPadding& operator=(const RandomPadding& other) {
        if (this != &other) {
            vscf_random_padding_delete(c_ctx_);
            c_ctx_ = vscf_random_padding_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    RandomPadding& operator=(RandomPadding&& other) noexcept {
        if (this != &other) {
            vscf_random_padding_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~RandomPadding() { vscf_random_padding_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_random_padding_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_random_padding_impl(c_ctx_); }

    static constexpr std::size_t PADDING_SIZE_LEN = 4;

    void set_random(const Random& random) {
        vscf_random_padding_release_random(c_ctx_);
        vscf_random_padding_use_random(c_ctx_, random.impl());
    }

    /// Provide algorithm identificator.
    AlgId alg_id() const override {
        auto proxy_result = vscf_random_padding_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override {
        auto proxy_result = vscf_random_padding_produce_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override {
        const vscf_status_t status = vscf_random_padding_restore_alg_info(c_ctx_, alg_info.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Set new padding parameters.
    void configure(const PaddingParams& params) override {
        vscf_random_padding_configure(c_ctx_, params.c_ctx());
    }

    /// Return length in bytes of a data with a padding.
    std::size_t padded_data_len(std::size_t data_len) const override {
        auto proxy_result = vscf_random_padding_padded_data_len(c_ctx_, data_len);
        return proxy_result;
    }

    /// Return an actual number of padding in bytes.
    /// Note, this method might be called right before "finish data processing".
    std::size_t len() const override {
        auto proxy_result = vscf_random_padding_len(c_ctx_);
        return proxy_result;
    }

    /// Return a maximum number of padding in bytes.
    std::size_t len_max() const override {
        auto proxy_result = vscf_random_padding_len_max(c_ctx_);
        return proxy_result;
    }

    /// Prepare the algorithm to process data.
    void start_data_processing() override {
        vscf_random_padding_start_data_processing(c_ctx_);
    }

    /// Only data length is needed to produce padding later.
    /// Return data that should be further proceeded.
    std::vector<uint8_t> process_data(std::span<const uint8_t> data) override {
        auto proxy_result = vscf_random_padding_process_data(c_ctx_, vsc_data(data.data(), data.size()));
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Accomplish data processing and return padding.
    tl::expected<std::vector<uint8_t>, Error> finish_data_processing() override {
        std::vector<uint8_t> out(this->len());
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_random_padding_finish_data_processing(c_ctx_, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Prepare the algorithm to process padded data.
    void start_padded_data_processing() override {
        vscf_random_padding_start_padded_data_processing(c_ctx_);
    }

    /// Process padded data.
    /// Return filtered data without padding.
    std::vector<uint8_t> process_padded_data(std::span<const uint8_t> data) override {
        std::vector<uint8_t> out(data.size());
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        vscf_random_padding_process_padded_data(c_ctx_, vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        return out;
    }

    /// Return length in bytes required hold output of the method
    /// "finish padded data processing".
    std::size_t finish_padded_data_processing_out_len() const override {
        auto proxy_result = vscf_random_padding_finish_padded_data_processing_out_len(c_ctx_);
        return proxy_result;
    }

    /// Accomplish padded data processing and return left data without a padding.
    tl::expected<std::vector<uint8_t>, Error> finish_padded_data_processing() override {
        std::vector<uint8_t> out(this->finish_padded_data_processing_out_len());
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_random_padding_finish_padded_data_processing(c_ctx_, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_random_padding_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
