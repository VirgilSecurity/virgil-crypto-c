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

#include <virgil/crypto/foundation/random_padding.hpp>
#include <virgil/crypto/foundation/vscf_random_padding.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/padding.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/padding_params.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

RandomPadding::RandomPadding() : c_ctx_(vscf_random_padding_new()) {}

RandomPadding::RandomPadding(vscf_random_padding_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

RandomPadding::RandomPadding(const RandomPadding& other) : c_ctx_(vscf_random_padding_shallow_copy(other.c_ctx_)) {}

RandomPadding::RandomPadding(RandomPadding&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

RandomPadding& RandomPadding::operator=(const RandomPadding& other) {
    if (this != &other) {
        vscf_random_padding_delete(c_ctx_);
        c_ctx_ = vscf_random_padding_shallow_copy(other.c_ctx_);
    }
    return *this;
}

RandomPadding& RandomPadding::operator=(RandomPadding&& other) noexcept {
    if (this != &other) {
        vscf_random_padding_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

RandomPadding::~RandomPadding() { vscf_random_padding_delete(c_ctx_); }

vscf_random_padding_t* RandomPadding::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* RandomPadding::impl() const noexcept { return vscf_random_padding_impl(c_ctx_); }

void RandomPadding::set_random(const Random& random) {
    vscf_random_padding_release_random(c_ctx_);
    vscf_random_padding_use_random(c_ctx_, random.impl());
}

AlgId RandomPadding::alg_id() const {
    auto proxy_result = vscf_random_padding_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> RandomPadding::produce_alg_info() const {
    auto proxy_result = vscf_random_padding_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> RandomPadding::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_random_padding_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

void RandomPadding::configure(const PaddingParams& params) {
    vscf_random_padding_configure(c_ctx_, params.c_ctx());
}

std::size_t RandomPadding::padded_data_len(std::size_t data_len) const {
    auto proxy_result = vscf_random_padding_padded_data_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t RandomPadding::len() const {
    auto proxy_result = vscf_random_padding_len(c_ctx_);
    return proxy_result;
}

std::size_t RandomPadding::len_max() const {
    auto proxy_result = vscf_random_padding_len_max(c_ctx_);
    return proxy_result;
}

void RandomPadding::start_data_processing() {
    vscf_random_padding_start_data_processing(c_ctx_);
}

std::vector<uint8_t> RandomPadding::process_data(std::span<const uint8_t> data) {
    auto proxy_result = vscf_random_padding_process_data(c_ctx_, vsc_data(data.data(), data.size()));
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

tl::expected<std::vector<uint8_t>, Error> RandomPadding::finish_data_processing() {
    std::vector<uint8_t> out(this->len());
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_random_padding_finish_data_processing(c_ctx_, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

void RandomPadding::start_padded_data_processing() {
    vscf_random_padding_start_padded_data_processing(c_ctx_);
}

std::vector<uint8_t> RandomPadding::process_padded_data(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(data.size());
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    vscf_random_padding_process_padded_data(c_ctx_, vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    return out;
}

std::size_t RandomPadding::finish_padded_data_processing_out_len() const {
    auto proxy_result = vscf_random_padding_finish_padded_data_processing_out_len(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> RandomPadding::finish_padded_data_processing() {
    std::vector<uint8_t> out(this->finish_padded_data_processing_out_len());
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_random_padding_finish_padded_data_processing(c_ctx_, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
