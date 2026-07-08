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

#include <virgil/crypto/foundation/fake_random.hpp>
#include <virgil/crypto/foundation/vscf_fake_random.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/entropy_source.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

FakeRandom::FakeRandom() : c_ctx_(vscf_fake_random_new()) {}

FakeRandom::FakeRandom(vscf_fake_random_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

FakeRandom::FakeRandom(const FakeRandom& other) : c_ctx_(vscf_fake_random_shallow_copy(other.c_ctx_)) {}

FakeRandom::FakeRandom(FakeRandom&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

FakeRandom& FakeRandom::operator=(const FakeRandom& other) {
    if (this != &other) {
        vscf_fake_random_delete(c_ctx_);
        c_ctx_ = vscf_fake_random_shallow_copy(other.c_ctx_);
    }
    return *this;
}

FakeRandom& FakeRandom::operator=(FakeRandom&& other) noexcept {
    if (this != &other) {
        vscf_fake_random_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

FakeRandom::~FakeRandom() { vscf_fake_random_delete(c_ctx_); }

vscf_fake_random_t* FakeRandom::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* FakeRandom::impl() const noexcept { return vscf_fake_random_impl(c_ctx_); }

void FakeRandom::setup_source_byte(uint8_t byte_source) {
    vscf_fake_random_setup_source_byte(c_ctx_, byte_source);
}

void FakeRandom::setup_source_data(std::span<const uint8_t> data_source) {
    vscf_fake_random_setup_source_data(c_ctx_, data_source.empty() ? vsc_data_empty() : vsc_data(data_source.data(), data_source.size()));
}

tl::expected<std::vector<uint8_t>, Error> FakeRandom::random(std::size_t data_len) const {
    std::vector<uint8_t> data(data_len);
    vsc_buffer_t data_buf;
    vsc_buffer_init(&data_buf);
    vsc_buffer_use(&data_buf, data.data(), data.size());
    const vscf_status_t status = vscf_fake_random_random(c_ctx_, data_len, &data_buf);
    data.resize(vsc_buffer_len(&data_buf));
    vsc_buffer_cleanup(&data_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return data;
}

tl::expected<void, Error> FakeRandom::reseed() {
    const vscf_status_t status = vscf_fake_random_reseed(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

bool FakeRandom::is_strong() {
    auto proxy_result = vscf_fake_random_is_strong(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> FakeRandom::gather(std::size_t len) {
    std::vector<uint8_t> out(len);
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_fake_random_gather(c_ctx_, len, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
