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

#include <virgil/crypto/foundation/ctr_drbg.hpp>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/entropy_source.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

CtrDrbg::CtrDrbg() : c_ctx_(vscf_ctr_drbg_new()) {}

CtrDrbg::CtrDrbg(vscf_ctr_drbg_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

CtrDrbg::CtrDrbg(const CtrDrbg& other) : c_ctx_(vscf_ctr_drbg_shallow_copy(other.c_ctx_)) {}

CtrDrbg::CtrDrbg(CtrDrbg&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

CtrDrbg& CtrDrbg::operator=(const CtrDrbg& other) {
    if (this != &other) {
        vscf_ctr_drbg_delete(c_ctx_);
        c_ctx_ = vscf_ctr_drbg_shallow_copy(other.c_ctx_);
    }
    return *this;
}

CtrDrbg& CtrDrbg::operator=(CtrDrbg&& other) noexcept {
    if (this != &other) {
        vscf_ctr_drbg_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

CtrDrbg::~CtrDrbg() { vscf_ctr_drbg_delete(c_ctx_); }

vscf_ctr_drbg_t* CtrDrbg::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* CtrDrbg::impl() const noexcept { return vscf_ctr_drbg_impl(c_ctx_); }

tl::expected<void, Error> CtrDrbg::set_entropy_source(const EntropySource& entropy_source) {
    vscf_ctr_drbg_release_entropy_source(c_ctx_);
    const vscf_status_t status = vscf_ctr_drbg_use_entropy_source(c_ctx_, entropy_source.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> CtrDrbg::setup_defaults() {
    const vscf_status_t status = vscf_ctr_drbg_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

void CtrDrbg::enable_prediction_resistance() {
    vscf_ctr_drbg_enable_prediction_resistance(c_ctx_);
}

void CtrDrbg::set_reseed_interval(std::size_t interval) {
    vscf_ctr_drbg_set_reseed_interval(c_ctx_, interval);
}

void CtrDrbg::set_entropy_len(std::size_t len) {
    vscf_ctr_drbg_set_entropy_len(c_ctx_, len);
}

tl::expected<std::vector<uint8_t>, Error> CtrDrbg::random(std::size_t data_len) const {
    std::vector<uint8_t> data(data_len);
    vsc_buffer_t data_buf;
    vsc_buffer_init(&data_buf);
    vsc_buffer_use(&data_buf, data.data(), data.size());
    const vscf_status_t status = vscf_ctr_drbg_random(c_ctx_, data_len, &data_buf);
    data.resize(vsc_buffer_len(&data_buf));
    vsc_buffer_cleanup(&data_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return data;
}

tl::expected<void, Error> CtrDrbg::reseed() {
    const vscf_status_t status = vscf_ctr_drbg_reseed(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

}  // namespace virgil::crypto::foundation
