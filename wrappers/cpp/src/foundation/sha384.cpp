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

#include <virgil/crypto/foundation/sha384.hpp>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Sha384::Sha384() : c_ctx_(vscf_sha384_new()) {}

Sha384::Sha384(vscf_sha384_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Sha384::Sha384(const Sha384& other) : c_ctx_(vscf_sha384_shallow_copy(other.c_ctx_)) {}

Sha384::Sha384(Sha384&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Sha384& Sha384::operator=(const Sha384& other) {
    if (this != &other) {
        vscf_sha384_delete(c_ctx_);
        c_ctx_ = vscf_sha384_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Sha384& Sha384::operator=(Sha384&& other) noexcept {
    if (this != &other) {
        vscf_sha384_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Sha384::~Sha384() { vscf_sha384_delete(c_ctx_); }

vscf_sha384_t* Sha384::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Sha384::impl() const noexcept { return vscf_sha384_impl(c_ctx_); }

AlgId Sha384::alg_id() const {
    auto proxy_result = vscf_sha384_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Sha384::produce_alg_info() const {
    auto proxy_result = vscf_sha384_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Sha384::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_sha384_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::vector<uint8_t> Sha384::hash(std::span<const uint8_t> data) {
    std::vector<uint8_t> digest(Sha384::DIGEST_LEN);
    vsc_buffer_t digest_buf;
    vsc_buffer_init(&digest_buf);
    vsc_buffer_use(&digest_buf, digest.data(), digest.size());
    vscf_sha384_hash(data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &digest_buf);
    digest.resize(vsc_buffer_len(&digest_buf));
    vsc_buffer_cleanup(&digest_buf);
    return digest;
}

void Sha384::start() {
    vscf_sha384_start(c_ctx_);
}

void Sha384::update(std::span<const uint8_t> data) {
    vscf_sha384_update(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()));
}

std::vector<uint8_t> Sha384::finish() {
    std::vector<uint8_t> digest(this->DIGEST_LEN);
    vsc_buffer_t digest_buf;
    vsc_buffer_init(&digest_buf);
    vsc_buffer_use(&digest_buf, digest.data(), digest.size());
    vscf_sha384_finish(c_ctx_, &digest_buf);
    digest.resize(vsc_buffer_len(&digest_buf));
    vsc_buffer_cleanup(&digest_buf);
    return digest;
}

}  // namespace virgil::crypto::foundation
