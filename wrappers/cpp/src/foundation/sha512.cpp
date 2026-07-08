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

#include <virgil/crypto/foundation/sha512.hpp>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Sha512::Sha512() : c_ctx_(vscf_sha512_new()) {}

Sha512::Sha512(vscf_sha512_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Sha512::Sha512(const Sha512& other) : c_ctx_(vscf_sha512_shallow_copy(other.c_ctx_)) {}

Sha512::Sha512(Sha512&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Sha512& Sha512::operator=(const Sha512& other) {
    if (this != &other) {
        vscf_sha512_delete(c_ctx_);
        c_ctx_ = vscf_sha512_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Sha512& Sha512::operator=(Sha512&& other) noexcept {
    if (this != &other) {
        vscf_sha512_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Sha512::~Sha512() { vscf_sha512_delete(c_ctx_); }

vscf_sha512_t* Sha512::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Sha512::impl() const noexcept { return vscf_sha512_impl(c_ctx_); }

AlgId Sha512::alg_id() const {
    auto proxy_result = vscf_sha512_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Sha512::produce_alg_info() const {
    auto proxy_result = vscf_sha512_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Sha512::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_sha512_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::vector<uint8_t> Sha512::hash(std::span<const uint8_t> data) {
    std::vector<uint8_t> digest(Sha512::DIGEST_LEN);
    vsc_buffer_t digest_buf;
    vsc_buffer_init(&digest_buf);
    vsc_buffer_use(&digest_buf, digest.data(), digest.size());
    vscf_sha512_hash(vsc_data(data.data(), data.size()), &digest_buf);
    digest.resize(vsc_buffer_len(&digest_buf));
    vsc_buffer_cleanup(&digest_buf);
    return digest;
}

void Sha512::start() {
    vscf_sha512_start(c_ctx_);
}

void Sha512::update(std::span<const uint8_t> data) {
    vscf_sha512_update(c_ctx_, vsc_data(data.data(), data.size()));
}

std::vector<uint8_t> Sha512::finish() {
    std::vector<uint8_t> digest(this->DIGEST_LEN);
    vsc_buffer_t digest_buf;
    vsc_buffer_init(&digest_buf);
    vsc_buffer_use(&digest_buf, digest.data(), digest.size());
    vscf_sha512_finish(c_ctx_, &digest_buf);
    digest.resize(vsc_buffer_len(&digest_buf));
    vsc_buffer_cleanup(&digest_buf);
    return digest;
}

}  // namespace virgil::crypto::foundation
