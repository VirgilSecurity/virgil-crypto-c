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

#include <virgil/crypto/foundation/kdf1.hpp>
#include <virgil/crypto/foundation/vscf_kdf1.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Kdf1::Kdf1() : c_ctx_(vscf_kdf1_new()) {}

Kdf1::Kdf1(vscf_kdf1_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Kdf1::Kdf1(const Kdf1& other) : c_ctx_(vscf_kdf1_shallow_copy(other.c_ctx_)) {}

Kdf1::Kdf1(Kdf1&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Kdf1& Kdf1::operator=(const Kdf1& other) {
    if (this != &other) {
        vscf_kdf1_delete(c_ctx_);
        c_ctx_ = vscf_kdf1_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Kdf1& Kdf1::operator=(Kdf1&& other) noexcept {
    if (this != &other) {
        vscf_kdf1_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Kdf1::~Kdf1() { vscf_kdf1_delete(c_ctx_); }

vscf_kdf1_t* Kdf1::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Kdf1::impl() const noexcept { return vscf_kdf1_impl(c_ctx_); }

void Kdf1::set_hash(const Hash& hash) {
    vscf_kdf1_release_hash(c_ctx_);
    vscf_kdf1_use_hash(c_ctx_, hash.impl());
}

AlgId Kdf1::alg_id() const {
    auto proxy_result = vscf_kdf1_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Kdf1::produce_alg_info() const {
    auto proxy_result = vscf_kdf1_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Kdf1::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_kdf1_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::vector<uint8_t> Kdf1::derive(std::span<const uint8_t> data, std::size_t key_len) {
    std::vector<uint8_t> key(key_len);
    vsc_buffer_t key_buf;
    vsc_buffer_init(&key_buf);
    vsc_buffer_use(&key_buf, key.data(), key.size());
    vscf_kdf1_derive(c_ctx_, vsc_data(data.data(), data.size()), key_len, &key_buf);
    key.resize(vsc_buffer_len(&key_buf));
    vsc_buffer_cleanup(&key_buf);
    return key;
}

}  // namespace virgil::crypto::foundation
