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

#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/vscf_raw_private_key.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

RawPrivateKey::RawPrivateKey() : c_ctx_(vscf_raw_private_key_new()) {}

RawPrivateKey::RawPrivateKey(vscf_raw_private_key_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

RawPrivateKey::RawPrivateKey(const RawPrivateKey& other) : c_ctx_(vscf_raw_private_key_shallow_copy(other.c_ctx_)) {}

RawPrivateKey::RawPrivateKey(RawPrivateKey&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

RawPrivateKey& RawPrivateKey::operator=(const RawPrivateKey& other) {
    if (this != &other) {
        vscf_raw_private_key_delete(c_ctx_);
        c_ctx_ = vscf_raw_private_key_shallow_copy(other.c_ctx_);
    }
    return *this;
}

RawPrivateKey& RawPrivateKey::operator=(RawPrivateKey&& other) noexcept {
    if (this != &other) {
        vscf_raw_private_key_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

RawPrivateKey::~RawPrivateKey() { vscf_raw_private_key_delete(c_ctx_); }

vscf_raw_private_key_t* RawPrivateKey::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* RawPrivateKey::impl() const noexcept { return vscf_raw_private_key_impl(c_ctx_); }

std::vector<uint8_t> RawPrivateKey::data() const {
    auto proxy_result = vscf_raw_private_key_data(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

bool RawPrivateKey::has_public_key() const {
    auto proxy_result = vscf_raw_private_key_has_public_key(c_ctx_);
    return proxy_result;
}

void RawPrivateKey::set_public_key(const RawPublicKey& raw_public_key) {
    vscf_raw_public_key_t* raw_public_key_ref = vscf_raw_public_key_shallow_copy(raw_public_key.c_ctx());
    vscf_raw_private_key_set_public_key(c_ctx_, &raw_public_key_ref);
}

RawPublicKey RawPrivateKey::get_public_key() const {
    auto proxy_result = vscf_raw_private_key_get_public_key(c_ctx_);
    return RawPublicKey(vscf_raw_public_key_shallow_copy(const_cast<vscf_raw_public_key_t*>(proxy_result)));
}

AlgId RawPrivateKey::alg_id() const {
    auto proxy_result = vscf_raw_private_key_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> RawPrivateKey::alg_info() const {
    auto proxy_result = vscf_raw_private_key_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::size_t RawPrivateKey::len() const {
    auto proxy_result = vscf_raw_private_key_len(c_ctx_);
    return proxy_result;
}

std::size_t RawPrivateKey::bitlen() const {
    auto proxy_result = vscf_raw_private_key_bitlen(c_ctx_);
    return proxy_result;
}

bool RawPrivateKey::is_valid() const {
    auto proxy_result = vscf_raw_private_key_is_valid(c_ctx_);
    return proxy_result;
}

std::unique_ptr<PublicKey> RawPrivateKey::extract_public_key() const {
    auto proxy_result = vscf_raw_private_key_extract_public_key(c_ctx_);
    return FoundationImplementation::wrap_public_key(proxy_result);
}

}  // namespace virgil::crypto::foundation
