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

#include <virgil/crypto/foundation/ecc_public_key.hpp>
#include <virgil/crypto/foundation/vscf_ecc_public_key.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

EccPublicKey::EccPublicKey() : c_ctx_(vscf_ecc_public_key_new()) {}

EccPublicKey::EccPublicKey(vscf_ecc_public_key_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

EccPublicKey::EccPublicKey(const EccPublicKey& other) : c_ctx_(vscf_ecc_public_key_shallow_copy(other.c_ctx_)) {}

EccPublicKey::EccPublicKey(EccPublicKey&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

EccPublicKey& EccPublicKey::operator=(const EccPublicKey& other) {
    if (this != &other) {
        vscf_ecc_public_key_delete(c_ctx_);
        c_ctx_ = vscf_ecc_public_key_shallow_copy(other.c_ctx_);
    }
    return *this;
}

EccPublicKey& EccPublicKey::operator=(EccPublicKey&& other) noexcept {
    if (this != &other) {
        vscf_ecc_public_key_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

EccPublicKey::~EccPublicKey() { vscf_ecc_public_key_delete(c_ctx_); }

vscf_ecc_public_key_t* EccPublicKey::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* EccPublicKey::impl() const noexcept { return vscf_ecc_public_key_impl(c_ctx_); }

AlgId EccPublicKey::alg_id() const {
    auto proxy_result = vscf_ecc_public_key_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> EccPublicKey::alg_info() const {
    auto proxy_result = vscf_ecc_public_key_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::size_t EccPublicKey::len() const {
    auto proxy_result = vscf_ecc_public_key_len(c_ctx_);
    return proxy_result;
}

std::size_t EccPublicKey::bitlen() const {
    auto proxy_result = vscf_ecc_public_key_bitlen(c_ctx_);
    return proxy_result;
}

bool EccPublicKey::is_valid() const {
    auto proxy_result = vscf_ecc_public_key_is_valid(c_ctx_);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
