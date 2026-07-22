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

#include <virgil/crypto/foundation/salted_kdf_alg_info.hpp>
#include <virgil/crypto/foundation/vscf_salted_kdf_alg_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

SaltedKdfAlgInfo::SaltedKdfAlgInfo() : c_ctx_(vscf_salted_kdf_alg_info_new()) {}

SaltedKdfAlgInfo::SaltedKdfAlgInfo(vscf_salted_kdf_alg_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

SaltedKdfAlgInfo::SaltedKdfAlgInfo(const SaltedKdfAlgInfo& other) : c_ctx_(vscf_salted_kdf_alg_info_shallow_copy(other.c_ctx_)) {}

SaltedKdfAlgInfo::SaltedKdfAlgInfo(SaltedKdfAlgInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

SaltedKdfAlgInfo& SaltedKdfAlgInfo::operator=(const SaltedKdfAlgInfo& other) {
    if (this != &other) {
        vscf_salted_kdf_alg_info_delete(c_ctx_);
        c_ctx_ = vscf_salted_kdf_alg_info_shallow_copy(other.c_ctx_);
    }
    return *this;
}

SaltedKdfAlgInfo& SaltedKdfAlgInfo::operator=(SaltedKdfAlgInfo&& other) noexcept {
    if (this != &other) {
        vscf_salted_kdf_alg_info_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

SaltedKdfAlgInfo::~SaltedKdfAlgInfo() { vscf_salted_kdf_alg_info_delete(c_ctx_); }

vscf_salted_kdf_alg_info_t* SaltedKdfAlgInfo::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* SaltedKdfAlgInfo::impl() const noexcept { return vscf_salted_kdf_alg_info_impl(c_ctx_); }

std::unique_ptr<AlgInfo> SaltedKdfAlgInfo::hash_alg_info() const {
    auto proxy_result = vscf_salted_kdf_alg_info_hash_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::vector<uint8_t> SaltedKdfAlgInfo::salt() const {
    auto proxy_result = vscf_salted_kdf_alg_info_salt(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::size_t SaltedKdfAlgInfo::iteration_count() const {
    auto proxy_result = vscf_salted_kdf_alg_info_iteration_count(c_ctx_);
    return proxy_result;
}

AlgId SaltedKdfAlgInfo::alg_id() const {
    auto proxy_result = vscf_salted_kdf_alg_info_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

}  // namespace virgil::crypto::foundation
