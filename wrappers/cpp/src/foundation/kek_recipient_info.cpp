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

#include <virgil/crypto/foundation/kek_recipient_info.hpp>
#include <virgil/crypto/foundation/vscf_kek_recipient_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

KekRecipientInfo::KekRecipientInfo() : c_ctx_(vscf_kek_recipient_info_new()) {}

KekRecipientInfo::KekRecipientInfo(vscf_kek_recipient_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

KekRecipientInfo::KekRecipientInfo(const KekRecipientInfo& other) : c_ctx_(vscf_kek_recipient_info_shallow_copy(other.c_ctx_)) {}

KekRecipientInfo::KekRecipientInfo(KekRecipientInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

KekRecipientInfo& KekRecipientInfo::operator=(const KekRecipientInfo& other) {
    if (this != &other) {
        vscf_kek_recipient_info_delete(c_ctx_);
        c_ctx_ = vscf_kek_recipient_info_shallow_copy(other.c_ctx_);
    }
    return *this;
}

KekRecipientInfo& KekRecipientInfo::operator=(KekRecipientInfo&& other) noexcept {
    if (this != &other) {
        vscf_kek_recipient_info_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

KekRecipientInfo::~KekRecipientInfo() { vscf_kek_recipient_info_delete(c_ctx_); }

vscf_kek_recipient_info_t* KekRecipientInfo::c_ctx() const noexcept { return c_ctx_; }

std::vector<uint8_t> KekRecipientInfo::kek_id() const {
    auto proxy_result = vscf_kek_recipient_info_kek_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::unique_ptr<AlgInfo> KekRecipientInfo::key_encryption_algorithm() const {
    auto proxy_result = vscf_kek_recipient_info_key_encryption_algorithm(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::vector<uint8_t> KekRecipientInfo::encrypted_key() const {
    auto proxy_result = vscf_kek_recipient_info_encrypted_key(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

}  // namespace virgil::crypto::foundation
