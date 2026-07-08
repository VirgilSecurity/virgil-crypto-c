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

#include <virgil/crypto/foundation/password_recipient_info.hpp>
#include <virgil/crypto/foundation/vscf_password_recipient_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

PasswordRecipientInfo::PasswordRecipientInfo() : c_ctx_(vscf_password_recipient_info_new()) {}

PasswordRecipientInfo::PasswordRecipientInfo(vscf_password_recipient_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

PasswordRecipientInfo::PasswordRecipientInfo(const PasswordRecipientInfo& other) : c_ctx_(vscf_password_recipient_info_shallow_copy(other.c_ctx_)) {}

PasswordRecipientInfo::PasswordRecipientInfo(PasswordRecipientInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

PasswordRecipientInfo& PasswordRecipientInfo::operator=(const PasswordRecipientInfo& other) {
    if (this != &other) {
        vscf_password_recipient_info_delete(c_ctx_);
        c_ctx_ = vscf_password_recipient_info_shallow_copy(other.c_ctx_);
    }
    return *this;
}

PasswordRecipientInfo& PasswordRecipientInfo::operator=(PasswordRecipientInfo&& other) noexcept {
    if (this != &other) {
        vscf_password_recipient_info_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

PasswordRecipientInfo::~PasswordRecipientInfo() { vscf_password_recipient_info_delete(c_ctx_); }

vscf_password_recipient_info_t* PasswordRecipientInfo::c_ctx() const noexcept { return c_ctx_; }

std::unique_ptr<AlgInfo> PasswordRecipientInfo::key_encryption_algorithm() const {
    auto proxy_result = vscf_password_recipient_info_key_encryption_algorithm(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::vector<uint8_t> PasswordRecipientInfo::encrypted_key() const {
    auto proxy_result = vscf_password_recipient_info_encrypted_key(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

}  // namespace virgil::crypto::foundation
