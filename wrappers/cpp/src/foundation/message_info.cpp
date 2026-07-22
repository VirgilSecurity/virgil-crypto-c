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

#include <virgil/crypto/foundation/message_info.hpp>
#include <virgil/crypto/foundation/vscf_message_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/footer_info.hpp>
#include <virgil/crypto/foundation/kek_recipient_info_list.hpp>
#include <virgil/crypto/foundation/key_recipient_info_list.hpp>
#include <virgil/crypto/foundation/message_info_custom_params.hpp>
#include <virgil/crypto/foundation/password_recipient_info_list.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

MessageInfo::MessageInfo() : c_ctx_(vscf_message_info_new()) {}

MessageInfo::MessageInfo(vscf_message_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

MessageInfo::MessageInfo(const MessageInfo& other) : c_ctx_(vscf_message_info_shallow_copy(other.c_ctx_)) {}

MessageInfo::MessageInfo(MessageInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

MessageInfo& MessageInfo::operator=(const MessageInfo& other) {
    if (this != &other) {
        vscf_message_info_delete(c_ctx_);
        c_ctx_ = vscf_message_info_shallow_copy(other.c_ctx_);
    }
    return *this;
}

MessageInfo& MessageInfo::operator=(MessageInfo&& other) noexcept {
    if (this != &other) {
        vscf_message_info_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

MessageInfo::~MessageInfo() { vscf_message_info_delete(c_ctx_); }

vscf_message_info_t* MessageInfo::c_ctx() const noexcept { return c_ctx_; }

std::unique_ptr<AlgInfo> MessageInfo::data_encryption_alg_info() const {
    auto proxy_result = vscf_message_info_data_encryption_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

KeyRecipientInfoList MessageInfo::key_recipient_info_list() const {
    auto proxy_result = vscf_message_info_key_recipient_info_list(c_ctx_);
    return KeyRecipientInfoList(vscf_key_recipient_info_list_shallow_copy(const_cast<vscf_key_recipient_info_list_t*>(proxy_result)));
}

PasswordRecipientInfoList MessageInfo::password_recipient_info_list() const {
    auto proxy_result = vscf_message_info_password_recipient_info_list(c_ctx_);
    return PasswordRecipientInfoList(vscf_password_recipient_info_list_shallow_copy(const_cast<vscf_password_recipient_info_list_t*>(proxy_result)));
}

KekRecipientInfoList MessageInfo::kek_recipient_info_list() const {
    auto proxy_result = vscf_message_info_kek_recipient_info_list(c_ctx_);
    return KekRecipientInfoList(vscf_kek_recipient_info_list_shallow_copy(const_cast<vscf_kek_recipient_info_list_t*>(proxy_result)));
}

bool MessageInfo::has_custom_params() const {
    auto proxy_result = vscf_message_info_has_custom_params(c_ctx_);
    return proxy_result;
}

MessageInfoCustomParams MessageInfo::custom_params() {
    auto proxy_result = vscf_message_info_custom_params(c_ctx_);
    return MessageInfoCustomParams(vscf_message_info_custom_params_shallow_copy(const_cast<vscf_message_info_custom_params_t*>(proxy_result)));
}

bool MessageInfo::has_cipher_kdf_alg_info() const {
    auto proxy_result = vscf_message_info_has_cipher_kdf_alg_info(c_ctx_);
    return proxy_result;
}

std::unique_ptr<AlgInfo> MessageInfo::cipher_kdf_alg_info() const {
    auto proxy_result = vscf_message_info_cipher_kdf_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

bool MessageInfo::has_cipher_padding_alg_info() const {
    auto proxy_result = vscf_message_info_has_cipher_padding_alg_info(c_ctx_);
    return proxy_result;
}

std::unique_ptr<AlgInfo> MessageInfo::cipher_padding_alg_info() const {
    auto proxy_result = vscf_message_info_cipher_padding_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

bool MessageInfo::has_footer_info() const {
    auto proxy_result = vscf_message_info_has_footer_info(c_ctx_);
    return proxy_result;
}

FooterInfo MessageInfo::footer_info() const {
    auto proxy_result = vscf_message_info_footer_info(c_ctx_);
    return FooterInfo(vscf_footer_info_shallow_copy(const_cast<vscf_footer_info_t*>(proxy_result)));
}

void MessageInfo::clear() {
    vscf_message_info_clear(c_ctx_);
}

}  // namespace virgil::crypto::foundation
