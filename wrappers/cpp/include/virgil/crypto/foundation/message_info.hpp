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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_message_info.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/footer_info.hpp>
#include <virgil/crypto/foundation/kek_recipient_info_list.hpp>
#include <virgil/crypto/foundation/key_recipient_info_list.hpp>
#include <virgil/crypto/foundation/message_info_custom_params.hpp>
#include <virgil/crypto/foundation/password_recipient_info_list.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handle information about an encrypted message and algorithms
/// that was used for encryption.
class MessageInfo {
public:
    MessageInfo() : c_ctx_(vscf_message_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MessageInfo(vscf_message_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MessageInfo(const MessageInfo& other) : c_ctx_(vscf_message_info_shallow_copy(other.c_ctx_)) {}
    MessageInfo(MessageInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MessageInfo& operator=(const MessageInfo& other) {
        if (this != &other) {
            vscf_message_info_delete(c_ctx_);
            c_ctx_ = vscf_message_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MessageInfo& operator=(MessageInfo&& other) noexcept {
        if (this != &other) {
            vscf_message_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MessageInfo() { vscf_message_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return information about algorithm that was used for the data encryption.
    std::unique_ptr<AlgInfo> data_encryption_alg_info() {
        auto proxy_result = vscf_message_info_data_encryption_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return list with a "key recipient info" elements.
    KeyRecipientInfoList key_recipient_info_list() {
        auto proxy_result = vscf_message_info_key_recipient_info_list(c_ctx_);
        return KeyRecipientInfoList(vscf_key_recipient_info_list_shallow_copy(const_cast<vscf_key_recipient_info_list_t*>(proxy_result)));
    }

    /// Return list with a "password recipient info" elements.
    PasswordRecipientInfoList password_recipient_info_list() {
        auto proxy_result = vscf_message_info_password_recipient_info_list(c_ctx_);
        return PasswordRecipientInfoList(vscf_password_recipient_info_list_shallow_copy(const_cast<vscf_password_recipient_info_list_t*>(proxy_result)));
    }

    /// Return list with a "kek recipient info" elements.
    KekRecipientInfoList kek_recipient_info_list() {
        auto proxy_result = vscf_message_info_kek_recipient_info_list(c_ctx_);
        return KekRecipientInfoList(vscf_kek_recipient_info_list_shallow_copy(const_cast<vscf_kek_recipient_info_list_t*>(proxy_result)));
    }

    /// Return true if message info contains at least one custom param.
    bool has_custom_params() {
        auto proxy_result = vscf_message_info_has_custom_params(c_ctx_);
        return proxy_result;
    }

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    /// If custom params object was not set then new empty object is created.
    MessageInfoCustomParams custom_params() {
        auto proxy_result = vscf_message_info_custom_params(c_ctx_);
        return MessageInfoCustomParams(vscf_message_info_custom_params_shallow_copy(const_cast<vscf_message_info_custom_params_t*>(proxy_result)));
    }

    /// Return true if cipher kdf alg info exists.
    bool has_cipher_kdf_alg_info() {
        auto proxy_result = vscf_message_info_has_cipher_kdf_alg_info(c_ctx_);
        return proxy_result;
    }

    /// Return cipher kdf alg info.
    std::unique_ptr<AlgInfo> cipher_kdf_alg_info() {
        auto proxy_result = vscf_message_info_cipher_kdf_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return true if cipher padding alg info exists.
    bool has_cipher_padding_alg_info() {
        auto proxy_result = vscf_message_info_has_cipher_padding_alg_info(c_ctx_);
        return proxy_result;
    }

    /// Return cipher padding alg info.
    std::unique_ptr<AlgInfo> cipher_padding_alg_info() {
        auto proxy_result = vscf_message_info_cipher_padding_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return true if footer info exists.
    bool has_footer_info() {
        auto proxy_result = vscf_message_info_has_footer_info(c_ctx_);
        return proxy_result;
    }

    /// Return footer info.
    FooterInfo footer_info() {
        auto proxy_result = vscf_message_info_footer_info(c_ctx_);
        return FooterInfo(vscf_footer_info_shallow_copy(const_cast<vscf_footer_info_t*>(proxy_result)));
    }

    /// Remove all infos.
    void clear() {
        vscf_message_info_clear(c_ctx_);
    }

private:
    vscf_message_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
