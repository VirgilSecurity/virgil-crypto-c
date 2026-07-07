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
#include <virgil/crypto/foundation/vscf_password_recipient_info_list.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/password_recipient_info.hpp>

namespace virgil::crypto::foundation {

/// Handles a list of "password recipient info" class objects.
class PasswordRecipientInfoList {
public:
    PasswordRecipientInfoList() : c_ctx_(vscf_password_recipient_info_list_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit PasswordRecipientInfoList(vscf_password_recipient_info_list_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    PasswordRecipientInfoList(const PasswordRecipientInfoList& other) : c_ctx_(vscf_password_recipient_info_list_shallow_copy(other.c_ctx_)) {}
    PasswordRecipientInfoList(PasswordRecipientInfoList&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    PasswordRecipientInfoList& operator=(const PasswordRecipientInfoList& other) {
        if (this != &other) {
            vscf_password_recipient_info_list_delete(c_ctx_);
            c_ctx_ = vscf_password_recipient_info_list_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    PasswordRecipientInfoList& operator=(PasswordRecipientInfoList&& other) noexcept {
        if (this != &other) {
            vscf_password_recipient_info_list_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~PasswordRecipientInfoList() { vscf_password_recipient_info_list_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_password_recipient_info_list_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return true if given list has item.
    bool has_item() {
        auto proxy_result = vscf_password_recipient_info_list_has_item(c_ctx_);
        return proxy_result;
    }

    /// Return list item.
    PasswordRecipientInfo item() {
        auto proxy_result = vscf_password_recipient_info_list_item(c_ctx_);
        return PasswordRecipientInfo(vscf_password_recipient_info_shallow_copy(const_cast<vscf_password_recipient_info_t*>(proxy_result)));
    }

    /// Return true if list has next item.
    bool has_next() {
        auto proxy_result = vscf_password_recipient_info_list_has_next(c_ctx_);
        return proxy_result;
    }

    /// Return next list node if exists, or NULL otherwise.
    PasswordRecipientInfoList next() {
        auto proxy_result = vscf_password_recipient_info_list_next(c_ctx_);
        return PasswordRecipientInfoList(vscf_password_recipient_info_list_shallow_copy(const_cast<vscf_password_recipient_info_list_t*>(proxy_result)));
    }

    /// Return true if list has previous item.
    bool has_prev() {
        auto proxy_result = vscf_password_recipient_info_list_has_prev(c_ctx_);
        return proxy_result;
    }

    /// Return previous list node if exists, or NULL otherwise.
    PasswordRecipientInfoList prev() {
        auto proxy_result = vscf_password_recipient_info_list_prev(c_ctx_);
        return PasswordRecipientInfoList(vscf_password_recipient_info_list_shallow_copy(const_cast<vscf_password_recipient_info_list_t*>(proxy_result)));
    }

    /// Remove all items.
    void clear() {
        vscf_password_recipient_info_list_clear(c_ctx_);
    }

private:
    vscf_password_recipient_info_list_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
