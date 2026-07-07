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
#include <virgil/crypto/foundation/vscf_message_info_editor.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Add and/or remove recipients and it's parameters within message info.
///
/// Usage:
/// 1. Unpack binary message info that was obtained from RecipientCipher.
/// 2. Add and/or remove key recipients.
/// 3. Pack MessagInfo to the binary data.
class MessageInfoEditor {
public:
    MessageInfoEditor() : c_ctx_(vscf_message_info_editor_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoEditor(vscf_message_info_editor_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MessageInfoEditor(const MessageInfoEditor& other) : c_ctx_(vscf_message_info_editor_shallow_copy(other.c_ctx_)) {}
    MessageInfoEditor(MessageInfoEditor&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MessageInfoEditor& operator=(const MessageInfoEditor& other) {
        if (this != &other) {
            vscf_message_info_editor_delete(c_ctx_);
            c_ctx_ = vscf_message_info_editor_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MessageInfoEditor& operator=(MessageInfoEditor&& other) noexcept {
        if (this != &other) {
            vscf_message_info_editor_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MessageInfoEditor() { vscf_message_info_editor_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_editor_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const Random& random) {
        vscf_message_info_editor_release_random(c_ctx_);
        vscf_message_info_editor_use_random(c_ctx_, random.impl());
    }

    /// Set dependencies to it's defaults.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_message_info_editor_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Unpack serialized message info.
    ///
    /// Note that recipients can only be removed but not added.
    /// Note, use "unlock" method to be able to add new recipients as well.
    tl::expected<void, Error> unpack(std::span<const uint8_t> message_info_data) {
        const vscf_status_t status = vscf_message_info_editor_unpack(c_ctx_, vsc_data(message_info_data.data(), message_info_data.size()));
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Decrypt encryption key this allows adding new recipients.
    tl::expected<void, Error> unlock(std::span<const uint8_t> owner_recipient_id, const PrivateKey& owner_private_key) {
        const vscf_status_t status = vscf_message_info_editor_unlock(c_ctx_, vsc_data(owner_recipient_id.data(), owner_recipient_id.size()), owner_private_key.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Add recipient defined with id and public key.
    tl::expected<void, Error> add_key_recipient(std::span<const uint8_t> recipient_id, const PublicKey& public_key) {
        const vscf_status_t status = vscf_message_info_editor_add_key_recipient(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()), public_key.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Remove recipient with a given id.
    /// Return false if recipient with given id was not found.
    bool remove_key_recipient(std::span<const uint8_t> recipient_id) {
        auto proxy_result = vscf_message_info_editor_remove_key_recipient(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()));
        return proxy_result;
    }

    /// Remove all existent recipients.
    void remove_all() {
        vscf_message_info_editor_remove_all(c_ctx_);
    }

    /// Return length of serialized message info.
    /// Actual length can be obtained right after applying changes.
    std::size_t packed_len() {
        auto proxy_result = vscf_message_info_editor_packed_len(c_ctx_);
        return proxy_result;
    }

    /// Return serialized message info.
    /// Precondition: this method can be called after "apply".
    std::vector<uint8_t> pack() {
        std::vector<uint8_t> message_info(this->packed_len());
        vsc_buffer_t* message_info_buf = vsc_buffer_new();
        vsc_buffer_use(message_info_buf, message_info.data(), message_info.size());
        vscf_message_info_editor_pack(c_ctx_, message_info_buf);
        message_info.resize(vsc_buffer_len(message_info_buf));
        vsc_buffer_delete(message_info_buf);
        return message_info;
    }

private:
    vscf_message_info_editor_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
