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
#include <virgil/crypto/foundation/vscf_group_session.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/group_session_message.hpp>
#include <virgil/crypto/foundation/group_session_ticket.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Group chat encryption session.
class GroupSession {
public:
    GroupSession() : c_ctx_(vscf_group_session_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit GroupSession(vscf_group_session_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    GroupSession(const GroupSession& other) : c_ctx_(vscf_group_session_shallow_copy(other.c_ctx_)) {}
    GroupSession(GroupSession&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    GroupSession& operator=(const GroupSession& other) {
        if (this != &other) {
            vscf_group_session_delete(c_ctx_);
            c_ctx_ = vscf_group_session_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    GroupSession& operator=(GroupSession&& other) noexcept {
        if (this != &other) {
            vscf_group_session_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~GroupSession() { vscf_group_session_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_group_session_t* c_ctx() const noexcept { return c_ctx_; }

    /// Sender id len
    static constexpr std::size_t SENDER_ID_LEN = 32;

    /// Max plain text len
    static constexpr std::size_t MAX_PLAIN_TEXT_LEN = 30000;

    /// Max epochs count
    static constexpr std::size_t MAX_EPOCHS_COUNT = 50;

    /// Salt size
    static constexpr std::size_t SALT_SIZE = 32;

    void set_rng(const Random& rng) {
        vscf_group_session_release_rng(c_ctx_);
        vscf_group_session_use_rng(c_ctx_, rng.impl());
    }

    /// Returns current epoch.
    uint32_t get_current_epoch() {
        auto proxy_result = vscf_group_session_get_current_epoch(c_ctx_);
        return proxy_result;
    }

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_group_session_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Returns session id.
    std::vector<uint8_t> get_session_id() {
        auto proxy_result = vscf_group_session_get_session_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    /// Epoch message should be encrypted and signed by trusted group chat member (admin).
    tl::expected<void, Error> add_epoch(const GroupSessionMessage& message) {
        const vscf_status_t status = vscf_group_session_add_epoch(c_ctx_, message.c_ctx());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Encrypts data
    tl::expected<GroupSessionMessage, Error> encrypt(std::span<const uint8_t> plain_text, const PrivateKey& private_key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_group_session_encrypt(c_ctx_, vsc_data(plain_text.data(), plain_text.size()), private_key.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return GroupSessionMessage(proxy_result);
    }

    /// Calculates size of buffer sufficient to store decrypted message
    std::size_t decrypt_len(const GroupSessionMessage& message) {
        auto proxy_result = vscf_group_session_decrypt_len(c_ctx_, message.c_ctx());
        return proxy_result;
    }

    /// Decrypts message
    tl::expected<std::vector<uint8_t>, Error> decrypt(const GroupSessionMessage& message, const PublicKey& public_key) {
        std::vector<uint8_t> plain_text(this->decrypt_len(message));
        vsc_buffer_t* plain_text_buf = vsc_buffer_new();
        vsc_buffer_use(plain_text_buf, plain_text.data(), plain_text.size());
        const vscf_status_t status = vscf_group_session_decrypt(c_ctx_, message.c_ctx(), public_key.impl(), plain_text_buf);
        plain_text.resize(vsc_buffer_len(plain_text_buf));
        vsc_buffer_delete(plain_text_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return plain_text;
    }

    /// Creates ticket with new key for removing participants or proactive to rotate encryption key.
    tl::expected<GroupSessionTicket, Error> create_group_ticket() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_group_session_create_group_ticket(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return GroupSessionTicket(proxy_result);
    }

private:
    vscf_group_session_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
