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
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/ratchet/vscr_ratchet_session.h>
#include <virgil/crypto/ratchet/error.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/ratchet/ratchet_message.hpp>

namespace virgil::crypto::ratchet {

/// Class for ratchet session between 2 participants
class RatchetSession {
public:
    RatchetSession() : c_ctx_(vscr_ratchet_session_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit RatchetSession(vscr_ratchet_session_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    RatchetSession(const RatchetSession& other) : c_ctx_(vscr_ratchet_session_shallow_copy(other.c_ctx_)) {}
    RatchetSession(RatchetSession&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    RatchetSession& operator=(const RatchetSession& other) {
        if (this != &other) {
            vscr_ratchet_session_delete(c_ctx_);
            c_ctx_ = vscr_ratchet_session_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    RatchetSession& operator=(RatchetSession&& other) noexcept {
        if (this != &other) {
            vscr_ratchet_session_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~RatchetSession() { vscr_ratchet_session_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscr_ratchet_session_t* c_ctx() const noexcept { return c_ctx_; }

    void set_rng(const virgil::crypto::foundation::Random& rng) {
        vscr_ratchet_session_release_rng(c_ctx_);
        vscr_ratchet_session_use_rng(c_ctx_, rng.impl());
    }

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    tl::expected<void, Error> setup_defaults() {
        const vscr_status_t status = vscr_ratchet_session_setup_defaults(c_ctx_);
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Initiates session
    tl::expected<void, Error> initiate(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id, const virgil::crypto::foundation::PublicKey& receiver_one_time_public_key, std::span<const uint8_t> receiver_one_time_key_id) {
        const vscr_status_t status = vscr_ratchet_session_initiate(c_ctx_, sender_identity_private_key.impl(), vsc_data(sender_identity_key_id.data(), sender_identity_key_id.size()), receiver_identity_public_key.impl(), vsc_data(receiver_identity_key_id.data(), receiver_identity_key_id.size()), receiver_long_term_public_key.impl(), vsc_data(receiver_long_term_key_id.data(), receiver_long_term_key_id.size()), receiver_one_time_public_key.impl(), vsc_data(receiver_one_time_key_id.data(), receiver_one_time_key_id.size()));
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Initiates session
    tl::expected<void, Error> initiate_no_one_time_key(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id) {
        const vscr_status_t status = vscr_ratchet_session_initiate_no_one_time_key(c_ctx_, sender_identity_private_key.impl(), vsc_data(sender_identity_key_id.data(), sender_identity_key_id.size()), receiver_identity_public_key.impl(), vsc_data(receiver_identity_key_id.data(), receiver_identity_key_id.size()), receiver_long_term_public_key.impl(), vsc_data(receiver_long_term_key_id.data(), receiver_long_term_key_id.size()));
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Responds to session initiation
    tl::expected<void, Error> respond(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const virgil::crypto::foundation::PrivateKey& receiver_one_time_private_key, const RatchetMessage& message) {
        const vscr_status_t status = vscr_ratchet_session_respond(c_ctx_, sender_identity_public_key.impl(), receiver_identity_private_key.impl(), receiver_long_term_private_key.impl(), receiver_one_time_private_key.impl(), message.c_ctx());
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Responds to session initiation
    tl::expected<void, Error> respond_no_one_time_key(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const RatchetMessage& message) {
        const vscr_status_t status = vscr_ratchet_session_respond_no_one_time_key(c_ctx_, sender_identity_public_key.impl(), receiver_identity_private_key.impl(), receiver_long_term_private_key.impl(), message.c_ctx());
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Returns flag that indicates is this session was initiated or responded
    bool is_initiator() {
        auto proxy_result = vscr_ratchet_session_is_initiator(c_ctx_);
        return proxy_result;
    }

    /// Returns flag that indicates if session is post-quantum
    bool is_pqc_enabled() {
        auto proxy_result = vscr_ratchet_session_is_pqc_enabled(c_ctx_);
        return proxy_result;
    }

    /// Returns true if at least 1 response was successfully decrypted, false - otherwise
    bool received_first_response() {
        auto proxy_result = vscr_ratchet_session_received_first_response(c_ctx_);
        return proxy_result;
    }

    /// Returns true if receiver had one time public key
    bool receiver_has_one_time_public_key() {
        auto proxy_result = vscr_ratchet_session_receiver_has_one_time_public_key(c_ctx_);
        return proxy_result;
    }

    /// Encrypts data
    tl::expected<RatchetMessage, Error> encrypt(std::span<const uint8_t> plain_text) {
        vscr_error_t error;
        vscr_error_reset(&error);
        auto proxy_result = vscr_ratchet_session_encrypt(c_ctx_, vsc_data(plain_text.data(), plain_text.size()), &error);
        if (vscr_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
        }
        return RatchetMessage(proxy_result);
    }

    /// Calculates size of buffer sufficient to store decrypted message
    std::size_t decrypt_len(const RatchetMessage& message) {
        auto proxy_result = vscr_ratchet_session_decrypt_len(c_ctx_, message.c_ctx());
        return proxy_result;
    }

    /// Decrypts message
    tl::expected<std::vector<uint8_t>, Error> decrypt(const RatchetMessage& message) {
        std::vector<uint8_t> plain_text(this->decrypt_len(message));
        vsc_buffer_t* plain_text_buf = vsc_buffer_new();
        vsc_buffer_use(plain_text_buf, plain_text.data(), plain_text.size());
        const vscr_status_t status = vscr_ratchet_session_decrypt(c_ctx_, message.c_ctx(), plain_text_buf);
        plain_text.resize(vsc_buffer_len(plain_text_buf));
        vsc_buffer_delete(plain_text_buf);
        if (status != vscr_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return plain_text;
    }

    /// Serializes session to buffer
    std::vector<uint8_t> serialize() {
        auto proxy_result = vscr_ratchet_session_serialize(c_ctx_);
        std::vector<uint8_t> result(vsc_buffer_bytes(proxy_result), vsc_buffer_bytes(proxy_result) + vsc_buffer_len(proxy_result));
        vsc_buffer_delete(proxy_result);
        return result;
    }

    /// Deserializes session from buffer.
    /// NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    static tl::expected<RatchetSession, Error> deserialize(std::span<const uint8_t> input) {
        vscr_error_t error;
        vscr_error_reset(&error);
        auto proxy_result = vscr_ratchet_session_deserialize(vsc_data(input.data(), input.size()), &error);
        if (vscr_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
        }
        return RatchetSession(proxy_result);
    }

private:
    vscr_ratchet_session_t* c_ctx_;
};

}  // namespace virgil::crypto::ratchet
