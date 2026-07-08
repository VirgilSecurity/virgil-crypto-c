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

#include <virgil/crypto/ratchet/ratchet_session.hpp>
#include <virgil/crypto/ratchet/vscr_ratchet_session.h>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/ratchet/ratchet_message.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::ratchet {

RatchetSession::RatchetSession() : c_ctx_(vscr_ratchet_session_new()) {}

RatchetSession::RatchetSession(vscr_ratchet_session_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

RatchetSession::RatchetSession(const RatchetSession& other) : c_ctx_(vscr_ratchet_session_shallow_copy(other.c_ctx_)) {}

RatchetSession::RatchetSession(RatchetSession&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

RatchetSession& RatchetSession::operator=(const RatchetSession& other) {
    if (this != &other) {
        vscr_ratchet_session_delete(c_ctx_);
        c_ctx_ = vscr_ratchet_session_shallow_copy(other.c_ctx_);
    }
    return *this;
}

RatchetSession& RatchetSession::operator=(RatchetSession&& other) noexcept {
    if (this != &other) {
        vscr_ratchet_session_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

RatchetSession::~RatchetSession() { vscr_ratchet_session_delete(c_ctx_); }

vscr_ratchet_session_t* RatchetSession::c_ctx() const noexcept { return c_ctx_; }

void RatchetSession::set_rng(const virgil::crypto::foundation::Random& rng) {
    vscr_ratchet_session_release_rng(c_ctx_);
    vscr_ratchet_session_use_rng(c_ctx_, rng.impl());
}

tl::expected<void, Error> RatchetSession::setup_defaults() {
    const vscr_status_t status = vscr_ratchet_session_setup_defaults(c_ctx_);
    if (status != vscr_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RatchetSession::initiate(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id, const virgil::crypto::foundation::PublicKey& receiver_one_time_public_key, std::span<const uint8_t> receiver_one_time_key_id) {
    const vscr_status_t status = vscr_ratchet_session_initiate(c_ctx_, sender_identity_private_key.impl(), sender_identity_key_id.empty() ? vsc_data_empty() : vsc_data(sender_identity_key_id.data(), sender_identity_key_id.size()), receiver_identity_public_key.impl(), receiver_identity_key_id.empty() ? vsc_data_empty() : vsc_data(receiver_identity_key_id.data(), receiver_identity_key_id.size()), receiver_long_term_public_key.impl(), receiver_long_term_key_id.empty() ? vsc_data_empty() : vsc_data(receiver_long_term_key_id.data(), receiver_long_term_key_id.size()), receiver_one_time_public_key.impl(), receiver_one_time_key_id.empty() ? vsc_data_empty() : vsc_data(receiver_one_time_key_id.data(), receiver_one_time_key_id.size()));
    if (status != vscr_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RatchetSession::initiate_no_one_time_key(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id) {
    const vscr_status_t status = vscr_ratchet_session_initiate_no_one_time_key(c_ctx_, sender_identity_private_key.impl(), sender_identity_key_id.empty() ? vsc_data_empty() : vsc_data(sender_identity_key_id.data(), sender_identity_key_id.size()), receiver_identity_public_key.impl(), receiver_identity_key_id.empty() ? vsc_data_empty() : vsc_data(receiver_identity_key_id.data(), receiver_identity_key_id.size()), receiver_long_term_public_key.impl(), receiver_long_term_key_id.empty() ? vsc_data_empty() : vsc_data(receiver_long_term_key_id.data(), receiver_long_term_key_id.size()));
    if (status != vscr_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RatchetSession::respond(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const virgil::crypto::foundation::PrivateKey& receiver_one_time_private_key, const RatchetMessage& message) {
    const vscr_status_t status = vscr_ratchet_session_respond(c_ctx_, sender_identity_public_key.impl(), receiver_identity_private_key.impl(), receiver_long_term_private_key.impl(), receiver_one_time_private_key.impl(), message.c_ctx());
    if (status != vscr_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RatchetSession::respond_no_one_time_key(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const RatchetMessage& message) {
    const vscr_status_t status = vscr_ratchet_session_respond_no_one_time_key(c_ctx_, sender_identity_public_key.impl(), receiver_identity_private_key.impl(), receiver_long_term_private_key.impl(), message.c_ctx());
    if (status != vscr_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

bool RatchetSession::is_initiator() {
    auto proxy_result = vscr_ratchet_session_is_initiator(c_ctx_);
    return proxy_result;
}

bool RatchetSession::is_pqc_enabled() {
    auto proxy_result = vscr_ratchet_session_is_pqc_enabled(c_ctx_);
    return proxy_result;
}

bool RatchetSession::received_first_response() {
    auto proxy_result = vscr_ratchet_session_received_first_response(c_ctx_);
    return proxy_result;
}

bool RatchetSession::receiver_has_one_time_public_key() {
    auto proxy_result = vscr_ratchet_session_receiver_has_one_time_public_key(c_ctx_);
    return proxy_result;
}

tl::expected<RatchetMessage, Error> RatchetSession::encrypt(std::span<const uint8_t> plain_text) {
    vscr_error_t error;
    vscr_error_reset(&error);
    auto proxy_result = vscr_ratchet_session_encrypt(c_ctx_, plain_text.empty() ? vsc_data_empty() : vsc_data(plain_text.data(), plain_text.size()), &error);
    if (vscr_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
    }
    return RatchetMessage(proxy_result);
}

std::size_t RatchetSession::decrypt_len(const RatchetMessage& message) {
    auto proxy_result = vscr_ratchet_session_decrypt_len(c_ctx_, message.c_ctx());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> RatchetSession::decrypt(const RatchetMessage& message) {
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

std::vector<uint8_t> RatchetSession::serialize() {
    auto proxy_result = vscr_ratchet_session_serialize(c_ctx_);
    std::vector<uint8_t> result(vsc_buffer_bytes(proxy_result), vsc_buffer_bytes(proxy_result) + vsc_buffer_len(proxy_result));
    vsc_buffer_delete(proxy_result);
    return result;
}

tl::expected<RatchetSession, Error> RatchetSession::deserialize(std::span<const uint8_t> input) {
    vscr_error_t error;
    vscr_error_reset(&error);
    auto proxy_result = vscr_ratchet_session_deserialize(input.empty() ? vsc_data_empty() : vsc_data(input.data(), input.size()), &error);
    if (vscr_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
    }
    return RatchetSession(proxy_result);
}

}  // namespace virgil::crypto::ratchet
