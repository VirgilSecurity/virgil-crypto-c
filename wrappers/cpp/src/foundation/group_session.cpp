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

#include <virgil/crypto/foundation/group_session.hpp>
#include <virgil/crypto/foundation/vscf_group_session.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/group_session_message.hpp>
#include <virgil/crypto/foundation/group_session_ticket.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

GroupSession::GroupSession() : c_ctx_(vscf_group_session_new()) {}

GroupSession::GroupSession(vscf_group_session_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

GroupSession::GroupSession(const GroupSession& other) : c_ctx_(vscf_group_session_shallow_copy(other.c_ctx_)) {}

GroupSession::GroupSession(GroupSession&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

GroupSession& GroupSession::operator=(const GroupSession& other) {
    if (this != &other) {
        vscf_group_session_delete(c_ctx_);
        c_ctx_ = vscf_group_session_shallow_copy(other.c_ctx_);
    }
    return *this;
}

GroupSession& GroupSession::operator=(GroupSession&& other) noexcept {
    if (this != &other) {
        vscf_group_session_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

GroupSession::~GroupSession() { vscf_group_session_delete(c_ctx_); }

vscf_group_session_t* GroupSession::c_ctx() const noexcept { return c_ctx_; }

void GroupSession::set_rng(const Random& rng) {
    vscf_group_session_release_rng(c_ctx_);
    vscf_group_session_use_rng(c_ctx_, rng.impl());
}

uint32_t GroupSession::get_current_epoch() const {
    auto proxy_result = vscf_group_session_get_current_epoch(c_ctx_);
    return proxy_result;
}

tl::expected<void, Error> GroupSession::setup_defaults() {
    const vscf_status_t status = vscf_group_session_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::vector<uint8_t> GroupSession::get_session_id() const {
    auto proxy_result = vscf_group_session_get_session_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

tl::expected<void, Error> GroupSession::add_epoch(const GroupSessionMessage& message) {
    const vscf_status_t status = vscf_group_session_add_epoch(c_ctx_, message.c_ctx());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<GroupSessionMessage, Error> GroupSession::encrypt(std::span<const uint8_t> plain_text, const PrivateKey& private_key) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_group_session_encrypt(c_ctx_, plain_text.empty() ? vsc_data_empty() : vsc_data(plain_text.data(), plain_text.size()), private_key.impl(), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return GroupSessionMessage(proxy_result);
}

std::size_t GroupSession::decrypt_len(const GroupSessionMessage& message) {
    auto proxy_result = vscf_group_session_decrypt_len(c_ctx_, message.c_ctx());
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> GroupSession::decrypt(const GroupSessionMessage& message, const PublicKey& public_key) {
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

tl::expected<GroupSessionTicket, Error> GroupSession::create_group_ticket() const {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_group_session_create_group_ticket(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return GroupSessionTicket(proxy_result);
}

}  // namespace virgil::crypto::foundation
