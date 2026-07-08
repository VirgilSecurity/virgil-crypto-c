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

#include <virgil/crypto/foundation/group_session_ticket.hpp>
#include <virgil/crypto/foundation/vscf_group_session_ticket.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/group_session_message.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

GroupSessionTicket::GroupSessionTicket() : c_ctx_(vscf_group_session_ticket_new()) {}

GroupSessionTicket::GroupSessionTicket(vscf_group_session_ticket_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

GroupSessionTicket::GroupSessionTicket(const GroupSessionTicket& other) : c_ctx_(vscf_group_session_ticket_shallow_copy(other.c_ctx_)) {}

GroupSessionTicket::GroupSessionTicket(GroupSessionTicket&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

GroupSessionTicket& GroupSessionTicket::operator=(const GroupSessionTicket& other) {
    if (this != &other) {
        vscf_group_session_ticket_delete(c_ctx_);
        c_ctx_ = vscf_group_session_ticket_shallow_copy(other.c_ctx_);
    }
    return *this;
}

GroupSessionTicket& GroupSessionTicket::operator=(GroupSessionTicket&& other) noexcept {
    if (this != &other) {
        vscf_group_session_ticket_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

GroupSessionTicket::~GroupSessionTicket() { vscf_group_session_ticket_delete(c_ctx_); }

vscf_group_session_ticket_t* GroupSessionTicket::c_ctx() const noexcept { return c_ctx_; }

void GroupSessionTicket::set_rng(const Random& rng) {
    vscf_group_session_ticket_release_rng(c_ctx_);
    vscf_group_session_ticket_use_rng(c_ctx_, rng.impl());
}

tl::expected<void, Error> GroupSessionTicket::setup_defaults() {
    const vscf_status_t status = vscf_group_session_ticket_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> GroupSessionTicket::setup_ticket_as_new(std::span<const uint8_t> session_id) {
    const vscf_status_t status = vscf_group_session_ticket_setup_ticket_as_new(c_ctx_, vsc_data(session_id.data(), session_id.size()));
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

GroupSessionMessage GroupSessionTicket::get_ticket_message() const {
    auto proxy_result = vscf_group_session_ticket_get_ticket_message(c_ctx_);
    return GroupSessionMessage(vscf_group_session_message_shallow_copy(const_cast<vscf_group_session_message_t*>(proxy_result)));
}

}  // namespace virgil::crypto::foundation
