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

#include <virgil/crypto/ratchet/ratchet_message.hpp>
#include <virgil/crypto/ratchet/vscr_ratchet_message.h>
#include <virgil/crypto/ratchet/msg_type.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::ratchet {

RatchetMessage::RatchetMessage() : c_ctx_(vscr_ratchet_message_new()) {}

RatchetMessage::RatchetMessage(vscr_ratchet_message_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

RatchetMessage::RatchetMessage(const RatchetMessage& other) : c_ctx_(vscr_ratchet_message_shallow_copy(other.c_ctx_)) {}

RatchetMessage::RatchetMessage(RatchetMessage&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

RatchetMessage& RatchetMessage::operator=(const RatchetMessage& other) {
    if (this != &other) {
        vscr_ratchet_message_delete(c_ctx_);
        c_ctx_ = vscr_ratchet_message_shallow_copy(other.c_ctx_);
    }
    return *this;
}

RatchetMessage& RatchetMessage::operator=(RatchetMessage&& other) noexcept {
    if (this != &other) {
        vscr_ratchet_message_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

RatchetMessage::~RatchetMessage() { vscr_ratchet_message_delete(c_ctx_); }

vscr_ratchet_message_t* RatchetMessage::c_ctx() const noexcept { return c_ctx_; }

MsgType RatchetMessage::get_type() const {
    auto proxy_result = vscr_ratchet_message_get_type(c_ctx_);
    return static_cast<MsgType>(proxy_result);
}

uint32_t RatchetMessage::get_counter() const {
    auto proxy_result = vscr_ratchet_message_get_counter(c_ctx_);
    return proxy_result;
}

std::vector<uint8_t> RatchetMessage::get_sender_identity_key_id() {
    auto proxy_result = vscr_ratchet_message_get_sender_identity_key_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> RatchetMessage::get_receiver_identity_key_id() {
    auto proxy_result = vscr_ratchet_message_get_receiver_identity_key_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> RatchetMessage::get_receiver_long_term_key_id() {
    auto proxy_result = vscr_ratchet_message_get_receiver_long_term_key_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> RatchetMessage::get_receiver_one_time_key_id() {
    auto proxy_result = vscr_ratchet_message_get_receiver_one_time_key_id(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::size_t RatchetMessage::serialize_len() const {
    auto proxy_result = vscr_ratchet_message_serialize_len(c_ctx_);
    return proxy_result;
}

std::vector<uint8_t> RatchetMessage::serialize() const {
    std::vector<uint8_t> output(this->serialize_len());
    vsc_buffer_t output_buf;
    vsc_buffer_init(&output_buf);
    vsc_buffer_use(&output_buf, output.data(), output.size());
    vscr_ratchet_message_serialize(c_ctx_, &output_buf);
    output.resize(vsc_buffer_len(&output_buf));
    vsc_buffer_cleanup(&output_buf);
    return output;
}

tl::expected<RatchetMessage, Error> RatchetMessage::deserialize(std::span<const uint8_t> input) {
    vscr_error_t error;
    vscr_error_reset(&error);
    auto proxy_result = vscr_ratchet_message_deserialize(input.empty() ? vsc_data_empty() : vsc_data(input.data(), input.size()), &error);
    if (vscr_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
    }
    return RatchetMessage(proxy_result);
}

}  // namespace virgil::crypto::ratchet
