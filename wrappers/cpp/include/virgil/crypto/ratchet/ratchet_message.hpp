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
#include <virgil/crypto/ratchet/vscr_ratchet_message.h>
#include <virgil/crypto/ratchet/error.hpp>
#include <virgil/crypto/ratchet/msg_type.hpp>

namespace virgil::crypto::ratchet {

/// Class represents ratchet message
class RatchetMessage {
public:
    RatchetMessage() : c_ctx_(vscr_ratchet_message_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit RatchetMessage(vscr_ratchet_message_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    RatchetMessage(const RatchetMessage& other) : c_ctx_(vscr_ratchet_message_shallow_copy(other.c_ctx_)) {}
    RatchetMessage(RatchetMessage&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    RatchetMessage& operator=(const RatchetMessage& other) {
        if (this != &other) {
            vscr_ratchet_message_delete(c_ctx_);
            c_ctx_ = vscr_ratchet_message_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    RatchetMessage& operator=(RatchetMessage&& other) noexcept {
        if (this != &other) {
            vscr_ratchet_message_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~RatchetMessage() { vscr_ratchet_message_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscr_ratchet_message_t* c_ctx() const noexcept { return c_ctx_; }

    /// Returns message type.
    MsgType get_type() {
        auto proxy_result = vscr_ratchet_message_get_type(c_ctx_);
        return static_cast<MsgType>(proxy_result);
    }

    /// Returns message counter in current asymmetric ratchet round.
    uint32_t get_counter() {
        auto proxy_result = vscr_ratchet_message_get_counter(c_ctx_);
        return proxy_result;
    }

    /// Returns long-term public key, if message is prekey message.
    std::vector<uint8_t> get_sender_identity_key_id() {
        auto proxy_result = vscr_ratchet_message_get_sender_identity_key_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Returns long-term public key, if message is prekey message.
    std::vector<uint8_t> get_receiver_identity_key_id() {
        auto proxy_result = vscr_ratchet_message_get_receiver_identity_key_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Returns long-term public key, if message is prekey message.
    std::vector<uint8_t> get_receiver_long_term_key_id() {
        auto proxy_result = vscr_ratchet_message_get_receiver_long_term_key_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
    std::vector<uint8_t> get_receiver_one_time_key_id() {
        auto proxy_result = vscr_ratchet_message_get_receiver_one_time_key_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Buffer len to serialize this class.
    std::size_t serialize_len() {
        auto proxy_result = vscr_ratchet_message_serialize_len(c_ctx_);
        return proxy_result;
    }

    /// Serializes instance.
    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> output(this->serialize_len());
        vsc_buffer_t* output_buf = vsc_buffer_new();
        vsc_buffer_use(output_buf, output.data(), output.size());
        vscr_ratchet_message_serialize(c_ctx_, output_buf);
        output.resize(vsc_buffer_len(output_buf));
        vsc_buffer_delete(output_buf);
        return output;
    }

    /// Deserializes instance.
    static tl::expected<RatchetMessage, Error> deserialize(std::span<const uint8_t> input) {
        vscr_error_t error;
        vscr_error_reset(&error);
        auto proxy_result = vscr_ratchet_message_deserialize(vsc_data(input.data(), input.size()), &error);
        if (vscr_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscr_error_status(&error)));
        }
        return RatchetMessage(proxy_result);
    }

private:
    vscr_ratchet_message_t* c_ctx_;
};

}  // namespace virgil::crypto::ratchet
