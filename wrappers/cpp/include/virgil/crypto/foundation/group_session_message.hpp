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
#include <virgil/crypto/foundation/vscf_group_session_message.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/group_msg_type.hpp>

namespace virgil::crypto::foundation {

/// Class represents group session message
class GroupSessionMessage {
public:
    GroupSessionMessage() : c_ctx_(vscf_group_session_message_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit GroupSessionMessage(vscf_group_session_message_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    GroupSessionMessage(const GroupSessionMessage& other) : c_ctx_(vscf_group_session_message_shallow_copy(other.c_ctx_)) {}
    GroupSessionMessage(GroupSessionMessage&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    GroupSessionMessage& operator=(const GroupSessionMessage& other) {
        if (this != &other) {
            vscf_group_session_message_delete(c_ctx_);
            c_ctx_ = vscf_group_session_message_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    GroupSessionMessage& operator=(GroupSessionMessage&& other) noexcept {
        if (this != &other) {
            vscf_group_session_message_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~GroupSessionMessage() { vscf_group_session_message_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_group_session_message_t* c_ctx() const noexcept { return c_ctx_; }

    /// Max message len
    static constexpr std::size_t MAX_MESSAGE_LEN = 30188;

    /// Message version
    static constexpr std::size_t MESSAGE_VERSION = 1;

    /// Returns message type.
    GroupMsgType get_type() {
        auto proxy_result = vscf_group_session_message_get_type(c_ctx_);
        return static_cast<GroupMsgType>(proxy_result);
    }

    /// Returns session id.
    /// This method should be called only for group info type.
    std::vector<uint8_t> get_session_id() {
        auto proxy_result = vscf_group_session_message_get_session_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Returns message epoch.
    uint32_t get_epoch() {
        auto proxy_result = vscf_group_session_message_get_epoch(c_ctx_);
        return proxy_result;
    }

    /// Buffer len to serialize this class.
    std::size_t serialize_len() {
        auto proxy_result = vscf_group_session_message_serialize_len(c_ctx_);
        return proxy_result;
    }

    /// Serializes instance.
    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> output(this->serialize_len());
        vsc_buffer_t* output_buf = vsc_buffer_new();
        vsc_buffer_use(output_buf, output.data(), output.size());
        vscf_group_session_message_serialize(c_ctx_, output_buf);
        output.resize(vsc_buffer_len(output_buf));
        vsc_buffer_delete(output_buf);
        return output;
    }

    /// Deserializes instance.
    static tl::expected<GroupSessionMessage, Error> deserialize(std::span<const uint8_t> input) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_group_session_message_deserialize(vsc_data(input.data(), input.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return GroupSessionMessage(proxy_result);
    }

private:
    vscf_group_session_message_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
