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
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/group_msg_type.hpp>

struct vscf_group_session_message_t;

namespace virgil::crypto::foundation {

/// Class represents group session message
class GroupSessionMessage {
public:
    GroupSessionMessage();
    /// Adopt ownership of an existing C handle.
    explicit GroupSessionMessage(vscf_group_session_message_t* c_ctx) noexcept;
    GroupSessionMessage(const GroupSessionMessage& other);
    GroupSessionMessage(GroupSessionMessage&& other) noexcept;
    GroupSessionMessage& operator=(const GroupSessionMessage& other);
    GroupSessionMessage& operator=(GroupSessionMessage&& other) noexcept;
    ~GroupSessionMessage();

    /// The underlying concrete C handle (non-owning).
    vscf_group_session_message_t* c_ctx() const noexcept;

    /// Max message len
    static constexpr std::size_t MAX_MESSAGE_LEN = 30188;

    /// Message version
    static constexpr std::size_t MESSAGE_VERSION = 1;

    /// Returns message type.
    GroupMsgType get_type() const;

    /// Returns session id.
    /// This method should be called only for group info type.
    std::vector<uint8_t> get_session_id() const;

    /// Returns message epoch.
    uint32_t get_epoch() const;

    /// Buffer len to serialize this class.
    std::size_t serialize_len() const;

    /// Serializes instance.
    std::vector<uint8_t> serialize() const;

    /// Deserializes instance.
    static tl::expected<GroupSessionMessage, Error> deserialize(std::span<const uint8_t> input);

private:
    vscf_group_session_message_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
