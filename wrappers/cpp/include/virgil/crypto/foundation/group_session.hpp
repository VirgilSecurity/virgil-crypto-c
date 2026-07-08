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

struct vscf_group_session_t;

namespace virgil::crypto::foundation {

class GroupSessionMessage;
class GroupSessionTicket;
class PrivateKey;
class PublicKey;
class Random;

/// Group chat encryption session.
class GroupSession {
public:
    GroupSession();
    /// Adopt ownership of an existing C handle.
    explicit GroupSession(vscf_group_session_t* c_ctx) noexcept;
    GroupSession(const GroupSession& other);
    GroupSession(GroupSession&& other) noexcept;
    GroupSession& operator=(const GroupSession& other);
    GroupSession& operator=(GroupSession&& other) noexcept;
    ~GroupSession();

    /// The underlying concrete C handle (non-owning).
    vscf_group_session_t* c_ctx() const noexcept;

    /// Sender id len
    static constexpr std::size_t SENDER_ID_LEN = 32;

    /// Max plain text len
    static constexpr std::size_t MAX_PLAIN_TEXT_LEN = 30000;

    /// Max epochs count
    static constexpr std::size_t MAX_EPOCHS_COUNT = 50;

    /// Salt size
    static constexpr std::size_t SALT_SIZE = 32;

    void set_rng(const Random& rng);

    /// Returns current epoch.
    uint32_t get_current_epoch() const;

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    tl::expected<void, Error> setup_defaults();

    /// Returns session id.
    std::vector<uint8_t> get_session_id() const;

    /// Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    /// Epoch message should be encrypted and signed by trusted group chat member (admin).
    tl::expected<void, Error> add_epoch(const GroupSessionMessage& message);

    /// Encrypts data
    tl::expected<GroupSessionMessage, Error> encrypt(std::span<const uint8_t> plain_text, const PrivateKey& private_key);

    /// Calculates size of buffer sufficient to store decrypted message
    std::size_t decrypt_len(const GroupSessionMessage& message);

    /// Decrypts message
    tl::expected<std::vector<uint8_t>, Error> decrypt(const GroupSessionMessage& message, const PublicKey& public_key);

    /// Creates ticket with new key for removing participants or proactive to rotate encryption key.
    tl::expected<GroupSessionTicket, Error> create_group_ticket() const;

private:
    vscf_group_session_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
