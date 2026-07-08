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
#include <virgil/crypto/ratchet/error.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vscr_ratchet_session_t;

namespace virgil::crypto::ratchet {

class RatchetMessage;

/// Class for ratchet session between 2 participants
class RatchetSession {
public:
    RatchetSession();
    /// Adopt ownership of an existing C handle.
    explicit RatchetSession(vscr_ratchet_session_t* c_ctx) noexcept;
    RatchetSession(const RatchetSession& other);
    RatchetSession(RatchetSession&& other) noexcept;
    RatchetSession& operator=(const RatchetSession& other);
    RatchetSession& operator=(RatchetSession&& other) noexcept;
    ~RatchetSession();

    /// The underlying concrete C handle (non-owning).
    vscr_ratchet_session_t* c_ctx() const noexcept;

    void set_rng(const virgil::crypto::foundation::Random& rng);

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    tl::expected<void, Error> setup_defaults();

    /// Initiates session
    tl::expected<void, Error> initiate(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id, const virgil::crypto::foundation::PublicKey& receiver_one_time_public_key, std::span<const uint8_t> receiver_one_time_key_id);

    /// Initiates session
    tl::expected<void, Error> initiate_no_one_time_key(const virgil::crypto::foundation::PrivateKey& sender_identity_private_key, std::span<const uint8_t> sender_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_identity_public_key, std::span<const uint8_t> receiver_identity_key_id, const virgil::crypto::foundation::PublicKey& receiver_long_term_public_key, std::span<const uint8_t> receiver_long_term_key_id);

    /// Responds to session initiation
    tl::expected<void, Error> respond(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const virgil::crypto::foundation::PrivateKey& receiver_one_time_private_key, const RatchetMessage& message);

    /// Responds to session initiation
    tl::expected<void, Error> respond_no_one_time_key(const virgil::crypto::foundation::PublicKey& sender_identity_public_key, const virgil::crypto::foundation::PrivateKey& receiver_identity_private_key, const virgil::crypto::foundation::PrivateKey& receiver_long_term_private_key, const RatchetMessage& message);

    /// Returns flag that indicates is this session was initiated or responded
    bool is_initiator();

    /// Returns flag that indicates if session is post-quantum
    bool is_pqc_enabled();

    /// Returns true if at least 1 response was successfully decrypted, false - otherwise
    bool received_first_response();

    /// Returns true if receiver had one time public key
    bool receiver_has_one_time_public_key();

    /// Encrypts data
    tl::expected<RatchetMessage, Error> encrypt(std::span<const uint8_t> plain_text);

    /// Calculates size of buffer sufficient to store decrypted message
    std::size_t decrypt_len(const RatchetMessage& message);

    /// Decrypts message
    tl::expected<std::vector<uint8_t>, Error> decrypt(const RatchetMessage& message);

    /// Serializes session to buffer
    std::vector<uint8_t> serialize();

    /// Deserializes session from buffer.
    /// NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    static tl::expected<RatchetSession, Error> deserialize(std::span<const uint8_t> input);

private:
    vscr_ratchet_session_t* c_ctx_;
};

}  // namespace virgil::crypto::ratchet
