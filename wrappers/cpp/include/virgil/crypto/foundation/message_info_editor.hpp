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

struct vscf_message_info_editor_t;

namespace virgil::crypto::foundation {

class PrivateKey;
class PublicKey;
class Random;

/// Add and/or remove recipients and it's parameters within message info.
///
/// Usage:
/// 1. Unpack binary message info that was obtained from RecipientCipher.
/// 2. Add and/or remove key recipients.
/// 3. Pack MessagInfo to the binary data.
class MessageInfoEditor {
public:
    MessageInfoEditor();
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoEditor(vscf_message_info_editor_t* c_ctx) noexcept;
    MessageInfoEditor(const MessageInfoEditor& other);
    MessageInfoEditor(MessageInfoEditor&& other) noexcept;
    MessageInfoEditor& operator=(const MessageInfoEditor& other);
    MessageInfoEditor& operator=(MessageInfoEditor&& other) noexcept;
    ~MessageInfoEditor();

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_editor_t* c_ctx() const noexcept;

    void set_random(const Random& random);

    /// Set dependencies to it's defaults.
    tl::expected<void, Error> setup_defaults();

    /// Unpack serialized message info.
    ///
    /// Note that recipients can only be removed but not added.
    /// Note, use "unlock" method to be able to add new recipients as well.
    tl::expected<void, Error> unpack(std::span<const uint8_t> message_info_data);

    /// Decrypt encryption key this allows adding new recipients.
    tl::expected<void, Error> unlock(std::span<const uint8_t> owner_recipient_id, const PrivateKey& owner_private_key);

    /// Add recipient defined with id and public key.
    tl::expected<void, Error> add_key_recipient(std::span<const uint8_t> recipient_id, const PublicKey& public_key);

    /// Remove recipient with a given id.
    /// Return false if recipient with given id was not found.
    bool remove_key_recipient(std::span<const uint8_t> recipient_id);

    /// Remove all existent recipients.
    void remove_all();

    /// Return length of serialized message info.
    /// Actual length can be obtained right after applying changes.
    std::size_t packed_len() const;

    /// Return serialized message info.
    /// Precondition: this method can be called after "apply".
    std::vector<uint8_t> pack();

private:
    vscf_message_info_editor_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
