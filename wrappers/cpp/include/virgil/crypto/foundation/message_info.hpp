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
#include <memory>
#include <virgil/crypto/foundation/error.hpp>

struct vscf_message_info_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class FooterInfo;
class KekRecipientInfoList;
class KeyRecipientInfoList;
class MessageInfoCustomParams;
class PasswordRecipientInfoList;

/// Handle information about an encrypted message and algorithms
/// that was used for encryption.
class MessageInfo {
public:
    MessageInfo();
    /// Adopt ownership of an existing C handle.
    explicit MessageInfo(vscf_message_info_t* c_ctx) noexcept;
    MessageInfo(const MessageInfo& other);
    MessageInfo(MessageInfo&& other) noexcept;
    MessageInfo& operator=(const MessageInfo& other);
    MessageInfo& operator=(MessageInfo&& other) noexcept;
    ~MessageInfo();

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_t* c_ctx() const noexcept;

    /// Return information about algorithm that was used for the data encryption.
    std::unique_ptr<AlgInfo> data_encryption_alg_info() const;

    /// Return list with a "key recipient info" elements.
    KeyRecipientInfoList key_recipient_info_list() const;

    /// Return list with a "password recipient info" elements.
    PasswordRecipientInfoList password_recipient_info_list() const;

    /// Return list with a "kek recipient info" elements.
    KekRecipientInfoList kek_recipient_info_list() const;

    /// Return true if message info contains at least one custom param.
    bool has_custom_params() const;

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    /// If custom params object was not set then new empty object is created.
    MessageInfoCustomParams custom_params();

    /// Return true if cipher kdf alg info exists.
    bool has_cipher_kdf_alg_info() const;

    /// Return cipher kdf alg info.
    std::unique_ptr<AlgInfo> cipher_kdf_alg_info() const;

    /// Return true if cipher padding alg info exists.
    bool has_cipher_padding_alg_info() const;

    /// Return cipher padding alg info.
    std::unique_ptr<AlgInfo> cipher_padding_alg_info() const;

    /// Return true if footer info exists.
    bool has_footer_info() const;

    /// Return footer info.
    FooterInfo footer_info() const;

    /// Remove all infos.
    void clear();

private:
    vscf_message_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
