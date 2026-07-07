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
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_key_recipient_info.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handle information about recipient that is defined by a Public Key.
class KeyRecipientInfo {
public:
    KeyRecipientInfo() : c_ctx_(vscf_key_recipient_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit KeyRecipientInfo(vscf_key_recipient_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    KeyRecipientInfo(const KeyRecipientInfo& other) : c_ctx_(vscf_key_recipient_info_shallow_copy(other.c_ctx_)) {}
    KeyRecipientInfo(KeyRecipientInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    KeyRecipientInfo& operator=(const KeyRecipientInfo& other) {
        if (this != &other) {
            vscf_key_recipient_info_delete(c_ctx_);
            c_ctx_ = vscf_key_recipient_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    KeyRecipientInfo& operator=(KeyRecipientInfo&& other) noexcept {
        if (this != &other) {
            vscf_key_recipient_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~KeyRecipientInfo() { vscf_key_recipient_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_key_recipient_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return recipient identifier.
    std::vector<uint8_t> recipient_id() {
        auto proxy_result = vscf_key_recipient_info_recipient_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Return algorithm information that was used for encryption
    /// a data encryption key.
    std::unique_ptr<AlgInfo> key_encryption_algorithm() {
        auto proxy_result = vscf_key_recipient_info_key_encryption_algorithm(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return an encrypted data encryption key.
    std::vector<uint8_t> encrypted_key() {
        auto proxy_result = vscf_key_recipient_info_encrypted_key(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

private:
    vscf_key_recipient_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
