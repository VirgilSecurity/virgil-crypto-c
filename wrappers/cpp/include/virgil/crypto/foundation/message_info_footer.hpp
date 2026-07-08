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
#include <virgil/crypto/foundation/vscf_message_info_footer.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/signer_info_list.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handle message signatures and related information.
class MessageInfoFooter {
public:
    MessageInfoFooter() : c_ctx_(vscf_message_info_footer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoFooter(vscf_message_info_footer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MessageInfoFooter(const MessageInfoFooter& other) : c_ctx_(vscf_message_info_footer_shallow_copy(other.c_ctx_)) {}
    MessageInfoFooter(MessageInfoFooter&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MessageInfoFooter& operator=(const MessageInfoFooter& other) {
        if (this != &other) {
            vscf_message_info_footer_delete(c_ctx_);
            c_ctx_ = vscf_message_info_footer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MessageInfoFooter& operator=(MessageInfoFooter&& other) noexcept {
        if (this != &other) {
            vscf_message_info_footer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MessageInfoFooter() { vscf_message_info_footer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_footer_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return true if at least one signer info presents.
    bool has_signer_infos() const {
        auto proxy_result = vscf_message_info_footer_has_signer_infos(c_ctx_);
        return proxy_result;
    }

    /// Return list with a "signer info" elements.
    SignerInfoList signer_infos() const {
        auto proxy_result = vscf_message_info_footer_signer_infos(c_ctx_);
        return SignerInfoList(vscf_signer_info_list_shallow_copy(const_cast<vscf_signer_info_list_t*>(proxy_result)));
    }

    /// Return information about algorithm that was used for data hashing.
    std::unique_ptr<AlgInfo> signer_hash_alg_info() const {
        auto proxy_result = vscf_message_info_footer_signer_hash_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return plain text digest that was used to produce signature.
    std::vector<uint8_t> signer_digest() const {
        auto proxy_result = vscf_message_info_footer_signer_digest(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

private:
    vscf_message_info_footer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
