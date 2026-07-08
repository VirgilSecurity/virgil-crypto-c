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

#include <virgil/crypto/foundation/message_info_footer.hpp>
#include <virgil/crypto/foundation/vscf_message_info_footer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/signer_info_list.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

MessageInfoFooter::MessageInfoFooter() : c_ctx_(vscf_message_info_footer_new()) {}

MessageInfoFooter::MessageInfoFooter(vscf_message_info_footer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

MessageInfoFooter::MessageInfoFooter(const MessageInfoFooter& other) : c_ctx_(vscf_message_info_footer_shallow_copy(other.c_ctx_)) {}

MessageInfoFooter::MessageInfoFooter(MessageInfoFooter&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

MessageInfoFooter& MessageInfoFooter::operator=(const MessageInfoFooter& other) {
    if (this != &other) {
        vscf_message_info_footer_delete(c_ctx_);
        c_ctx_ = vscf_message_info_footer_shallow_copy(other.c_ctx_);
    }
    return *this;
}

MessageInfoFooter& MessageInfoFooter::operator=(MessageInfoFooter&& other) noexcept {
    if (this != &other) {
        vscf_message_info_footer_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

MessageInfoFooter::~MessageInfoFooter() { vscf_message_info_footer_delete(c_ctx_); }

vscf_message_info_footer_t* MessageInfoFooter::c_ctx() const noexcept { return c_ctx_; }

bool MessageInfoFooter::has_signer_infos() const {
    auto proxy_result = vscf_message_info_footer_has_signer_infos(c_ctx_);
    return proxy_result;
}

SignerInfoList MessageInfoFooter::signer_infos() const {
    auto proxy_result = vscf_message_info_footer_signer_infos(c_ctx_);
    return SignerInfoList(vscf_signer_info_list_shallow_copy(const_cast<vscf_signer_info_list_t*>(proxy_result)));
}

std::unique_ptr<AlgInfo> MessageInfoFooter::signer_hash_alg_info() const {
    auto proxy_result = vscf_message_info_footer_signer_hash_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
}

std::vector<uint8_t> MessageInfoFooter::signer_digest() const {
    auto proxy_result = vscf_message_info_footer_signer_digest(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

}  // namespace virgil::crypto::foundation
