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
#include <virgil/crypto/foundation/vscf_signer_info.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handle information about signer that is defined by an identifer and
/// a Public Key.
class SignerInfo {
public:
    SignerInfo() : c_ctx_(vscf_signer_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit SignerInfo(vscf_signer_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    SignerInfo(const SignerInfo& other) : c_ctx_(vscf_signer_info_shallow_copy(other.c_ctx_)) {}
    SignerInfo(SignerInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    SignerInfo& operator=(const SignerInfo& other) {
        if (this != &other) {
            vscf_signer_info_delete(c_ctx_);
            c_ctx_ = vscf_signer_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    SignerInfo& operator=(SignerInfo&& other) noexcept {
        if (this != &other) {
            vscf_signer_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~SignerInfo() { vscf_signer_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_signer_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return signer identifier.
    std::vector<uint8_t> signer_id() {
        auto proxy_result = vscf_signer_info_signer_id(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Return algorithm information that was used for data signing.
    std::unique_ptr<AlgInfo> signer_alg_info() {
        auto proxy_result = vscf_signer_info_signer_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return data signature.
    std::vector<uint8_t> signature() {
        auto proxy_result = vscf_signer_info_signature(c_ctx_);
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

private:
    vscf_signer_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
