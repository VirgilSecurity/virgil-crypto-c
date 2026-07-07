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
#include <virgil/crypto/foundation/vscf_compound_key_alg_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handle information about compound key algorithm.
class CompoundKeyAlgInfo : virtual public AlgInfo {
public:
    CompoundKeyAlgInfo() : c_ctx_(vscf_compound_key_alg_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit CompoundKeyAlgInfo(vscf_compound_key_alg_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    CompoundKeyAlgInfo(const CompoundKeyAlgInfo& other) : c_ctx_(vscf_compound_key_alg_info_shallow_copy(other.c_ctx_)) {}
    CompoundKeyAlgInfo(CompoundKeyAlgInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    CompoundKeyAlgInfo& operator=(const CompoundKeyAlgInfo& other) {
        if (this != &other) {
            vscf_compound_key_alg_info_delete(c_ctx_);
            c_ctx_ = vscf_compound_key_alg_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    CompoundKeyAlgInfo& operator=(CompoundKeyAlgInfo&& other) noexcept {
        if (this != &other) {
            vscf_compound_key_alg_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~CompoundKeyAlgInfo() { vscf_compound_key_alg_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_compound_key_alg_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_compound_key_alg_info_impl(c_ctx_); }

    /// Return information about encrypt/decrypt algorithm.
    std::unique_ptr<AlgInfo> cipher_alg_info() {
        auto proxy_result = vscf_compound_key_alg_info_cipher_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return information about sign/verify algorithm.
    std::unique_ptr<AlgInfo> signer_alg_info() {
        auto proxy_result = vscf_compound_key_alg_info_signer_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Provide algorithm identificator.
    AlgId alg_id() override {
        auto proxy_result = vscf_compound_key_alg_info_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

private:
    vscf_compound_key_alg_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
