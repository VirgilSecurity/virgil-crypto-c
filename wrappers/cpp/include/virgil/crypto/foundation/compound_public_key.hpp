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
#include <virgil/crypto/foundation/vscf_compound_public_key.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Handles compound public key.
///
/// Compound public key contains 2 public keys and signature:
/// - cipher key - is used for encryption;
/// - signer key - is used for verifying.
class CompoundPublicKey : virtual public Key, virtual public PublicKey {
public:
    CompoundPublicKey() : c_ctx_(vscf_compound_public_key_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit CompoundPublicKey(vscf_compound_public_key_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    CompoundPublicKey(const CompoundPublicKey& other) : c_ctx_(vscf_compound_public_key_shallow_copy(other.c_ctx_)) {}
    CompoundPublicKey(CompoundPublicKey&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    CompoundPublicKey& operator=(const CompoundPublicKey& other) {
        if (this != &other) {
            vscf_compound_public_key_delete(c_ctx_);
            c_ctx_ = vscf_compound_public_key_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    CompoundPublicKey& operator=(CompoundPublicKey&& other) noexcept {
        if (this != &other) {
            vscf_compound_public_key_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~CompoundPublicKey() { vscf_compound_public_key_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_compound_public_key_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_compound_public_key_impl(c_ctx_); }

    /// Return a cipher public key suitable for initial encryption.
    std::unique_ptr<PublicKey> cipher_key() {
        auto proxy_result = vscf_compound_public_key_cipher_key(c_ctx_);
        return FoundationImplementation::wrap_public_key(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Return public key suitable for verifying.
    std::unique_ptr<PublicKey> signer_key() {
        auto proxy_result = vscf_compound_public_key_signer_key(c_ctx_);
        return FoundationImplementation::wrap_public_key(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Algorithm identifier the key belongs to.
    AlgId alg_id() override {
        auto proxy_result = vscf_compound_public_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return algorithm information that can be used for serialization.
    std::unique_ptr<AlgInfo> alg_info() override {
        auto proxy_result = vscf_compound_public_key_alg_info(c_ctx_);
        return FoundationImplementation::wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)));
    }

    /// Length of the key in bytes.
    std::size_t len() override {
        auto proxy_result = vscf_compound_public_key_len(c_ctx_);
        return proxy_result;
    }

    /// Length of the key in bits.
    std::size_t bitlen() override {
        auto proxy_result = vscf_compound_public_key_bitlen(c_ctx_);
        return proxy_result;
    }

    /// Check that key is valid.
    /// Note, this operation can be slow.
    bool is_valid() override {
        auto proxy_result = vscf_compound_public_key_is_valid(c_ctx_);
        return proxy_result;
    }

private:
    vscf_compound_public_key_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
