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
#include <virgil/crypto/foundation/vscf_key_info.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

namespace virgil::crypto::foundation {

class KeyInfo {
public:
    KeyInfo() : c_ctx_(vscf_key_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit KeyInfo(vscf_key_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    KeyInfo(const KeyInfo& other) : c_ctx_(vscf_key_info_shallow_copy(other.c_ctx_)) {}
    KeyInfo(KeyInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    KeyInfo& operator=(const KeyInfo& other) {
        if (this != &other) {
            vscf_key_info_delete(c_ctx_);
            c_ctx_ = vscf_key_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    KeyInfo& operator=(KeyInfo&& other) noexcept {
        if (this != &other) {
            vscf_key_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~KeyInfo() { vscf_key_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_key_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// Return true if a key is a compound key
    bool is_compound() {
        auto proxy_result = vscf_key_info_is_compound(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a hybrid key
    bool is_hybrid() {
        auto proxy_result = vscf_key_info_is_hybrid(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key and compounds cipher key
    /// and signer key are hybrid keys.
    bool is_compound_hybrid() {
        auto proxy_result = vscf_key_info_is_compound_hybrid(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key and compounds cipher key
    /// is a hybrid key.
    bool is_compound_hybrid_cipher() {
        auto proxy_result = vscf_key_info_is_compound_hybrid_cipher(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key and compounds signer key
    /// is a hybrid key.
    bool is_compound_hybrid_signer() {
        auto proxy_result = vscf_key_info_is_compound_hybrid_signer(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key that contains hybrid keys
    /// for encryption/decryption and signing/verifying that itself
    /// contains a combination of classic keys and post-quantum keys.
    bool is_hybrid_post_quantum() {
        auto proxy_result = vscf_key_info_is_hybrid_post_quantum(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key that contains a hybrid key
    /// for encryption/decryption that contains a classic key and
    /// a post-quantum key.
    bool is_hybrid_post_quantum_cipher() {
        auto proxy_result = vscf_key_info_is_hybrid_post_quantum_cipher(c_ctx_);
        return proxy_result;
    }

    /// Return true if a key is a compound key that contains a hybrid key
    /// for signing/verifying that contains a classic key and
    /// a post-quantum key.
    bool is_hybrid_post_quantum_signer() {
        auto proxy_result = vscf_key_info_is_hybrid_post_quantum_signer(c_ctx_);
        return proxy_result;
    }

    /// Return common type of the key.
    AlgId alg_id() {
        auto proxy_result = vscf_key_info_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return compound's cipher key id, if key is compound.
    /// Return None, otherwise.
    AlgId compound_cipher_alg_id() {
        auto proxy_result = vscf_key_info_compound_cipher_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return compound's signer key id, if key is compound.
    /// Return None, otherwise.
    AlgId compound_signer_alg_id() {
        auto proxy_result = vscf_key_info_compound_signer_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's first key id, if key is hybrid.
    /// Return None, otherwise.
    AlgId hybrid_first_key_alg_id() {
        auto proxy_result = vscf_key_info_hybrid_first_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's second key id, if key is hybrid.
    /// Return None, otherwise.
    AlgId hybrid_second_key_alg_id() {
        auto proxy_result = vscf_key_info_hybrid_second_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's first key id of compound's cipher key,
    /// if key is compound(hybrid, ...), None - otherwise.
    AlgId compound_hybrid_cipher_first_key_alg_id() {
        auto proxy_result = vscf_key_info_compound_hybrid_cipher_first_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's second key id of compound's cipher key,
    /// if key is compound(hybrid, ...), None - otherwise.
    AlgId compound_hybrid_cipher_second_key_alg_id() {
        auto proxy_result = vscf_key_info_compound_hybrid_cipher_second_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's first key id of compound's signer key,
    /// if key is compound(..., hybrid), None - otherwise.
    AlgId compound_hybrid_signer_first_key_alg_id() {
        auto proxy_result = vscf_key_info_compound_hybrid_signer_first_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

    /// Return hybrid's second key id of compound's signer key,
    /// if key is compound(..., hybrid), None - otherwise.
    AlgId compound_hybrid_signer_second_key_alg_id() {
        auto proxy_result = vscf_key_info_compound_hybrid_signer_second_key_alg_id(c_ctx_);
        return static_cast<AlgId>(proxy_result);
    }

private:
    vscf_key_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
