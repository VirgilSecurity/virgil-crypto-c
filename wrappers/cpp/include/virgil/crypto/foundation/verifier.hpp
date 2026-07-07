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
#include <virgil/crypto/foundation/vscf_verifier.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/public_key.hpp>

namespace virgil::crypto::foundation {

/// Verify data of any size.
/// Compatible with the class "signer".
class Verifier {
public:
    Verifier() : c_ctx_(vscf_verifier_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Verifier(vscf_verifier_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Verifier(const Verifier& other) : c_ctx_(vscf_verifier_shallow_copy(other.c_ctx_)) {}
    Verifier(Verifier&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Verifier& operator=(const Verifier& other) {
        if (this != &other) {
            vscf_verifier_delete(c_ctx_);
            c_ctx_ = vscf_verifier_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Verifier& operator=(Verifier&& other) noexcept {
        if (this != &other) {
            vscf_verifier_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Verifier() { vscf_verifier_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_verifier_t* c_ctx() const noexcept { return c_ctx_; }

    /// Start verifying a signature.
    tl::expected<void, Error> reset(std::span<const uint8_t> signature) {
        const vscf_status_t status = vscf_verifier_reset(c_ctx_, vsc_data(signature.data(), signature.size()));
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Add given data to the signed data.
    void append_data(std::span<const uint8_t> data) {
        vscf_verifier_append_data(c_ctx_, vsc_data(data.data(), data.size()));
    }

    /// Verify accumulated data.
    bool verify(const PublicKey& public_key) {
        auto proxy_result = vscf_verifier_verify(c_ctx_, public_key.impl());
        return proxy_result;
    }

private:
    vscf_verifier_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
