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
#include <virgil/crypto/foundation/vscf_signer.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Sign data of any size.
class Signer {
public:
    Signer() : c_ctx_(vscf_signer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Signer(vscf_signer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Signer(const Signer& other) : c_ctx_(vscf_signer_shallow_copy(other.c_ctx_)) {}
    Signer(Signer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Signer& operator=(const Signer& other) {
        if (this != &other) {
            vscf_signer_delete(c_ctx_);
            c_ctx_ = vscf_signer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Signer& operator=(Signer&& other) noexcept {
        if (this != &other) {
            vscf_signer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Signer() { vscf_signer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_signer_t* c_ctx() const noexcept { return c_ctx_; }

    void set_hash(const Hash& hash) {
        vscf_signer_release_hash(c_ctx_);
        vscf_signer_use_hash(c_ctx_, hash.impl());
    }

    void set_random(const Random& random) {
        vscf_signer_release_random(c_ctx_);
        vscf_signer_use_random(c_ctx_, random.impl());
    }

    /// Start a processing a new signature.
    void reset() {
        vscf_signer_reset(c_ctx_);
    }

    /// Add given data to the signed data.
    void append_data(std::span<const uint8_t> data) {
        vscf_signer_append_data(c_ctx_, vsc_data(data.data(), data.size()));
    }

    /// Return length of the signature.
    std::size_t signature_len(const PrivateKey& private_key) {
        auto proxy_result = vscf_signer_signature_len(c_ctx_, private_key.impl());
        return proxy_result;
    }

    /// Accomplish signing and return signature.
    tl::expected<std::vector<uint8_t>, Error> sign(const PrivateKey& private_key) {
        std::vector<uint8_t> signature(this->signature_len(private_key));
        vsc_buffer_t* signature_buf = vsc_buffer_new();
        vsc_buffer_use(signature_buf, signature.data(), signature.size());
        const vscf_status_t status = vscf_signer_sign(c_ctx_, private_key.impl(), signature_buf);
        signature.resize(vsc_buffer_len(signature_buf));
        vsc_buffer_delete(signature_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return signature;
    }

private:
    vscf_signer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
