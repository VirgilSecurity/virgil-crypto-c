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
#include <virgil/crypto/foundation/vscf_ecies.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Virgil implementation of the ECIES algorithm.
class Ecies {
public:
    Ecies() : c_ctx_(vscf_ecies_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Ecies(vscf_ecies_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Ecies(const Ecies& other) : c_ctx_(vscf_ecies_shallow_copy(other.c_ctx_)) {}
    Ecies(Ecies&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Ecies& operator=(const Ecies& other) {
        if (this != &other) {
            vscf_ecies_delete(c_ctx_);
            c_ctx_ = vscf_ecies_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Ecies& operator=(Ecies&& other) noexcept {
        if (this != &other) {
            vscf_ecies_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Ecies() { vscf_ecies_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_ecies_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const Random& random) {
        vscf_ecies_release_random(c_ctx_);
        vscf_ecies_use_random(c_ctx_, random.impl());
    }

    void set_cipher(const Cipher& cipher) {
        vscf_ecies_release_cipher(c_ctx_);
        vscf_ecies_use_cipher(c_ctx_, cipher.impl());
    }

    void set_mac(const Mac& mac) {
        vscf_ecies_release_mac(c_ctx_);
        vscf_ecies_use_mac(c_ctx_, mac.impl());
    }

    void set_kdf(const Kdf& kdf) {
        vscf_ecies_release_kdf(c_ctx_);
        vscf_ecies_use_kdf(c_ctx_, kdf.impl());
    }

    void set_ephemeral_key(const PrivateKey& ephemeral_key) {
        vscf_ecies_release_ephemeral_key(c_ctx_);
        vscf_ecies_use_ephemeral_key(c_ctx_, ephemeral_key.impl());
    }

    /// Set weak reference to the key algorithm.
    /// Key algorithm MUST support shared key computation as well.
    void set_key_alg(const KeyAlg& key_alg) {
        vscf_ecies_set_key_alg(c_ctx_, key_alg.impl());
    }

    /// Release weak reference to the key algorithm.
    void release_key_alg() {
        vscf_ecies_release_key_alg(c_ctx_);
    }

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_ecies_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Setup predefined values to the uninitialized class dependencies
    /// except random.
    void setup_defaults_no_random() {
        vscf_ecies_setup_defaults_no_random(c_ctx_);
    }

    /// Calculate required buffer length to hold the encrypted data.
    std::size_t encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
        auto proxy_result = vscf_ecies_encrypted_len(c_ctx_, public_key.impl(), data_len);
        return proxy_result;
    }

    /// Encrypt data with a given public key.
    tl::expected<std::vector<uint8_t>, Error> encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
        std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_ecies_encrypt(c_ctx_, public_key.impl(), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Calculate required buffer length to hold the decrypted data.
    std::size_t decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
        auto proxy_result = vscf_ecies_decrypted_len(c_ctx_, private_key.impl(), data_len);
        return proxy_result;
    }

    /// Decrypt given data.
    tl::expected<std::vector<uint8_t>, Error> decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
        std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_ecies_decrypt(c_ctx_, private_key.impl(), vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_ecies_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
