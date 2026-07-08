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

#include <virgil/crypto/foundation/ecies.hpp>
#include <virgil/crypto/foundation/vscf_ecies.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Ecies::Ecies() : c_ctx_(vscf_ecies_new()) {}

Ecies::Ecies(vscf_ecies_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Ecies::Ecies(const Ecies& other) : c_ctx_(vscf_ecies_shallow_copy(other.c_ctx_)) {}

Ecies::Ecies(Ecies&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Ecies& Ecies::operator=(const Ecies& other) {
    if (this != &other) {
        vscf_ecies_delete(c_ctx_);
        c_ctx_ = vscf_ecies_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Ecies& Ecies::operator=(Ecies&& other) noexcept {
    if (this != &other) {
        vscf_ecies_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Ecies::~Ecies() { vscf_ecies_delete(c_ctx_); }

vscf_ecies_t* Ecies::c_ctx() const noexcept { return c_ctx_; }

void Ecies::set_random(const Random& random) {
    vscf_ecies_release_random(c_ctx_);
    vscf_ecies_use_random(c_ctx_, random.impl());
}

void Ecies::set_cipher(const Cipher& cipher) {
    vscf_ecies_release_cipher(c_ctx_);
    vscf_ecies_use_cipher(c_ctx_, cipher.impl());
}

void Ecies::set_mac(const Mac& mac) {
    vscf_ecies_release_mac(c_ctx_);
    vscf_ecies_use_mac(c_ctx_, mac.impl());
}

void Ecies::set_kdf(const Kdf& kdf) {
    vscf_ecies_release_kdf(c_ctx_);
    vscf_ecies_use_kdf(c_ctx_, kdf.impl());
}

void Ecies::set_ephemeral_key(const PrivateKey& ephemeral_key) {
    vscf_ecies_release_ephemeral_key(c_ctx_);
    vscf_ecies_use_ephemeral_key(c_ctx_, ephemeral_key.impl());
}

void Ecies::set_key_alg(const KeyAlg& key_alg) {
    vscf_ecies_set_key_alg(c_ctx_, key_alg.impl());
}

void Ecies::release_key_alg() {
    vscf_ecies_release_key_alg(c_ctx_);
}

tl::expected<void, Error> Ecies::setup_defaults() {
    const vscf_status_t status = vscf_ecies_setup_defaults(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

void Ecies::setup_defaults_no_random() {
    vscf_ecies_setup_defaults_no_random(c_ctx_);
}

std::size_t Ecies::encrypted_len(const PublicKey& public_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecies_encrypted_len(c_ctx_, public_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecies::encrypt(const PublicKey& public_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->encrypted_len(public_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_ecies_encrypt(c_ctx_, public_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Ecies::decrypted_len(const PrivateKey& private_key, std::size_t data_len) const {
    auto proxy_result = vscf_ecies_decrypted_len(c_ctx_, private_key.impl(), data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Ecies::decrypt(const PrivateKey& private_key, std::span<const uint8_t> data) const {
    std::vector<uint8_t> out(this->decrypted_len(private_key, data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_ecies_decrypt(c_ctx_, private_key.impl(), data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
