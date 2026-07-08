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

#include <virgil/crypto/phe/phe_cipher.hpp>
#include <virgil/crypto/phe/vsce_phe_cipher.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::phe {

PheCipher::PheCipher() : c_ctx_(vsce_phe_cipher_new()) {}

PheCipher::PheCipher(vsce_phe_cipher_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

PheCipher::PheCipher(const PheCipher& other) : c_ctx_(vsce_phe_cipher_shallow_copy(other.c_ctx_)) {}

PheCipher::PheCipher(PheCipher&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

PheCipher& PheCipher::operator=(const PheCipher& other) {
    if (this != &other) {
        vsce_phe_cipher_delete(c_ctx_);
        c_ctx_ = vsce_phe_cipher_shallow_copy(other.c_ctx_);
    }
    return *this;
}

PheCipher& PheCipher::operator=(PheCipher&& other) noexcept {
    if (this != &other) {
        vsce_phe_cipher_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

PheCipher::~PheCipher() { vsce_phe_cipher_delete(c_ctx_); }

vsce_phe_cipher_t* PheCipher::c_ctx() const noexcept { return c_ctx_; }

void PheCipher::set_random(const virgil::crypto::foundation::Random& random) {
    vsce_phe_cipher_release_random(c_ctx_);
    vsce_phe_cipher_use_random(c_ctx_, random.impl());
}

tl::expected<void, Error> PheCipher::setup_defaults() {
    const vsce_status_t status = vsce_phe_cipher_setup_defaults(c_ctx_);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t PheCipher::encrypt_len(std::size_t plain_text_len) {
    auto proxy_result = vsce_phe_cipher_encrypt_len(c_ctx_, plain_text_len);
    return proxy_result;
}

std::size_t PheCipher::decrypt_len(std::size_t cipher_text_len) {
    auto proxy_result = vsce_phe_cipher_decrypt_len(c_ctx_, cipher_text_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> PheCipher::encrypt(std::span<const uint8_t> plain_text, std::span<const uint8_t> account_key) {
    std::vector<uint8_t> cipher_text(this->encrypt_len(plain_text.size()));
    vsc_buffer_t* cipher_text_buf = vsc_buffer_new();
    vsc_buffer_use(cipher_text_buf, cipher_text.data(), cipher_text.size());
    const vsce_status_t status = vsce_phe_cipher_encrypt(c_ctx_, plain_text.empty() ? vsc_data_empty() : vsc_data(plain_text.data(), plain_text.size()), account_key.empty() ? vsc_data_empty() : vsc_data(account_key.data(), account_key.size()), cipher_text_buf);
    cipher_text.resize(vsc_buffer_len(cipher_text_buf));
    vsc_buffer_delete(cipher_text_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return cipher_text;
}

tl::expected<std::vector<uint8_t>, Error> PheCipher::decrypt(std::span<const uint8_t> cipher_text, std::span<const uint8_t> account_key) {
    std::vector<uint8_t> plain_text(this->decrypt_len(cipher_text.size()));
    vsc_buffer_t* plain_text_buf = vsc_buffer_new();
    vsc_buffer_use(plain_text_buf, plain_text.data(), plain_text.size());
    const vsce_status_t status = vsce_phe_cipher_decrypt(c_ctx_, cipher_text.empty() ? vsc_data_empty() : vsc_data(cipher_text.data(), cipher_text.size()), account_key.empty() ? vsc_data_empty() : vsc_data(account_key.data(), account_key.size()), plain_text_buf);
    plain_text.resize(vsc_buffer_len(plain_text_buf));
    vsc_buffer_delete(plain_text_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return plain_text;
}

tl::expected<std::vector<uint8_t>, Error> PheCipher::auth_encrypt(std::span<const uint8_t> plain_text, std::span<const uint8_t> additional_data, std::span<const uint8_t> account_key) {
    std::vector<uint8_t> cipher_text(this->encrypt_len(plain_text.size()));
    vsc_buffer_t* cipher_text_buf = vsc_buffer_new();
    vsc_buffer_use(cipher_text_buf, cipher_text.data(), cipher_text.size());
    const vsce_status_t status = vsce_phe_cipher_auth_encrypt(c_ctx_, plain_text.empty() ? vsc_data_empty() : vsc_data(plain_text.data(), plain_text.size()), additional_data.empty() ? vsc_data_empty() : vsc_data(additional_data.data(), additional_data.size()), account_key.empty() ? vsc_data_empty() : vsc_data(account_key.data(), account_key.size()), cipher_text_buf);
    cipher_text.resize(vsc_buffer_len(cipher_text_buf));
    vsc_buffer_delete(cipher_text_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return cipher_text;
}

tl::expected<std::vector<uint8_t>, Error> PheCipher::auth_decrypt(std::span<const uint8_t> cipher_text, std::span<const uint8_t> additional_data, std::span<const uint8_t> account_key) {
    std::vector<uint8_t> plain_text(this->decrypt_len(cipher_text.size()));
    vsc_buffer_t* plain_text_buf = vsc_buffer_new();
    vsc_buffer_use(plain_text_buf, plain_text.data(), plain_text.size());
    const vsce_status_t status = vsce_phe_cipher_auth_decrypt(c_ctx_, cipher_text.empty() ? vsc_data_empty() : vsc_data(cipher_text.data(), cipher_text.size()), additional_data.empty() ? vsc_data_empty() : vsc_data(additional_data.data(), additional_data.size()), account_key.empty() ? vsc_data_empty() : vsc_data(account_key.data(), account_key.size()), plain_text_buf);
    plain_text.resize(vsc_buffer_len(plain_text_buf));
    vsc_buffer_delete(plain_text_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return plain_text;
}

}  // namespace virgil::crypto::phe
