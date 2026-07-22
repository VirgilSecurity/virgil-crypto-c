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

#include <virgil/crypto/foundation/aes256_gcm.hpp>
#include <virgil/crypto/foundation/vscf_aes256_gcm.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/cipher_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/cipher_auth_info.hpp>
#include <virgil/crypto/foundation/auth_encrypt.hpp>
#include <virgil/crypto/foundation/auth_decrypt.hpp>
#include <virgil/crypto/foundation/cipher_auth.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Aes256Gcm::Aes256Gcm() : c_ctx_(vscf_aes256_gcm_new()) {}

Aes256Gcm::Aes256Gcm(vscf_aes256_gcm_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Aes256Gcm::Aes256Gcm(const Aes256Gcm& other) : c_ctx_(vscf_aes256_gcm_shallow_copy(other.c_ctx_)) {}

Aes256Gcm::Aes256Gcm(Aes256Gcm&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Aes256Gcm& Aes256Gcm::operator=(const Aes256Gcm& other) {
    if (this != &other) {
        vscf_aes256_gcm_delete(c_ctx_);
        c_ctx_ = vscf_aes256_gcm_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Aes256Gcm& Aes256Gcm::operator=(Aes256Gcm&& other) noexcept {
    if (this != &other) {
        vscf_aes256_gcm_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Aes256Gcm::~Aes256Gcm() { vscf_aes256_gcm_delete(c_ctx_); }

vscf_aes256_gcm_t* Aes256Gcm::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Aes256Gcm::impl() const noexcept { return vscf_aes256_gcm_impl(c_ctx_); }

AlgId Aes256Gcm::alg_id() const {
    auto proxy_result = vscf_aes256_gcm_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Aes256Gcm::produce_alg_info() const {
    auto proxy_result = vscf_aes256_gcm_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Aes256Gcm::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_aes256_gcm_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> Aes256Gcm::encrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_gcm_encrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Aes256Gcm::encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Gcm::precise_encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_precise_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Gcm::decrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_gcm_decrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Aes256Gcm::decrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_decrypted_len(c_ctx_, data_len);
    return proxy_result;
}

void Aes256Gcm::set_nonce(std::span<const uint8_t> nonce) {
    vscf_aes256_gcm_set_nonce(c_ctx_, nonce.empty() ? vsc_data_empty() : vsc_data(nonce.data(), nonce.size()));
}

void Aes256Gcm::set_key(std::span<const uint8_t> key) {
    vscf_aes256_gcm_set_key(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()));
}

void Aes256Gcm::start_encryption() {
    vscf_aes256_gcm_start_encryption(c_ctx_);
}

void Aes256Gcm::start_decryption() {
    vscf_aes256_gcm_start_decryption(c_ctx_);
}

std::vector<uint8_t> Aes256Gcm::update(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    vscf_aes256_gcm_update(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    return out;
}

std::size_t Aes256Gcm::out_len(std::size_t data_len) {
    auto proxy_result = vscf_aes256_gcm_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Gcm::encrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_encrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Gcm::decrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_decrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Gcm::finish() {
    std::vector<uint8_t> out(this->out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_gcm_finish(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<AuthEncryptAuthEncryptResult, Error> Aes256Gcm::auth_encrypt(std::span<const uint8_t> data, std::span<const uint8_t> auth_data) {
    std::vector<uint8_t> out(this->auth_encrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    std::vector<uint8_t> tag(this->AUTH_TAG_LEN);
    vsc_buffer_t* tag_buf = vsc_buffer_new();
    vsc_buffer_use(tag_buf, tag.data(), tag.size());
    const vscf_status_t status = vscf_aes256_gcm_auth_encrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), auth_data.empty() ? vsc_data_empty() : vsc_data(auth_data.data(), auth_data.size()), out_buf, tag_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    tag.resize(vsc_buffer_len(tag_buf));
    vsc_buffer_delete(tag_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return AuthEncryptAuthEncryptResult{.out = std::move(out), .tag = std::move(tag)};
}

std::size_t Aes256Gcm::auth_encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_auth_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Gcm::auth_decrypt(std::span<const uint8_t> data, std::span<const uint8_t> auth_data, std::span<const uint8_t> tag) {
    std::vector<uint8_t> out(this->auth_decrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_gcm_auth_decrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), auth_data.empty() ? vsc_data_empty() : vsc_data(auth_data.data(), auth_data.size()), tag.empty() ? vsc_data_empty() : vsc_data(tag.data(), tag.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Aes256Gcm::auth_decrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_gcm_auth_decrypted_len(c_ctx_, data_len);
    return proxy_result;
}

void Aes256Gcm::set_auth_data(std::span<const uint8_t> auth_data) {
    vscf_aes256_gcm_set_auth_data(c_ctx_, auth_data.empty() ? vsc_data_empty() : vsc_data(auth_data.data(), auth_data.size()));
}

tl::expected<CipherAuthFinishAuthEncryptionResult, Error> Aes256Gcm::finish_auth_encryption() {
    std::vector<uint8_t> out(this->out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    std::vector<uint8_t> tag(this->AUTH_TAG_LEN);
    vsc_buffer_t* tag_buf = vsc_buffer_new();
    vsc_buffer_use(tag_buf, tag.data(), tag.size());
    const vscf_status_t status = vscf_aes256_gcm_finish_auth_encryption(c_ctx_, out_buf, tag_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    tag.resize(vsc_buffer_len(tag_buf));
    vsc_buffer_delete(tag_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return CipherAuthFinishAuthEncryptionResult{.out = std::move(out), .tag = std::move(tag)};
}

tl::expected<std::vector<uint8_t>, Error> Aes256Gcm::finish_auth_decryption(std::span<const uint8_t> tag) {
    std::vector<uint8_t> out(this->out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_gcm_finish_auth_decryption(c_ctx_, tag.empty() ? vsc_data_empty() : vsc_data(tag.data(), tag.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
