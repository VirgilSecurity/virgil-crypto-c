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

#include <virgil/crypto/foundation/aes256_cbc.hpp>
#include <virgil/crypto/foundation/vscf_aes256_cbc.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/cipher_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

Aes256Cbc::Aes256Cbc() : c_ctx_(vscf_aes256_cbc_new()) {}

Aes256Cbc::Aes256Cbc(vscf_aes256_cbc_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Aes256Cbc::Aes256Cbc(const Aes256Cbc& other) : c_ctx_(vscf_aes256_cbc_shallow_copy(other.c_ctx_)) {}

Aes256Cbc::Aes256Cbc(Aes256Cbc&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Aes256Cbc& Aes256Cbc::operator=(const Aes256Cbc& other) {
    if (this != &other) {
        vscf_aes256_cbc_delete(c_ctx_);
        c_ctx_ = vscf_aes256_cbc_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Aes256Cbc& Aes256Cbc::operator=(Aes256Cbc&& other) noexcept {
    if (this != &other) {
        vscf_aes256_cbc_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Aes256Cbc::~Aes256Cbc() { vscf_aes256_cbc_delete(c_ctx_); }

vscf_aes256_cbc_t* Aes256Cbc::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Aes256Cbc::impl() const noexcept { return vscf_aes256_cbc_impl(c_ctx_); }

AlgId Aes256Cbc::alg_id() const {
    auto proxy_result = vscf_aes256_cbc_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Aes256Cbc::produce_alg_info() const {
    auto proxy_result = vscf_aes256_cbc_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Aes256Cbc::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_aes256_cbc_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> Aes256Cbc::encrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_cbc_encrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Aes256Cbc::encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_cbc_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Cbc::precise_encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_cbc_precise_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Cbc::decrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_cbc_decrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Aes256Cbc::decrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_cbc_decrypted_len(c_ctx_, data_len);
    return proxy_result;
}

void Aes256Cbc::set_nonce(std::span<const uint8_t> nonce) {
    vscf_aes256_cbc_set_nonce(c_ctx_, nonce.empty() ? vsc_data_empty() : vsc_data(nonce.data(), nonce.size()));
}

void Aes256Cbc::set_key(std::span<const uint8_t> key) {
    vscf_aes256_cbc_set_key(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()));
}

void Aes256Cbc::start_encryption() {
    vscf_aes256_cbc_start_encryption(c_ctx_);
}

void Aes256Cbc::start_decryption() {
    vscf_aes256_cbc_start_decryption(c_ctx_);
}

std::vector<uint8_t> Aes256Cbc::update(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    vscf_aes256_cbc_update(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    return out;
}

std::size_t Aes256Cbc::out_len(std::size_t data_len) {
    auto proxy_result = vscf_aes256_cbc_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Cbc::encrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_cbc_encrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Aes256Cbc::decrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_aes256_cbc_decrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Aes256Cbc::finish() {
    std::vector<uint8_t> out(this->out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_aes256_cbc_finish(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
