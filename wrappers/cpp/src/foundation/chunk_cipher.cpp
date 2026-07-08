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

#include <virgil/crypto/foundation/chunk_cipher.hpp>
#include <virgil/crypto/foundation/vscf_chunk_cipher.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/cipher_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

ChunkCipher::ChunkCipher() : c_ctx_(vscf_chunk_cipher_new()) {}

ChunkCipher::ChunkCipher(vscf_chunk_cipher_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

ChunkCipher::ChunkCipher(const ChunkCipher& other) : c_ctx_(vscf_chunk_cipher_shallow_copy(other.c_ctx_)) {}

ChunkCipher::ChunkCipher(ChunkCipher&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

ChunkCipher& ChunkCipher::operator=(const ChunkCipher& other) {
    if (this != &other) {
        vscf_chunk_cipher_delete(c_ctx_);
        c_ctx_ = vscf_chunk_cipher_shallow_copy(other.c_ctx_);
    }
    return *this;
}

ChunkCipher& ChunkCipher::operator=(ChunkCipher&& other) noexcept {
    if (this != &other) {
        vscf_chunk_cipher_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

ChunkCipher::~ChunkCipher() { vscf_chunk_cipher_delete(c_ctx_); }

vscf_chunk_cipher_t* ChunkCipher::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* ChunkCipher::impl() const noexcept { return vscf_chunk_cipher_impl(c_ctx_); }

void ChunkCipher::set_random(const Random& random) {
    vscf_chunk_cipher_release_random(c_ctx_);
    vscf_chunk_cipher_use_random(c_ctx_, random.impl());
}

void ChunkCipher::set_chunk_size(std::size_t chunk_size) {
    vscf_chunk_cipher_set_chunk_size(c_ctx_, chunk_size);
}

std::vector<uint8_t> ChunkCipher::nonce() const {
    auto proxy_result = vscf_chunk_cipher_nonce(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::size_t ChunkCipher::encryption_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_encryption_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::process_encryption(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encryption_out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_process_encryption(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::finish_encryption() {
    std::vector<uint8_t> out(this->encryption_out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_finish_encryption(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t ChunkCipher::decryption_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_decryption_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::process_decryption(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decryption_out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_process_decryption(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::finish_decryption() {
    std::vector<uint8_t> out(this->decryption_out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_finish_decryption(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t ChunkCipher::chunk_count(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_chunk_count(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::encrypt_at(uint64_t chunk_index, bool is_last, std::span<const uint8_t> plaintext) {
    std::vector<uint8_t> out(this->encryption_out_len(plaintext.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_encrypt_at(c_ctx_, chunk_index, is_last, plaintext.empty() ? vsc_data_empty() : vsc_data(plaintext.data(), plaintext.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::decrypt_at(uint64_t chunk_index, bool is_last, std::span<const uint8_t> frame) {
    std::vector<uint8_t> out(this->decryption_out_len(frame.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_decrypt_at(c_ctx_, chunk_index, is_last, frame.empty() ? vsc_data_empty() : vsc_data(frame.data(), frame.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

void ChunkCipher::set_auth_data(std::span<const uint8_t> auth_data) {
    vscf_chunk_cipher_set_auth_data(c_ctx_, auth_data.empty() ? vsc_data_empty() : vsc_data(auth_data.data(), auth_data.size()));
}

AlgId ChunkCipher::alg_id() const {
    auto proxy_result = vscf_chunk_cipher_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> ChunkCipher::produce_alg_info() const {
    auto proxy_result = vscf_chunk_cipher_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> ChunkCipher::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_chunk_cipher_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::encrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_encrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t ChunkCipher::encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t ChunkCipher::precise_encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_precise_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::decrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decrypted_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_decrypt(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t ChunkCipher::decrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_decrypted_len(c_ctx_, data_len);
    return proxy_result;
}

void ChunkCipher::set_nonce(std::span<const uint8_t> nonce) {
    vscf_chunk_cipher_set_nonce(c_ctx_, nonce.empty() ? vsc_data_empty() : vsc_data(nonce.data(), nonce.size()));
}

void ChunkCipher::set_key(std::span<const uint8_t> key) {
    vscf_chunk_cipher_set_key(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()));
}

void ChunkCipher::start_encryption() {
    vscf_chunk_cipher_start_encryption(c_ctx_);
}

void ChunkCipher::start_decryption() {
    vscf_chunk_cipher_start_decryption(c_ctx_);
}

std::vector<uint8_t> ChunkCipher::update(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    vscf_chunk_cipher_update(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    return out;
}

std::size_t ChunkCipher::out_len(std::size_t data_len) {
    auto proxy_result = vscf_chunk_cipher_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t ChunkCipher::encrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_encrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t ChunkCipher::decrypted_out_len(std::size_t data_len) const {
    auto proxy_result = vscf_chunk_cipher_decrypted_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> ChunkCipher::finish() {
    std::vector<uint8_t> out(this->out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_chunk_cipher_finish(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
