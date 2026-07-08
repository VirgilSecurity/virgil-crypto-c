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

#include <virgil/crypto/foundation/recipient_cipher.hpp>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/key_wrap.hpp>
#include <virgil/crypto/foundation/message_info_custom_params.hpp>
#include <virgil/crypto/foundation/padding.hpp>
#include <virgil/crypto/foundation/padding_params.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/signer_info.hpp>
#include <virgil/crypto/foundation/signer_info_list.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::foundation {

RecipientCipher::RecipientCipher() : c_ctx_(vscf_recipient_cipher_new()) {}

RecipientCipher::RecipientCipher(vscf_recipient_cipher_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

RecipientCipher::RecipientCipher(const RecipientCipher& other) : c_ctx_(vscf_recipient_cipher_shallow_copy(other.c_ctx_)) {}

RecipientCipher::RecipientCipher(RecipientCipher&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

RecipientCipher& RecipientCipher::operator=(const RecipientCipher& other) {
    if (this != &other) {
        vscf_recipient_cipher_delete(c_ctx_);
        c_ctx_ = vscf_recipient_cipher_shallow_copy(other.c_ctx_);
    }
    return *this;
}

RecipientCipher& RecipientCipher::operator=(RecipientCipher&& other) noexcept {
    if (this != &other) {
        vscf_recipient_cipher_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

RecipientCipher::~RecipientCipher() { vscf_recipient_cipher_delete(c_ctx_); }

vscf_recipient_cipher_t* RecipientCipher::c_ctx() const noexcept { return c_ctx_; }

void RecipientCipher::set_random(const Random& random) {
    vscf_recipient_cipher_release_random(c_ctx_);
    vscf_recipient_cipher_use_random(c_ctx_, random.impl());
}

void RecipientCipher::set_encryption_cipher(const Cipher& encryption_cipher) {
    vscf_recipient_cipher_release_encryption_cipher(c_ctx_);
    vscf_recipient_cipher_use_encryption_cipher(c_ctx_, encryption_cipher.impl());
}

void RecipientCipher::set_encryption_padding(const Padding& encryption_padding) {
    vscf_recipient_cipher_release_encryption_padding(c_ctx_);
    vscf_recipient_cipher_use_encryption_padding(c_ctx_, encryption_padding.impl());
}

void RecipientCipher::set_padding_params(const PaddingParams& padding_params) {
    vscf_recipient_cipher_release_padding_params(c_ctx_);
    vscf_recipient_cipher_use_padding_params(c_ctx_, padding_params.c_ctx());
}

void RecipientCipher::set_signer_hash(const Hash& signer_hash) {
    vscf_recipient_cipher_release_signer_hash(c_ctx_);
    vscf_recipient_cipher_use_signer_hash(c_ctx_, signer_hash.impl());
}

bool RecipientCipher::has_key_recipient(std::span<const uint8_t> recipient_id) const {
    auto proxy_result = vscf_recipient_cipher_has_key_recipient(c_ctx_, recipient_id.empty() ? vsc_data_empty() : vsc_data(recipient_id.data(), recipient_id.size()));
    return proxy_result;
}

void RecipientCipher::add_key_recipient(std::span<const uint8_t> recipient_id, const PublicKey& public_key) {
    vscf_recipient_cipher_add_key_recipient(c_ctx_, recipient_id.empty() ? vsc_data_empty() : vsc_data(recipient_id.data(), recipient_id.size()), public_key.impl());
}

void RecipientCipher::add_kek_recipient(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap) {
    vscf_recipient_cipher_add_kek_recipient(c_ctx_, kek_id.empty() ? vsc_data_empty() : vsc_data(kek_id.data(), kek_id.size()), kek.empty() ? vsc_data_empty() : vsc_data(kek.data(), kek.size()), key_wrap.impl());
}

void RecipientCipher::clear_recipients() {
    vscf_recipient_cipher_clear_recipients(c_ctx_);
}

tl::expected<void, Error> RecipientCipher::add_signer(std::span<const uint8_t> signer_id, const PrivateKey& private_key) {
    const vscf_status_t status = vscf_recipient_cipher_add_signer(c_ctx_, signer_id.empty() ? vsc_data_empty() : vsc_data(signer_id.data(), signer_id.size()), private_key.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

void RecipientCipher::clear_signers() {
    vscf_recipient_cipher_clear_signers(c_ctx_);
}

MessageInfoCustomParams RecipientCipher::custom_params() {
    auto proxy_result = vscf_recipient_cipher_custom_params(c_ctx_);
    return MessageInfoCustomParams(vscf_message_info_custom_params_shallow_copy(const_cast<vscf_message_info_custom_params_t*>(proxy_result)));
}

tl::expected<void, Error> RecipientCipher::start_encryption() {
    const vscf_status_t status = vscf_recipient_cipher_start_encryption(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RecipientCipher::start_signed_encryption(std::size_t data_size) {
    const vscf_status_t status = vscf_recipient_cipher_start_signed_encryption(c_ctx_, data_size);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t RecipientCipher::message_info_len() const {
    auto proxy_result = vscf_recipient_cipher_message_info_len(c_ctx_);
    return proxy_result;
}

std::vector<uint8_t> RecipientCipher::pack_message_info() {
    std::vector<uint8_t> message_info(this->message_info_len());
    vsc_buffer_t* message_info_buf = vsc_buffer_new();
    vsc_buffer_use(message_info_buf, message_info.data(), message_info.size());
    vscf_recipient_cipher_pack_message_info(c_ctx_, message_info_buf);
    message_info.resize(vsc_buffer_len(message_info_buf));
    vsc_buffer_delete(message_info_buf);
    return message_info;
}

std::size_t RecipientCipher::encryption_out_len(std::size_t data_len) {
    auto proxy_result = vscf_recipient_cipher_encryption_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> RecipientCipher::process_encryption(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encryption_out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_recipient_cipher_process_encryption(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> RecipientCipher::finish_encryption() {
    std::vector<uint8_t> out(this->encryption_out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_recipient_cipher_finish_encryption(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<void, Error> RecipientCipher::start_decryption_with_kek(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap, std::span<const uint8_t> message_info) {
    const vscf_status_t status = vscf_recipient_cipher_start_decryption_with_kek(c_ctx_, kek_id.empty() ? vsc_data_empty() : vsc_data(kek_id.data(), kek_id.size()), kek.empty() ? vsc_data_empty() : vsc_data(kek.data(), kek.size()), key_wrap.impl(), message_info.empty() ? vsc_data_empty() : vsc_data(message_info.data(), message_info.size()));
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RecipientCipher::start_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info) {
    const vscf_status_t status = vscf_recipient_cipher_start_decryption_with_key(c_ctx_, recipient_id.empty() ? vsc_data_empty() : vsc_data(recipient_id.data(), recipient_id.size()), private_key.impl(), message_info.empty() ? vsc_data_empty() : vsc_data(message_info.data(), message_info.size()));
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> RecipientCipher::start_verified_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info, std::span<const uint8_t> message_info_footer) {
    const vscf_status_t status = vscf_recipient_cipher_start_verified_decryption_with_key(c_ctx_, recipient_id.empty() ? vsc_data_empty() : vsc_data(recipient_id.data(), recipient_id.size()), private_key.impl(), message_info.empty() ? vsc_data_empty() : vsc_data(message_info.data(), message_info.size()), message_info_footer.empty() ? vsc_data_empty() : vsc_data(message_info_footer.data(), message_info_footer.size()));
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

std::size_t RecipientCipher::decryption_out_len(std::size_t data_len) {
    auto proxy_result = vscf_recipient_cipher_decryption_out_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> RecipientCipher::process_decryption(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decryption_out_len(data.size()));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_recipient_cipher_process_decryption(c_ctx_, data.empty() ? vsc_data_empty() : vsc_data(data.data(), data.size()), out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

tl::expected<std::vector<uint8_t>, Error> RecipientCipher::finish_decryption() {
    std::vector<uint8_t> out(this->decryption_out_len(0));
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_recipient_cipher_finish_decryption(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

bool RecipientCipher::is_data_signed() const {
    auto proxy_result = vscf_recipient_cipher_is_data_signed(c_ctx_);
    return proxy_result;
}

SignerInfoList RecipientCipher::signer_infos() const {
    auto proxy_result = vscf_recipient_cipher_signer_infos(c_ctx_);
    return SignerInfoList(vscf_signer_info_list_shallow_copy(const_cast<vscf_signer_info_list_t*>(proxy_result)));
}

bool RecipientCipher::verify_signer_info(const SignerInfo& signer_info, const PublicKey& public_key) {
    auto proxy_result = vscf_recipient_cipher_verify_signer_info(c_ctx_, signer_info.c_ctx(), public_key.impl());
    return proxy_result;
}

std::size_t RecipientCipher::message_info_footer_len() const {
    auto proxy_result = vscf_recipient_cipher_message_info_footer_len(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> RecipientCipher::pack_message_info_footer() {
    std::vector<uint8_t> out(this->message_info_footer_len());
    vsc_buffer_t* out_buf = vsc_buffer_new();
    vsc_buffer_use(out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_recipient_cipher_pack_message_info_footer(c_ctx_, out_buf);
    out.resize(vsc_buffer_len(out_buf));
    vsc_buffer_delete(out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
