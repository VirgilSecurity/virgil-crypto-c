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

#include <virgil/crypto/phe/uokms_client.hpp>
#include <virgil/crypto/phe/vsce_uokms_client.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/phe/phe_common.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::phe {

UokmsClient::UokmsClient() : c_ctx_(vsce_uokms_client_new()) {}

UokmsClient::UokmsClient(vsce_uokms_client_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

UokmsClient::UokmsClient(const UokmsClient& other) : c_ctx_(vsce_uokms_client_shallow_copy(other.c_ctx_)) {}

UokmsClient::UokmsClient(UokmsClient&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

UokmsClient& UokmsClient::operator=(const UokmsClient& other) {
    if (this != &other) {
        vsce_uokms_client_delete(c_ctx_);
        c_ctx_ = vsce_uokms_client_shallow_copy(other.c_ctx_);
    }
    return *this;
}

UokmsClient& UokmsClient::operator=(UokmsClient&& other) noexcept {
    if (this != &other) {
        vsce_uokms_client_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

UokmsClient::~UokmsClient() { vsce_uokms_client_delete(c_ctx_); }

vsce_uokms_client_t* UokmsClient::c_ctx() const noexcept { return c_ctx_; }

void UokmsClient::set_random(const virgil::crypto::foundation::Random& random) {
    vsce_uokms_client_release_random(c_ctx_);
    vsce_uokms_client_use_random(c_ctx_, random.impl());
}

void UokmsClient::set_operation_random(const virgil::crypto::foundation::Random& operation_random) {
    vsce_uokms_client_release_operation_random(c_ctx_);
    vsce_uokms_client_use_operation_random(c_ctx_, operation_random.impl());
}

tl::expected<void, Error> UokmsClient::setup_defaults() {
    const vsce_status_t status = vsce_uokms_client_setup_defaults(c_ctx_);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> UokmsClient::set_keys_oneparty(std::span<const uint8_t> client_private_key) {
    const vsce_status_t status = vsce_uokms_client_set_keys_oneparty(c_ctx_, vsc_data(client_private_key.data(), client_private_key.size()));
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> UokmsClient::set_keys(std::span<const uint8_t> client_private_key, std::span<const uint8_t> server_public_key) {
    const vsce_status_t status = vsce_uokms_client_set_keys(c_ctx_, vsc_data(client_private_key.data(), client_private_key.size()), vsc_data(server_public_key.data(), server_public_key.size()));
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> UokmsClient::generate_client_private_key() {
    std::vector<uint8_t> client_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t client_private_key_buf;
    vsc_buffer_init(&client_private_key_buf);
    vsc_buffer_use(&client_private_key_buf, client_private_key.data(), client_private_key.size());
    const vsce_status_t status = vsce_uokms_client_generate_client_private_key(c_ctx_, &client_private_key_buf);
    client_private_key.resize(vsc_buffer_len(&client_private_key_buf));
    vsc_buffer_cleanup(&client_private_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return client_private_key;
}

tl::expected<UokmsClientGenerateEncryptWrapResult, Error> UokmsClient::generate_encrypt_wrap(std::size_t encryption_key_len) {
    std::vector<uint8_t> wrap(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t wrap_buf;
    vsc_buffer_init(&wrap_buf);
    vsc_buffer_use(&wrap_buf, wrap.data(), wrap.size());
    std::vector<uint8_t> encryption_key(encryption_key_len);
    vsc_buffer_t encryption_key_buf;
    vsc_buffer_init(&encryption_key_buf);
    vsc_buffer_use(&encryption_key_buf, encryption_key.data(), encryption_key.size());
    const vsce_status_t status = vsce_uokms_client_generate_encrypt_wrap(c_ctx_, &wrap_buf, encryption_key_len, &encryption_key_buf);
    wrap.resize(vsc_buffer_len(&wrap_buf));
    vsc_buffer_cleanup(&wrap_buf);
    encryption_key.resize(vsc_buffer_len(&encryption_key_buf));
    vsc_buffer_cleanup(&encryption_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return UokmsClientGenerateEncryptWrapResult{.wrap = std::move(wrap), .encryption_key = std::move(encryption_key)};
}

tl::expected<std::vector<uint8_t>, Error> UokmsClient::decrypt_oneparty(std::span<const uint8_t> wrap, std::size_t encryption_key_len) {
    std::vector<uint8_t> encryption_key(encryption_key_len);
    vsc_buffer_t encryption_key_buf;
    vsc_buffer_init(&encryption_key_buf);
    vsc_buffer_use(&encryption_key_buf, encryption_key.data(), encryption_key.size());
    const vsce_status_t status = vsce_uokms_client_decrypt_oneparty(c_ctx_, vsc_data(wrap.data(), wrap.size()), encryption_key_len, &encryption_key_buf);
    encryption_key.resize(vsc_buffer_len(&encryption_key_buf));
    vsc_buffer_cleanup(&encryption_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return encryption_key;
}

tl::expected<UokmsClientGenerateDecryptRequestResult, Error> UokmsClient::generate_decrypt_request(std::span<const uint8_t> wrap) {
    std::vector<uint8_t> deblind_factor(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t deblind_factor_buf;
    vsc_buffer_init(&deblind_factor_buf);
    vsc_buffer_use(&deblind_factor_buf, deblind_factor.data(), deblind_factor.size());
    std::vector<uint8_t> decrypt_request(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t decrypt_request_buf;
    vsc_buffer_init(&decrypt_request_buf);
    vsc_buffer_use(&decrypt_request_buf, decrypt_request.data(), decrypt_request.size());
    const vsce_status_t status = vsce_uokms_client_generate_decrypt_request(c_ctx_, vsc_data(wrap.data(), wrap.size()), &deblind_factor_buf, &decrypt_request_buf);
    deblind_factor.resize(vsc_buffer_len(&deblind_factor_buf));
    vsc_buffer_cleanup(&deblind_factor_buf);
    decrypt_request.resize(vsc_buffer_len(&decrypt_request_buf));
    vsc_buffer_cleanup(&decrypt_request_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return UokmsClientGenerateDecryptRequestResult{.deblind_factor = std::move(deblind_factor), .decrypt_request = std::move(decrypt_request)};
}

tl::expected<std::vector<uint8_t>, Error> UokmsClient::process_decrypt_response(std::span<const uint8_t> wrap, std::span<const uint8_t> decrypt_request, std::span<const uint8_t> decrypt_response, std::span<const uint8_t> deblind_factor, std::size_t encryption_key_len) {
    std::vector<uint8_t> encryption_key(encryption_key_len);
    vsc_buffer_t encryption_key_buf;
    vsc_buffer_init(&encryption_key_buf);
    vsc_buffer_use(&encryption_key_buf, encryption_key.data(), encryption_key.size());
    const vsce_status_t status = vsce_uokms_client_process_decrypt_response(c_ctx_, vsc_data(wrap.data(), wrap.size()), vsc_data(decrypt_request.data(), decrypt_request.size()), vsc_data(decrypt_response.data(), decrypt_response.size()), vsc_data(deblind_factor.data(), deblind_factor.size()), encryption_key_len, &encryption_key_buf);
    encryption_key.resize(vsc_buffer_len(&encryption_key_buf));
    vsc_buffer_cleanup(&encryption_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return encryption_key;
}

tl::expected<std::vector<uint8_t>, Error> UokmsClient::rotate_keys_oneparty(std::span<const uint8_t> update_token) {
    std::vector<uint8_t> new_client_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t new_client_private_key_buf;
    vsc_buffer_init(&new_client_private_key_buf);
    vsc_buffer_use(&new_client_private_key_buf, new_client_private_key.data(), new_client_private_key.size());
    const vsce_status_t status = vsce_uokms_client_rotate_keys_oneparty(c_ctx_, vsc_data(update_token.data(), update_token.size()), &new_client_private_key_buf);
    new_client_private_key.resize(vsc_buffer_len(&new_client_private_key_buf));
    vsc_buffer_cleanup(&new_client_private_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return new_client_private_key;
}

tl::expected<std::vector<uint8_t>, Error> UokmsClient::generate_update_token_oneparty() {
    std::vector<uint8_t> update_token(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t update_token_buf;
    vsc_buffer_init(&update_token_buf);
    vsc_buffer_use(&update_token_buf, update_token.data(), update_token.size());
    const vsce_status_t status = vsce_uokms_client_generate_update_token_oneparty(c_ctx_, &update_token_buf);
    update_token.resize(vsc_buffer_len(&update_token_buf));
    vsc_buffer_cleanup(&update_token_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return update_token;
}

tl::expected<UokmsClientRotateKeysResult, Error> UokmsClient::rotate_keys(std::span<const uint8_t> update_token) {
    std::vector<uint8_t> new_client_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t new_client_private_key_buf;
    vsc_buffer_init(&new_client_private_key_buf);
    vsc_buffer_use(&new_client_private_key_buf, new_client_private_key.data(), new_client_private_key.size());
    std::vector<uint8_t> new_server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t new_server_public_key_buf;
    vsc_buffer_init(&new_server_public_key_buf);
    vsc_buffer_use(&new_server_public_key_buf, new_server_public_key.data(), new_server_public_key.size());
    const vsce_status_t status = vsce_uokms_client_rotate_keys(c_ctx_, vsc_data(update_token.data(), update_token.size()), &new_client_private_key_buf, &new_server_public_key_buf);
    new_client_private_key.resize(vsc_buffer_len(&new_client_private_key_buf));
    vsc_buffer_cleanup(&new_client_private_key_buf);
    new_server_public_key.resize(vsc_buffer_len(&new_server_public_key_buf));
    vsc_buffer_cleanup(&new_server_public_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return UokmsClientRotateKeysResult{.new_client_private_key = std::move(new_client_private_key), .new_server_public_key = std::move(new_server_public_key)};
}

}  // namespace virgil::crypto::phe
