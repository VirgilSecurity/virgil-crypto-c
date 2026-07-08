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

#include <virgil/crypto/phe/phe_client.hpp>
#include <virgil/crypto/phe/vsce_phe_client.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/phe/phe_common.hpp>
#include <virgil/crypto/common/vsc_buffer.h>

namespace virgil::crypto::phe {

PheClient::PheClient() : c_ctx_(vsce_phe_client_new()) {}

PheClient::PheClient(vsce_phe_client_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

PheClient::PheClient(const PheClient& other) : c_ctx_(vsce_phe_client_shallow_copy(other.c_ctx_)) {}

PheClient::PheClient(PheClient&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

PheClient& PheClient::operator=(const PheClient& other) {
    if (this != &other) {
        vsce_phe_client_delete(c_ctx_);
        c_ctx_ = vsce_phe_client_shallow_copy(other.c_ctx_);
    }
    return *this;
}

PheClient& PheClient::operator=(PheClient&& other) noexcept {
    if (this != &other) {
        vsce_phe_client_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

PheClient::~PheClient() { vsce_phe_client_delete(c_ctx_); }

vsce_phe_client_t* PheClient::c_ctx() const noexcept { return c_ctx_; }

void PheClient::set_random(const virgil::crypto::foundation::Random& random) {
    vsce_phe_client_release_random(c_ctx_);
    vsce_phe_client_use_random(c_ctx_, random.impl());
}

void PheClient::set_operation_random(const virgil::crypto::foundation::Random& operation_random) {
    vsce_phe_client_release_operation_random(c_ctx_);
    vsce_phe_client_use_operation_random(c_ctx_, operation_random.impl());
}

tl::expected<void, Error> PheClient::setup_defaults() {
    const vsce_status_t status = vsce_phe_client_setup_defaults(c_ctx_);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<void, Error> PheClient::set_keys(std::span<const uint8_t> client_private_key, std::span<const uint8_t> server_public_key) {
    const vsce_status_t status = vsce_phe_client_set_keys(c_ctx_, client_private_key.empty() ? vsc_data_empty() : vsc_data(client_private_key.data(), client_private_key.size()), server_public_key.empty() ? vsc_data_empty() : vsc_data(server_public_key.data(), server_public_key.size()));
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> PheClient::generate_client_private_key() {
    std::vector<uint8_t> client_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t* client_private_key_buf = vsc_buffer_new();
    vsc_buffer_use(client_private_key_buf, client_private_key.data(), client_private_key.size());
    const vsce_status_t status = vsce_phe_client_generate_client_private_key(c_ctx_, client_private_key_buf);
    client_private_key.resize(vsc_buffer_len(client_private_key_buf));
    vsc_buffer_delete(client_private_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return client_private_key;
}

std::size_t PheClient::enrollment_record_len() {
    auto proxy_result = vsce_phe_client_enrollment_record_len(c_ctx_);
    return proxy_result;
}

tl::expected<PheClientEnrollAccountResult, Error> PheClient::enroll_account(std::span<const uint8_t> enrollment_response, std::span<const uint8_t> password) {
    std::vector<uint8_t> enrollment_record(this->enrollment_record_len());
    vsc_buffer_t* enrollment_record_buf = vsc_buffer_new();
    vsc_buffer_use(enrollment_record_buf, enrollment_record.data(), enrollment_record.size());
    std::vector<uint8_t> account_key(PheCommon::PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_t* account_key_buf = vsc_buffer_new();
    vsc_buffer_use(account_key_buf, account_key.data(), account_key.size());
    const vsce_status_t status = vsce_phe_client_enroll_account(c_ctx_, enrollment_response.empty() ? vsc_data_empty() : vsc_data(enrollment_response.data(), enrollment_response.size()), password.empty() ? vsc_data_empty() : vsc_data(password.data(), password.size()), enrollment_record_buf, account_key_buf);
    enrollment_record.resize(vsc_buffer_len(enrollment_record_buf));
    vsc_buffer_delete(enrollment_record_buf);
    account_key.resize(vsc_buffer_len(account_key_buf));
    vsc_buffer_delete(account_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return PheClientEnrollAccountResult{.enrollment_record = std::move(enrollment_record), .account_key = std::move(account_key)};
}

std::size_t PheClient::verify_password_request_len() {
    auto proxy_result = vsce_phe_client_verify_password_request_len(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> PheClient::create_verify_password_request(std::span<const uint8_t> password, std::span<const uint8_t> enrollment_record) {
    std::vector<uint8_t> verify_password_request(this->verify_password_request_len());
    vsc_buffer_t* verify_password_request_buf = vsc_buffer_new();
    vsc_buffer_use(verify_password_request_buf, verify_password_request.data(), verify_password_request.size());
    const vsce_status_t status = vsce_phe_client_create_verify_password_request(c_ctx_, password.empty() ? vsc_data_empty() : vsc_data(password.data(), password.size()), enrollment_record.empty() ? vsc_data_empty() : vsc_data(enrollment_record.data(), enrollment_record.size()), verify_password_request_buf);
    verify_password_request.resize(vsc_buffer_len(verify_password_request_buf));
    vsc_buffer_delete(verify_password_request_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return verify_password_request;
}

tl::expected<std::vector<uint8_t>, Error> PheClient::check_response_and_decrypt(std::span<const uint8_t> password, std::span<const uint8_t> enrollment_record, std::span<const uint8_t> verify_password_response) {
    std::vector<uint8_t> account_key(PheCommon::PHE_ACCOUNT_KEY_LENGTH);
    vsc_buffer_t* account_key_buf = vsc_buffer_new();
    vsc_buffer_use(account_key_buf, account_key.data(), account_key.size());
    const vsce_status_t status = vsce_phe_client_check_response_and_decrypt(c_ctx_, password.empty() ? vsc_data_empty() : vsc_data(password.data(), password.size()), enrollment_record.empty() ? vsc_data_empty() : vsc_data(enrollment_record.data(), enrollment_record.size()), verify_password_response.empty() ? vsc_data_empty() : vsc_data(verify_password_response.data(), verify_password_response.size()), account_key_buf);
    account_key.resize(vsc_buffer_len(account_key_buf));
    vsc_buffer_delete(account_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return account_key;
}

tl::expected<PheClientRotateKeysResult, Error> PheClient::rotate_keys(std::span<const uint8_t> update_token) {
    std::vector<uint8_t> new_client_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t* new_client_private_key_buf = vsc_buffer_new();
    vsc_buffer_use(new_client_private_key_buf, new_client_private_key.data(), new_client_private_key.size());
    std::vector<uint8_t> new_server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t* new_server_public_key_buf = vsc_buffer_new();
    vsc_buffer_use(new_server_public_key_buf, new_server_public_key.data(), new_server_public_key.size());
    const vsce_status_t status = vsce_phe_client_rotate_keys(c_ctx_, update_token.empty() ? vsc_data_empty() : vsc_data(update_token.data(), update_token.size()), new_client_private_key_buf, new_server_public_key_buf);
    new_client_private_key.resize(vsc_buffer_len(new_client_private_key_buf));
    vsc_buffer_delete(new_client_private_key_buf);
    new_server_public_key.resize(vsc_buffer_len(new_server_public_key_buf));
    vsc_buffer_delete(new_server_public_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return PheClientRotateKeysResult{.new_client_private_key = std::move(new_client_private_key), .new_server_public_key = std::move(new_server_public_key)};
}

tl::expected<std::vector<uint8_t>, Error> PheClient::update_enrollment_record(std::span<const uint8_t> enrollment_record, std::span<const uint8_t> update_token) {
    std::vector<uint8_t> new_enrollment_record(this->enrollment_record_len());
    vsc_buffer_t* new_enrollment_record_buf = vsc_buffer_new();
    vsc_buffer_use(new_enrollment_record_buf, new_enrollment_record.data(), new_enrollment_record.size());
    const vsce_status_t status = vsce_phe_client_update_enrollment_record(c_ctx_, enrollment_record.empty() ? vsc_data_empty() : vsc_data(enrollment_record.data(), enrollment_record.size()), update_token.empty() ? vsc_data_empty() : vsc_data(update_token.data(), update_token.size()), new_enrollment_record_buf);
    new_enrollment_record.resize(vsc_buffer_len(new_enrollment_record_buf));
    vsc_buffer_delete(new_enrollment_record_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return new_enrollment_record;
}

}  // namespace virgil::crypto::phe
