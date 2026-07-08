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

#include <virgil/crypto/phe/phe_server.hpp>
#include <virgil/crypto/phe/vsce_phe_server.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/phe/phe_common.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::phe {

PheServer::PheServer() : c_ctx_(vsce_phe_server_new()) {}

PheServer::PheServer(vsce_phe_server_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

PheServer::PheServer(const PheServer& other) : c_ctx_(vsce_phe_server_shallow_copy(other.c_ctx_)) {}

PheServer::PheServer(PheServer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

PheServer& PheServer::operator=(const PheServer& other) {
    if (this != &other) {
        vsce_phe_server_delete(c_ctx_);
        c_ctx_ = vsce_phe_server_shallow_copy(other.c_ctx_);
    }
    return *this;
}

PheServer& PheServer::operator=(PheServer&& other) noexcept {
    if (this != &other) {
        vsce_phe_server_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

PheServer::~PheServer() { vsce_phe_server_delete(c_ctx_); }

vsce_phe_server_t* PheServer::c_ctx() const noexcept { return c_ctx_; }

void PheServer::set_random(const virgil::crypto::foundation::Random& random) {
    vsce_phe_server_release_random(c_ctx_);
    vsce_phe_server_use_random(c_ctx_, random.impl());
}

void PheServer::set_operation_random(const virgil::crypto::foundation::Random& operation_random) {
    vsce_phe_server_release_operation_random(c_ctx_);
    vsce_phe_server_use_operation_random(c_ctx_, operation_random.impl());
}

tl::expected<void, Error> PheServer::setup_defaults() {
    const vsce_status_t status = vsce_phe_server_setup_defaults(c_ctx_);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<PheServerGenerateServerKeyPairResult, Error> PheServer::generate_server_key_pair() {
    std::vector<uint8_t> server_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t server_private_key_buf;
    vsc_buffer_init(&server_private_key_buf);
    vsc_buffer_use(&server_private_key_buf, server_private_key.data(), server_private_key.size());
    std::vector<uint8_t> server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t server_public_key_buf;
    vsc_buffer_init(&server_public_key_buf);
    vsc_buffer_use(&server_public_key_buf, server_public_key.data(), server_public_key.size());
    const vsce_status_t status = vsce_phe_server_generate_server_key_pair(c_ctx_, &server_private_key_buf, &server_public_key_buf);
    server_private_key.resize(vsc_buffer_len(&server_private_key_buf));
    vsc_buffer_cleanup(&server_private_key_buf);
    server_public_key.resize(vsc_buffer_len(&server_public_key_buf));
    vsc_buffer_cleanup(&server_public_key_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return PheServerGenerateServerKeyPairResult{.server_private_key = std::move(server_private_key), .server_public_key = std::move(server_public_key)};
}

std::size_t PheServer::enrollment_response_len() {
    auto proxy_result = vsce_phe_server_enrollment_response_len(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> PheServer::get_enrollment(std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key) {
    std::vector<uint8_t> enrollment_response(this->enrollment_response_len());
    vsc_buffer_t enrollment_response_buf;
    vsc_buffer_init(&enrollment_response_buf);
    vsc_buffer_use(&enrollment_response_buf, enrollment_response.data(), enrollment_response.size());
    const vsce_status_t status = vsce_phe_server_get_enrollment(c_ctx_, vsc_data(server_private_key.data(), server_private_key.size()), vsc_data(server_public_key.data(), server_public_key.size()), &enrollment_response_buf);
    enrollment_response.resize(vsc_buffer_len(&enrollment_response_buf));
    vsc_buffer_cleanup(&enrollment_response_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return enrollment_response;
}

std::size_t PheServer::verify_password_response_len() {
    auto proxy_result = vsce_phe_server_verify_password_response_len(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> PheServer::verify_password(std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key, std::span<const uint8_t> verify_password_request) {
    std::vector<uint8_t> verify_password_response(this->verify_password_response_len());
    vsc_buffer_t verify_password_response_buf;
    vsc_buffer_init(&verify_password_response_buf);
    vsc_buffer_use(&verify_password_response_buf, verify_password_response.data(), verify_password_response.size());
    const vsce_status_t status = vsce_phe_server_verify_password(c_ctx_, vsc_data(server_private_key.data(), server_private_key.size()), vsc_data(server_public_key.data(), server_public_key.size()), vsc_data(verify_password_request.data(), verify_password_request.size()), &verify_password_response_buf);
    verify_password_response.resize(vsc_buffer_len(&verify_password_response_buf));
    vsc_buffer_cleanup(&verify_password_response_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return verify_password_response;
}

std::size_t PheServer::update_token_len() {
    auto proxy_result = vsce_phe_server_update_token_len(c_ctx_);
    return proxy_result;
}

tl::expected<PheServerRotateKeysResult, Error> PheServer::rotate_keys(std::span<const uint8_t> server_private_key) {
    std::vector<uint8_t> new_server_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t new_server_private_key_buf;
    vsc_buffer_init(&new_server_private_key_buf);
    vsc_buffer_use(&new_server_private_key_buf, new_server_private_key.data(), new_server_private_key.size());
    std::vector<uint8_t> new_server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t new_server_public_key_buf;
    vsc_buffer_init(&new_server_public_key_buf);
    vsc_buffer_use(&new_server_public_key_buf, new_server_public_key.data(), new_server_public_key.size());
    std::vector<uint8_t> update_token(this->update_token_len());
    vsc_buffer_t update_token_buf;
    vsc_buffer_init(&update_token_buf);
    vsc_buffer_use(&update_token_buf, update_token.data(), update_token.size());
    const vsce_status_t status = vsce_phe_server_rotate_keys(c_ctx_, vsc_data(server_private_key.data(), server_private_key.size()), &new_server_private_key_buf, &new_server_public_key_buf, &update_token_buf);
    new_server_private_key.resize(vsc_buffer_len(&new_server_private_key_buf));
    vsc_buffer_cleanup(&new_server_private_key_buf);
    new_server_public_key.resize(vsc_buffer_len(&new_server_public_key_buf));
    vsc_buffer_cleanup(&new_server_public_key_buf);
    update_token.resize(vsc_buffer_len(&update_token_buf));
    vsc_buffer_cleanup(&update_token_buf);
    if (status != vsce_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return PheServerRotateKeysResult{.new_server_private_key = std::move(new_server_private_key), .new_server_public_key = std::move(new_server_public_key), .update_token = std::move(update_token)};
}

}  // namespace virgil::crypto::phe
