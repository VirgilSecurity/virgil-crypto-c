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

#include <virgil/crypto/foundation/message_info_custom_params.hpp>
#include <virgil/crypto/foundation/vscf_message_info_custom_params.h>
#include <virgil/crypto/foundation/vscf_impl.h>

namespace virgil::crypto::foundation {

MessageInfoCustomParams::MessageInfoCustomParams() : c_ctx_(vscf_message_info_custom_params_new()) {}

MessageInfoCustomParams::MessageInfoCustomParams(vscf_message_info_custom_params_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

MessageInfoCustomParams::MessageInfoCustomParams(const MessageInfoCustomParams& other) : c_ctx_(vscf_message_info_custom_params_shallow_copy(other.c_ctx_)) {}

MessageInfoCustomParams::MessageInfoCustomParams(MessageInfoCustomParams&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

MessageInfoCustomParams& MessageInfoCustomParams::operator=(const MessageInfoCustomParams& other) {
    if (this != &other) {
        vscf_message_info_custom_params_delete(c_ctx_);
        c_ctx_ = vscf_message_info_custom_params_shallow_copy(other.c_ctx_);
    }
    return *this;
}

MessageInfoCustomParams& MessageInfoCustomParams::operator=(MessageInfoCustomParams&& other) noexcept {
    if (this != &other) {
        vscf_message_info_custom_params_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

MessageInfoCustomParams::~MessageInfoCustomParams() { vscf_message_info_custom_params_delete(c_ctx_); }

vscf_message_info_custom_params_t* MessageInfoCustomParams::c_ctx() const noexcept { return c_ctx_; }

void MessageInfoCustomParams::add_int(std::span<const uint8_t> key, int32_t value) {
    vscf_message_info_custom_params_add_int(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), value);
}

void MessageInfoCustomParams::add_string(std::span<const uint8_t> key, std::span<const uint8_t> value) {
    vscf_message_info_custom_params_add_string(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), value.empty() ? vsc_data_empty() : vsc_data(value.data(), value.size()));
}

void MessageInfoCustomParams::add_data(std::span<const uint8_t> key, std::span<const uint8_t> value) {
    vscf_message_info_custom_params_add_data(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), value.empty() ? vsc_data_empty() : vsc_data(value.data(), value.size()));
}

void MessageInfoCustomParams::clear() {
    vscf_message_info_custom_params_clear(c_ctx_);
}

tl::expected<int32_t, Error> MessageInfoCustomParams::find_int(std::span<const uint8_t> key) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_message_info_custom_params_find_int(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> MessageInfoCustomParams::find_string(std::span<const uint8_t> key) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_message_info_custom_params_find_string(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

tl::expected<std::vector<uint8_t>, Error> MessageInfoCustomParams::find_data(std::span<const uint8_t> key) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_message_info_custom_params_find_data(c_ctx_, key.empty() ? vsc_data_empty() : vsc_data(key.data(), key.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

bool MessageInfoCustomParams::has_params() const {
    auto proxy_result = vscf_message_info_custom_params_has_params(c_ctx_);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
