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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/foundation/vscf_message_info_custom_params.h>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

class MessageInfoCustomParams {
public:
    MessageInfoCustomParams() : c_ctx_(vscf_message_info_custom_params_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoCustomParams(vscf_message_info_custom_params_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MessageInfoCustomParams(const MessageInfoCustomParams& other) : c_ctx_(vscf_message_info_custom_params_shallow_copy(other.c_ctx_)) {}
    MessageInfoCustomParams(MessageInfoCustomParams&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MessageInfoCustomParams& operator=(const MessageInfoCustomParams& other) {
        if (this != &other) {
            vscf_message_info_custom_params_delete(c_ctx_);
            c_ctx_ = vscf_message_info_custom_params_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MessageInfoCustomParams& operator=(MessageInfoCustomParams&& other) noexcept {
        if (this != &other) {
            vscf_message_info_custom_params_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MessageInfoCustomParams() { vscf_message_info_custom_params_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_custom_params_t* c_ctx() const noexcept { return c_ctx_; }

    /// Add custom parameter with integer value.
    void add_int(std::span<const uint8_t> key, int32_t value) {
        vscf_message_info_custom_params_add_int(c_ctx_, vsc_data(key.data(), key.size()), value);
    }

    /// Add custom parameter with UTF8 string value.
    void add_string(std::span<const uint8_t> key, std::span<const uint8_t> value) {
        vscf_message_info_custom_params_add_string(c_ctx_, vsc_data(key.data(), key.size()), vsc_data(value.data(), value.size()));
    }

    /// Add custom parameter with octet string value.
    void add_data(std::span<const uint8_t> key, std::span<const uint8_t> value) {
        vscf_message_info_custom_params_add_data(c_ctx_, vsc_data(key.data(), key.size()), vsc_data(value.data(), value.size()));
    }

    /// Remove all parameters.
    void clear() {
        vscf_message_info_custom_params_clear(c_ctx_);
    }

    /// Return custom parameter with integer value.
    tl::expected<int32_t, Error> find_int(std::span<const uint8_t> key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_message_info_custom_params_find_int(c_ctx_, vsc_data(key.data(), key.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return proxy_result;
    }

    /// Return custom parameter with UTF8 string value.
    tl::expected<std::vector<uint8_t>, Error> find_string(std::span<const uint8_t> key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_message_info_custom_params_find_string(c_ctx_, vsc_data(key.data(), key.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Return custom parameter with octet string value.
    tl::expected<std::vector<uint8_t>, Error> find_data(std::span<const uint8_t> key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_message_info_custom_params_find_data(c_ctx_, vsc_data(key.data(), key.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

    /// Return true if at least one param exists.
    bool has_params() const {
        auto proxy_result = vscf_message_info_custom_params_has_params(c_ctx_);
        return proxy_result;
    }

private:
    vscf_message_info_custom_params_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
