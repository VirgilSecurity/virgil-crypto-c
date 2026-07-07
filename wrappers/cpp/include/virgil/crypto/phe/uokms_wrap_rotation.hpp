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
#include <virgil/crypto/phe/vsce_uokms_wrap_rotation.h>
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/phe/phe_common.hpp>

namespace virgil::crypto::phe {

/// Implements wrap rotation.
class UokmsWrapRotation {
public:
    UokmsWrapRotation() : c_ctx_(vsce_uokms_wrap_rotation_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit UokmsWrapRotation(vsce_uokms_wrap_rotation_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    UokmsWrapRotation(const UokmsWrapRotation& other) : c_ctx_(vsce_uokms_wrap_rotation_shallow_copy(other.c_ctx_)) {}
    UokmsWrapRotation(UokmsWrapRotation&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    UokmsWrapRotation& operator=(const UokmsWrapRotation& other) {
        if (this != &other) {
            vsce_uokms_wrap_rotation_delete(c_ctx_);
            c_ctx_ = vsce_uokms_wrap_rotation_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    UokmsWrapRotation& operator=(UokmsWrapRotation&& other) noexcept {
        if (this != &other) {
            vsce_uokms_wrap_rotation_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~UokmsWrapRotation() { vsce_uokms_wrap_rotation_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vsce_uokms_wrap_rotation_t* c_ctx() const noexcept { return c_ctx_; }

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random) {
        vsce_uokms_wrap_rotation_release_operation_random(c_ctx_);
        vsce_uokms_wrap_rotation_use_operation_random(c_ctx_, operation_random.impl());
    }

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults() {
        const vsce_status_t status = vsce_uokms_wrap_rotation_setup_defaults(c_ctx_);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Sets update token. Should be called only once and before any other function
    tl::expected<void, Error> set_update_token(std::span<const uint8_t> update_token) {
        const vsce_status_t status = vsce_uokms_wrap_rotation_set_update_token(c_ctx_, vsc_data(update_token.data(), update_token.size()));
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Updates EnrollmentRecord using server's update token
    tl::expected<std::vector<uint8_t>, Error> update_wrap(std::span<const uint8_t> wrap) {
        std::vector<uint8_t> new_wrap(PheCommon::PHE_PUBLIC_KEY_LENGTH);
        vsc_buffer_t* new_wrap_buf = vsc_buffer_new();
        vsc_buffer_use(new_wrap_buf, new_wrap.data(), new_wrap.size());
        const vsce_status_t status = vsce_uokms_wrap_rotation_update_wrap(c_ctx_, vsc_data(wrap.data(), wrap.size()), new_wrap_buf);
        new_wrap.resize(vsc_buffer_len(new_wrap_buf));
        vsc_buffer_delete(new_wrap_buf);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return new_wrap;
    }

private:
    vsce_uokms_wrap_rotation_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
