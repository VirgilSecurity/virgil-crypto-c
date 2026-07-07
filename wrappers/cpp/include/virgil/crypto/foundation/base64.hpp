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
#include <virgil/crypto/foundation/vscf_base64.h>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

/// Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
class Base64 {
public:
    /// Calculate length in bytes required to hold an encoded base64 string.
    static std::size_t encoded_len(std::size_t data_len) {
        auto proxy_result = vscf_base64_encoded_len(data_len);
        return proxy_result;
    }

    /// Encode given data to the base64 format.
    /// Note, written buffer is NOT null-terminated.
    static std::vector<uint8_t> encode(std::span<const uint8_t> data) {
        std::vector<uint8_t> str(Base64::encoded_len(data.size()));
        vsc_buffer_t* str_buf = vsc_buffer_new();
        vsc_buffer_use(str_buf, str.data(), str.size());
        vscf_base64_encode(vsc_data(data.data(), data.size()), str_buf);
        str.resize(vsc_buffer_len(str_buf));
        vsc_buffer_delete(str_buf);
        return str;
    }

    /// Calculate length in bytes required to hold a decoded base64 string.
    static std::size_t decoded_len(std::size_t str_len) {
        auto proxy_result = vscf_base64_decoded_len(str_len);
        return proxy_result;
    }

    /// Decode given data from the base64 format.
    static tl::expected<std::vector<uint8_t>, Error> decode(std::span<const uint8_t> str) {
        std::vector<uint8_t> data(Base64::decoded_len(str.size()));
        vsc_buffer_t* data_buf = vsc_buffer_new();
        vsc_buffer_use(data_buf, data.data(), data.size());
        const vscf_status_t status = vscf_base64_decode(vsc_data(str.data(), str.size()), data_buf);
        data.resize(vsc_buffer_len(data_buf));
        vsc_buffer_delete(data_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return data;
    }

};

}  // namespace virgil::crypto::foundation
