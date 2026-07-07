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
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/foundation/vscf_pem.h>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

/// Simple PEM wrapper.
class Pem {
public:
    /// Return length in bytes required to hold wrapped PEM format.
    static std::size_t wrapped_len(const std::string& title, std::size_t data_len) {
        auto proxy_result = vscf_pem_wrapped_len(title.c_str(), data_len);
        return proxy_result;
    }

    /// Takes binary data and wraps it to the simple PEM format - no
    /// additional information just header-base64-footer.
    /// Note, written buffer is NOT null-terminated.
    static std::vector<uint8_t> wrap(const std::string& title, std::span<const uint8_t> data) {
        std::vector<uint8_t> pem(Pem::wrapped_len(title, data.size()));
        vsc_buffer_t* pem_buf = vsc_buffer_new();
        vsc_buffer_use(pem_buf, pem.data(), pem.size());
        vscf_pem_wrap(title.c_str(), vsc_data(data.data(), data.size()), pem_buf);
        pem.resize(vsc_buffer_len(pem_buf));
        vsc_buffer_delete(pem_buf);
        return pem;
    }

    /// Return length in bytes required to hold unwrapped binary.
    static std::size_t unwrapped_len(std::size_t pem_len) {
        auto proxy_result = vscf_pem_unwrapped_len(pem_len);
        return proxy_result;
    }

    /// Takes PEM data and extract binary data from it.
    static tl::expected<std::vector<uint8_t>, Error> unwrap(std::span<const uint8_t> pem) {
        std::vector<uint8_t> data(Pem::unwrapped_len(pem.size()));
        vsc_buffer_t* data_buf = vsc_buffer_new();
        vsc_buffer_use(data_buf, data.data(), data.size());
        const vscf_status_t status = vscf_pem_unwrap(vsc_data(pem.data(), pem.size()), data_buf);
        data.resize(vsc_buffer_len(data_buf));
        vsc_buffer_delete(data_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return data;
    }

    /// Returns PEM title if PEM data is valid, otherwise - empty data.
    static std::vector<uint8_t> title(std::span<const uint8_t> pem) {
        auto proxy_result = vscf_pem_title(vsc_data(pem.data(), pem.size()));
        return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
    }

};

}  // namespace virgil::crypto::foundation
