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
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

/// Simple PEM wrapper.
class Pem {
public:
    /// Return length in bytes required to hold wrapped PEM format.
    static std::size_t wrapped_len(std::string_view title, std::size_t data_len);

    /// Takes binary data and wraps it to the simple PEM format - no
    /// additional information just header-base64-footer.
    /// Note, written buffer is NOT null-terminated.
    static std::vector<uint8_t> wrap(std::string_view title, std::span<const uint8_t> data);

    /// Return length in bytes required to hold unwrapped binary.
    static std::size_t unwrapped_len(std::size_t pem_len);

    /// Takes PEM data and extract binary data from it.
    static tl::expected<std::vector<uint8_t>, Error> unwrap(std::span<const uint8_t> pem);

    /// Returns PEM title if PEM data is valid, otherwise - empty data.
    static std::vector<uint8_t> title(std::span<const uint8_t> pem);

};

}  // namespace virgil::crypto::foundation
