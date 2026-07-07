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
#include <virgil/crypto/foundation/context.hpp>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg.hpp>

namespace virgil::crypto::foundation {

/// Provide interface for symmetric key wrapping algorithms (RFC 3394).
class KeyWrap : virtual public Context, virtual public Alg {
public:
    ~KeyWrap() override = default;

    /// Return buffer length required to hold a wrapped key for the given plain key length.
    virtual std::size_t wrapped_len(std::size_t data_len) = 0;

    /// Return buffer length required to hold an unwrapped key for the given wrapped key length.
    virtual std::size_t unwrapped_len(std::size_t data_len) = 0;

    /// Wrap given key data using the Key Encryption Key (KEK).
    virtual tl::expected<std::vector<uint8_t>, Error> wrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) = 0;

    /// Unwrap given key data using the Key Encryption Key (KEK).
    virtual tl::expected<std::vector<uint8_t>, Error> unwrap(std::span<const uint8_t> kek, std::span<const uint8_t> data) = 0;

};

}  // namespace virgil::crypto::foundation
