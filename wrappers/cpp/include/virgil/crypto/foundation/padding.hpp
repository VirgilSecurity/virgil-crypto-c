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
#include <virgil/crypto/foundation/context.hpp>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

class PaddingParams;

/// Provide an interface to add and remove data padding.
class Padding : virtual public Context {
public:
    ~Padding() override = default;

    /// Set new padding parameters.
    virtual void configure(const PaddingParams& params) = 0;

    /// Return length in bytes of a data with a padding.
    virtual std::size_t padded_data_len(std::size_t data_len) = 0;

    /// Return an actual number of padding in bytes.
    /// Note, this method might be called right before "finish data processing".
    virtual std::size_t len() = 0;

    /// Return a maximum number of padding in bytes.
    virtual std::size_t len_max() = 0;

    /// Prepare the algorithm to process data.
    virtual void start_data_processing() = 0;

    /// Only data length is needed to produce padding later.
    /// Return data that should be further proceeded.
    virtual std::vector<uint8_t> process_data(std::span<const uint8_t> data) = 0;

    /// Accomplish data processing and return padding.
    virtual tl::expected<std::vector<uint8_t>, Error> finish_data_processing() = 0;

    /// Prepare the algorithm to process padded data.
    virtual void start_padded_data_processing() = 0;

    /// Process padded data.
    /// Return filtered data without padding.
    virtual std::vector<uint8_t> process_padded_data(std::span<const uint8_t> data) = 0;

    /// Return length in bytes required hold output of the method
    /// "finish padded data processing".
    virtual std::size_t finish_padded_data_processing_out_len() = 0;

    /// Accomplish padded data processing and return left data without a padding.
    virtual tl::expected<std::vector<uint8_t>, Error> finish_padded_data_processing() = 0;

};

}  // namespace virgil::crypto::foundation
