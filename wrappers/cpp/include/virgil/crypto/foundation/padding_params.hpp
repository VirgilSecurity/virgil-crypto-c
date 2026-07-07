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
#include <virgil/crypto/foundation/vscf_padding_params.h>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

/// Handles padding parameters and constraints.
class PaddingParams {
public:
    PaddingParams() : c_ctx_(vscf_padding_params_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit PaddingParams(vscf_padding_params_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    PaddingParams(const PaddingParams& other) : c_ctx_(vscf_padding_params_shallow_copy(other.c_ctx_)) {}
    PaddingParams(PaddingParams&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    PaddingParams& operator=(const PaddingParams& other) {
        if (this != &other) {
            vscf_padding_params_delete(c_ctx_);
            c_ctx_ = vscf_padding_params_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    PaddingParams& operator=(PaddingParams&& other) noexcept {
        if (this != &other) {
            vscf_padding_params_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~PaddingParams() { vscf_padding_params_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_padding_params_t* c_ctx() const noexcept { return c_ctx_; }

    static constexpr std::size_t DEFAULT_FRAME_MIN = 32;

    static constexpr std::size_t DEFAULT_FRAME = 160;

    static constexpr std::size_t DEFAULT_FRAME_MAX = 256;

    /// Return padding frame in bytes.
    std::size_t frame() {
        auto proxy_result = vscf_padding_params_frame(c_ctx_);
        return proxy_result;
    }

    /// Return maximum padding frame in bytes.
    std::size_t frame_max() {
        auto proxy_result = vscf_padding_params_frame_max(c_ctx_);
        return proxy_result;
    }

private:
    vscf_padding_params_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
