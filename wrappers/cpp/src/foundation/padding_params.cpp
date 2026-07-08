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

#include <virgil/crypto/foundation/padding_params.hpp>
#include <virgil/crypto/foundation/vscf_padding_params.h>
#include <virgil/crypto/foundation/vscf_impl.h>

namespace virgil::crypto::foundation {

PaddingParams::PaddingParams() : c_ctx_(vscf_padding_params_new()) {}

PaddingParams::PaddingParams(vscf_padding_params_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

PaddingParams::PaddingParams(const PaddingParams& other) : c_ctx_(vscf_padding_params_shallow_copy(other.c_ctx_)) {}

PaddingParams::PaddingParams(PaddingParams&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

PaddingParams& PaddingParams::operator=(const PaddingParams& other) {
    if (this != &other) {
        vscf_padding_params_delete(c_ctx_);
        c_ctx_ = vscf_padding_params_shallow_copy(other.c_ctx_);
    }
    return *this;
}

PaddingParams& PaddingParams::operator=(PaddingParams&& other) noexcept {
    if (this != &other) {
        vscf_padding_params_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

PaddingParams::~PaddingParams() { vscf_padding_params_delete(c_ctx_); }

vscf_padding_params_t* PaddingParams::c_ctx() const noexcept { return c_ctx_; }

std::size_t PaddingParams::frame() const {
    auto proxy_result = vscf_padding_params_frame(c_ctx_);
    return proxy_result;
}

std::size_t PaddingParams::frame_max() const {
    auto proxy_result = vscf_padding_params_frame_max(c_ctx_);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
