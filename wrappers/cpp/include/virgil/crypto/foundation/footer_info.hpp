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
#include <virgil/crypto/foundation/vscf_footer_info.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/signed_data_info.hpp>

namespace virgil::crypto::foundation {

/// Handle meta information about footer.
class FooterInfo {
public:
    FooterInfo() : c_ctx_(vscf_footer_info_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit FooterInfo(vscf_footer_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    FooterInfo(const FooterInfo& other) : c_ctx_(vscf_footer_info_shallow_copy(other.c_ctx_)) {}
    FooterInfo(FooterInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    FooterInfo& operator=(const FooterInfo& other) {
        if (this != &other) {
            vscf_footer_info_delete(c_ctx_);
            c_ctx_ = vscf_footer_info_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    FooterInfo& operator=(FooterInfo&& other) noexcept {
        if (this != &other) {
            vscf_footer_info_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~FooterInfo() { vscf_footer_info_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_footer_info_t* c_ctx() const noexcept { return c_ctx_; }

    /// Retrun true if signed data info present.
    bool has_signed_data_info() {
        auto proxy_result = vscf_footer_info_has_signed_data_info(c_ctx_);
        return proxy_result;
    }

    /// Return signed data info.
    SignedDataInfo signed_data_info() {
        auto proxy_result = vscf_footer_info_signed_data_info(c_ctx_);
        return SignedDataInfo(vscf_signed_data_info_shallow_copy(const_cast<vscf_signed_data_info_t*>(proxy_result)));
    }

    /// Set data size.
    void set_data_size(std::size_t data_size) {
        vscf_footer_info_set_data_size(c_ctx_, data_size);
    }

    /// Return data size.
    std::size_t data_size() {
        auto proxy_result = vscf_footer_info_data_size(c_ctx_);
        return proxy_result;
    }

private:
    vscf_footer_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
