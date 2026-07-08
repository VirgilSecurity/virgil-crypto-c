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

struct vscf_footer_info_t;

namespace virgil::crypto::foundation {

class SignedDataInfo;

/// Handle meta information about footer.
class FooterInfo {
public:
    FooterInfo();
    /// Adopt ownership of an existing C handle.
    explicit FooterInfo(vscf_footer_info_t* c_ctx) noexcept;
    FooterInfo(const FooterInfo& other);
    FooterInfo(FooterInfo&& other) noexcept;
    FooterInfo& operator=(const FooterInfo& other);
    FooterInfo& operator=(FooterInfo&& other) noexcept;
    ~FooterInfo();

    /// The underlying concrete C handle (non-owning).
    vscf_footer_info_t* c_ctx() const noexcept;

    /// Retrun true if signed data info present.
    bool has_signed_data_info() const;

    /// Return signed data info.
    SignedDataInfo signed_data_info() const;

    /// Set data size.
    void set_data_size(std::size_t data_size);

    /// Return data size.
    std::size_t data_size() const;

private:
    vscf_footer_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
