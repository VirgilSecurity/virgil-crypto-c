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
#include <memory>
#include <virgil/crypto/foundation/error.hpp>

struct vscf_signer_info_t;

namespace virgil::crypto::foundation {

class AlgInfo;

/// Handle information about signer that is defined by an identifer and
/// a Public Key.
class SignerInfo {
public:
    SignerInfo();
    /// Adopt ownership of an existing C handle.
    explicit SignerInfo(vscf_signer_info_t* c_ctx) noexcept;
    SignerInfo(const SignerInfo& other);
    SignerInfo(SignerInfo&& other) noexcept;
    SignerInfo& operator=(const SignerInfo& other);
    SignerInfo& operator=(SignerInfo&& other) noexcept;
    ~SignerInfo();

    /// The underlying concrete C handle (non-owning).
    vscf_signer_info_t* c_ctx() const noexcept;

    /// Return signer identifier.
    std::vector<uint8_t> signer_id() const;

    /// Return algorithm information that was used for data signing.
    std::unique_ptr<AlgInfo> signer_alg_info() const;

    /// Return data signature.
    std::vector<uint8_t> signature() const;

private:
    vscf_signer_info_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
