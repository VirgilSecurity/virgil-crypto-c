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
#include <virgil/crypto/foundation/alg_info_serializer.hpp>

struct vscf_alg_info_der_serializer_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class Asn1Writer;

/// Provide DER serializer of algorithm information.
class AlgInfoDerSerializer : virtual public AlgInfoSerializer {
public:
    AlgInfoDerSerializer();
    /// Adopt ownership of an existing C handle.
    explicit AlgInfoDerSerializer(vscf_alg_info_der_serializer_t* c_ctx) noexcept;
    AlgInfoDerSerializer(const AlgInfoDerSerializer& other);
    AlgInfoDerSerializer(AlgInfoDerSerializer&& other) noexcept;
    AlgInfoDerSerializer& operator=(const AlgInfoDerSerializer& other);
    AlgInfoDerSerializer& operator=(AlgInfoDerSerializer&& other) noexcept;
    ~AlgInfoDerSerializer();

    /// The underlying concrete C handle (non-owning).
    vscf_alg_info_der_serializer_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    void set_asn1_writer(const Asn1Writer& asn1_writer);

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults();

    /// Serialize by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    std::size_t serialize_inplace(const AlgInfo& alg_info);

    /// Return buffer size enough to hold serialized algorithm.
    std::size_t serialized_len(const AlgInfo& alg_info) const override;

    /// Serialize algorithm info to buffer class.
    std::vector<uint8_t> serialize(const AlgInfo& alg_info) override;

private:
    vscf_alg_info_der_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
