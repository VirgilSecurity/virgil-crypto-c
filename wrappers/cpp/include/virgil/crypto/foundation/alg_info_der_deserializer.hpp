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
#include <virgil/crypto/foundation/alg_info_deserializer.hpp>

struct vscf_alg_info_der_deserializer_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class Asn1Reader;

/// Provide DER deserializer of algorithm information.
class AlgInfoDerDeserializer : virtual public AlgInfoDeserializer {
public:
    AlgInfoDerDeserializer();
    /// Adopt ownership of an existing C handle.
    explicit AlgInfoDerDeserializer(vscf_alg_info_der_deserializer_t* c_ctx) noexcept;
    AlgInfoDerDeserializer(const AlgInfoDerDeserializer& other);
    AlgInfoDerDeserializer(AlgInfoDerDeserializer&& other) noexcept;
    AlgInfoDerDeserializer& operator=(const AlgInfoDerDeserializer& other);
    AlgInfoDerDeserializer& operator=(AlgInfoDerDeserializer&& other) noexcept;
    ~AlgInfoDerDeserializer();

    /// The underlying concrete C handle (non-owning).
    vscf_alg_info_der_deserializer_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    void set_asn1_reader(const Asn1Reader& asn1_reader);

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults();

    /// Deserialize by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    tl::expected<std::unique_ptr<AlgInfo>, Error> deserialize_inplace();

    /// Deserialize algorithm from the data.
    tl::expected<std::unique_ptr<AlgInfo>, Error> deserialize(std::span<const uint8_t> data) override;

private:
    vscf_alg_info_der_deserializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
