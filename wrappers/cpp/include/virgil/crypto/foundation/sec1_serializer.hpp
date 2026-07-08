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
#include <virgil/crypto/foundation/key_serializer.hpp>

struct vscf_sec1_serializer_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class Asn1Writer;
class RawPrivateKey;
class RawPublicKey;

/// Implements SEC 1 key serialization to DER format.
/// See also RFC 5480 and RFC 5915.
class Sec1Serializer : virtual public KeySerializer {
public:
    Sec1Serializer();
    /// Adopt ownership of an existing C handle.
    explicit Sec1Serializer(vscf_sec1_serializer_t* c_ctx) noexcept;
    Sec1Serializer(const Sec1Serializer& other);
    Sec1Serializer(Sec1Serializer&& other) noexcept;
    Sec1Serializer& operator=(const Sec1Serializer& other);
    Sec1Serializer& operator=(Sec1Serializer&& other) noexcept;
    ~Sec1Serializer();

    /// The underlying concrete C handle (non-owning).
    vscf_sec1_serializer_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    void set_asn1_writer(const Asn1Writer& asn1_writer);

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults();

    /// Serialize Public Key by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    tl::expected<std::size_t, Error> serialize_public_key_inplace(const RawPublicKey& public_key);

    /// Serialize Private Key by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    tl::expected<std::size_t, Error> serialize_private_key_inplace(const RawPrivateKey& private_key);

    /// Calculate buffer size enough to hold serialized public key.
    ///
    /// Precondition: public key must be exportable.
    std::size_t serialized_public_key_len(const RawPublicKey& public_key) const override;

    /// Serialize given public key to an interchangeable format.
    ///
    /// Precondition: public key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> serialize_public_key(const RawPublicKey& public_key) override;

    /// Calculate buffer size enough to hold serialized private key.
    ///
    /// Precondition: private key must be exportable.
    std::size_t serialized_private_key_len(const RawPrivateKey& private_key) const override;

    /// Serialize given private key to an interchangeable format.
    ///
    /// Precondition: private key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> serialize_private_key(const RawPrivateKey& private_key) override;

private:
    vscf_sec1_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
