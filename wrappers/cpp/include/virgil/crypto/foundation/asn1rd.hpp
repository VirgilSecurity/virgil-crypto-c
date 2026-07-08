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
#include <virgil/crypto/foundation/asn1_reader.hpp>

struct vscf_asn1rd_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

/// This is MbedTLS implementation of ASN.1 reader.
class Asn1rd : virtual public Asn1Reader {
public:
    Asn1rd();
    /// Adopt ownership of an existing C handle.
    explicit Asn1rd(vscf_asn1rd_t* c_ctx) noexcept;
    Asn1rd(const Asn1rd& other);
    Asn1rd(Asn1rd&& other) noexcept;
    Asn1rd& operator=(const Asn1rd& other);
    Asn1rd& operator=(Asn1rd&& other) noexcept;
    ~Asn1rd();

    /// The underlying concrete C handle (non-owning).
    vscf_asn1rd_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// Reset all internal states and prepare to new ASN.1 reading operations.
    void reset(std::span<const uint8_t> data) override;

    /// Return length in bytes how many bytes are left for reading.
    std::size_t left_len() override;

    /// Return true if status is not "success".
    bool has_error() const override;

    /// Return error code.
    tl::expected<void, Error> status() const override;

    /// Get tag of the current ASN.1 element.
    int32_t get_tag() override;

    /// Get length of the current ASN.1 element.
    std::size_t get_len() override;

    /// Get length of the current ASN.1 element with tag and length itself.
    std::size_t get_data_len() override;

    /// Read ASN.1 type: TAG.
    /// Return element length.
    std::size_t read_tag(int32_t tag) override;

    /// Read ASN.1 type: context-specific TAG.
    /// Return element length.
    /// Return 0 if current position do not points to the requested tag.
    std::size_t read_context_tag(int32_t tag) override;

    /// Read ASN.1 type: INTEGER.
    int32_t read_int() override;

    /// Read ASN.1 type: INTEGER.
    int8_t read_int8() override;

    /// Read ASN.1 type: INTEGER.
    int16_t read_int16() override;

    /// Read ASN.1 type: INTEGER.
    int32_t read_int32() override;

    /// Read ASN.1 type: INTEGER.
    int64_t read_int64() override;

    /// Read ASN.1 type: INTEGER.
    uint32_t read_uint() override;

    /// Read ASN.1 type: INTEGER.
    uint8_t read_uint8() override;

    /// Read ASN.1 type: INTEGER.
    uint16_t read_uint16() override;

    /// Read ASN.1 type: INTEGER.
    uint32_t read_uint32() override;

    /// Read ASN.1 type: INTEGER.
    uint64_t read_uint64() override;

    /// Read ASN.1 type: BOOLEAN.
    bool read_bool() override;

    /// Read ASN.1 type: NULL.
    void read_null() override;

    /// Read ASN.1 type: NULL, only if it exists.
    /// Note, this method is safe to call even no more data is left for reading.
    void read_null_optional() override;

    /// Read ASN.1 type: OCTET STRING.
    std::vector<uint8_t> read_octet_str() override;

    /// Read ASN.1 type: BIT STRING.
    std::vector<uint8_t> read_bitstring_as_octet_str() override;

    /// Read ASN.1 type: UTF8String.
    std::vector<uint8_t> read_utf8_str() override;

    /// Read ASN.1 type: OID.
    std::vector<uint8_t> read_oid() override;

    /// Read raw data of given length.
    std::vector<uint8_t> read_data(std::size_t len) override;

    /// Read ASN.1 type: SEQUENCE.
    /// Return element length.
    std::size_t read_sequence() override;

    /// Read ASN.1 type: SET.
    /// Return element length.
    std::size_t read_set() override;

private:
    vscf_asn1rd_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
