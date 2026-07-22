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
#include <virgil/crypto/foundation/context.hpp>
#include <virgil/crypto/foundation/error.hpp>

namespace virgil::crypto::foundation {

/// Provides interface to the ASN.1 reader.
/// Note, that all "read" methods move reading position forward.
/// Note, that all "get" do not change reading position.
class Asn1Reader : virtual public Context {
public:
    ~Asn1Reader() override = default;

    /// Reset all internal states and prepare to new ASN.1 reading operations.
    virtual void reset(std::span<const uint8_t> data) = 0;

    /// Return length in bytes how many bytes are left for reading.
    virtual std::size_t left_len() = 0;

    /// Return true if status is not "success".
    virtual bool has_error() const = 0;

    /// Return error code.
    virtual tl::expected<void, Error> status() const = 0;

    /// Get tag of the current ASN.1 element.
    virtual int32_t get_tag() = 0;

    /// Get length of the current ASN.1 element.
    virtual std::size_t get_len() = 0;

    /// Get length of the current ASN.1 element with tag and length itself.
    virtual std::size_t get_data_len() = 0;

    /// Read ASN.1 type: TAG.
    /// Return element length.
    virtual std::size_t read_tag(int32_t tag) = 0;

    /// Read ASN.1 type: context-specific TAG.
    /// Return element length.
    /// Return 0 if current position do not points to the requested tag.
    virtual std::size_t read_context_tag(int32_t tag) = 0;

    /// Read ASN.1 type: INTEGER.
    virtual int32_t read_int() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual int8_t read_int8() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual int16_t read_int16() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual int32_t read_int32() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual int64_t read_int64() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual uint32_t read_uint() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual uint8_t read_uint8() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual uint16_t read_uint16() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual uint32_t read_uint32() = 0;

    /// Read ASN.1 type: INTEGER.
    virtual uint64_t read_uint64() = 0;

    /// Read ASN.1 type: BOOLEAN.
    virtual bool read_bool() = 0;

    /// Read ASN.1 type: NULL.
    virtual void read_null() = 0;

    /// Read ASN.1 type: NULL, only if it exists.
    /// Note, this method is safe to call even no more data is left for reading.
    virtual void read_null_optional() = 0;

    /// Read ASN.1 type: OCTET STRING.
    virtual std::vector<uint8_t> read_octet_str() = 0;

    /// Read ASN.1 type: BIT STRING.
    virtual std::vector<uint8_t> read_bitstring_as_octet_str() = 0;

    /// Read ASN.1 type: UTF8String.
    virtual std::vector<uint8_t> read_utf8_str() = 0;

    /// Read ASN.1 type: OID.
    virtual std::vector<uint8_t> read_oid() = 0;

    /// Read raw data of given length.
    virtual std::vector<uint8_t> read_data(std::size_t len) = 0;

    /// Read ASN.1 type: SEQUENCE.
    /// Return element length.
    virtual std::size_t read_sequence() = 0;

    /// Read ASN.1 type: SET.
    /// Return element length.
    virtual std::size_t read_set() = 0;

};

}  // namespace virgil::crypto::foundation
