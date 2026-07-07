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

/// Provides interface to the ASN.1 writer.
/// Note, elements are written starting from the buffer ending.
/// Note, that all "write" methods move writing position backward.
class Asn1Writer : virtual public Context {
public:
    ~Asn1Writer() override = default;

    /// Reset all internal states and prepare to new ASN.1 writing operations.
    virtual void reset(uint8_t* out, std::size_t out_len) = 0;

    /// Finalize writing and forbid further operations.
    ///
    /// Note, that ASN.1 structure is always written to the buffer end, and
    /// if argument "do not adjust" is false, then data is moved to the
    /// beginning, otherwise - data is left at the buffer end.
    ///
    /// Returns length of the written bytes.
    virtual std::size_t finish(bool do_not_adjust) = 0;

    /// Returns pointer to the inner buffer.
    virtual uint8_t* bytes() = 0;

    /// Returns total inner buffer length.
    virtual std::size_t len() = 0;

    /// Returns how many bytes were already written to the ASN.1 structure.
    virtual std::size_t written_len() = 0;

    /// Returns how many bytes are available for writing.
    virtual std::size_t unwritten_len() = 0;

    /// Return true if status is not "success".
    virtual bool has_error() = 0;

    /// Return error code.
    virtual tl::expected<void, Error> status() = 0;

    /// Move writing position backward for the given length.
    /// Return current writing position.
    virtual uint8_t* reserve(std::size_t len) = 0;

    /// Write ASN.1 tag.
    /// Return count of written bytes.
    virtual std::size_t write_tag(int32_t tag) = 0;

    /// Write context-specific ASN.1 tag.
    /// Return count of written bytes.
    virtual std::size_t write_context_tag(int32_t tag, std::size_t len) = 0;

    /// Write length of the following data.
    /// Return count of written bytes.
    virtual std::size_t write_len(std::size_t len) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_int(int32_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_int8(int8_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_int16(int16_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_int32(int32_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_int64(int64_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_uint(uint32_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_uint8(uint8_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_uint16(uint16_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_uint32(uint32_t value) = 0;

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    virtual std::size_t write_uint64(uint64_t value) = 0;

    /// Write ASN.1 type: BOOLEAN.
    /// Return count of written bytes.
    virtual std::size_t write_bool(bool value) = 0;

    /// Write ASN.1 type: NULL.
    virtual std::size_t write_null() = 0;

    /// Write ASN.1 type: OCTET STRING.
    /// Return count of written bytes.
    virtual std::size_t write_octet_str(std::span<const uint8_t> value) = 0;

    /// Write ASN.1 type: BIT STRING with all zero unused bits.
    ///
    /// Return count of written bytes.
    virtual std::size_t write_octet_str_as_bitstring(std::span<const uint8_t> value) = 0;

    /// Write raw data directly to the ASN.1 structure.
    /// Return count of written bytes.
    /// Note, use this method carefully.
    virtual std::size_t write_data(std::span<const uint8_t> data) = 0;

    /// Write ASN.1 type: UTF8String.
    /// Return count of written bytes.
    virtual std::size_t write_utf8_str(std::span<const uint8_t> value) = 0;

    /// Write ASN.1 type: OID.
    /// Return count of written bytes.
    virtual std::size_t write_oid(std::span<const uint8_t> value) = 0;

    /// Mark previously written data of given length as ASN.1 type: SEQUENCE.
    /// Return count of written bytes.
    virtual std::size_t write_sequence(std::size_t len) = 0;

    /// Mark previously written data of given length as ASN.1 type: SET.
    /// Return count of written bytes.
    virtual std::size_t write_set(std::size_t len) = 0;

};

}  // namespace virgil::crypto::foundation
