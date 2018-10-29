/// Copyright (C) 2015-2018 Virgil Security Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation
import VirgilCryptoCommon

/// Provides interface to the ASN.1 reader.
/// Note, that all "read" methods move reading position forward.
/// Note, that all "get" do not change reading position.
@objc(VSCFAsn1Reader) public protocol Asn1Reader : CContext {

    @objc func reset(data: Data)

    @objc func error() throws

    @objc func getTag() -> Int32

    @objc func getLen() -> Int

    @objc func readTag(tag: Int32) -> Int

    @objc func readInt() -> Int32

    @objc func readInt8() -> Int8

    @objc func readInt16() -> Int16

    @objc func readInt32() -> Int32

    @objc func readInt64() -> Int64

    @objc func readUint() -> UInt32

    @objc func readUint8() -> UInt8

    @objc func readUint16() -> UInt16

    @objc func readUint32() -> UInt32

    @objc func readUint64() -> UInt64

    @objc func readBool() -> Bool

    @objc func readNull()

    @objc func readOctetStr() -> Data

    @objc func readUtf8Str() -> Data

    @objc func readOid() -> Data

    @objc func readData(len: Int) -> Data

    @objc func readSequence() -> Int

    @objc func readSet() -> Int
}

/// Implement interface methods
@objc(VSCFAsn1ReaderProxy) internal class Asn1ReaderProxy: NSObject, Asn1Reader {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }

    /// Reset all internal states and prepare to new ASN.1 reading operations.
    @objc public func reset(data: Data) {
        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            vscf_asn1_reader_reset(self.c_ctx, vsc_data(dataPointer, data.count))
        })
    }

    /// Return last error.
    @objc public func error() throws {
        let proxyResult = vscf_asn1_reader_error(self.c_ctx)
        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Get tag of the current ASN.1 element.
    @objc public func getTag() -> Int32 {
        let proxyResult = vscf_asn1_reader_get_tag(self.c_ctx)
        return proxyResult
    }

    /// Get length of the current ASN.1 element.
    @objc public func getLen() -> Int {
        let proxyResult = vscf_asn1_reader_get_len(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: TAG.
    /// Return element length.
    @objc public func readTag(tag: Int32) -> Int {
        let proxyResult = vscf_asn1_reader_read_tag(self.c_ctx, tag)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readInt() -> Int32 {
        let proxyResult = vscf_asn1_reader_read_int(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readInt8() -> Int8 {
        let proxyResult = vscf_asn1_reader_read_int8(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readInt16() -> Int16 {
        let proxyResult = vscf_asn1_reader_read_int16(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readInt32() -> Int32 {
        let proxyResult = vscf_asn1_reader_read_int32(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readInt64() -> Int64 {
        let proxyResult = vscf_asn1_reader_read_int64(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readUint() -> UInt32 {
        let proxyResult = vscf_asn1_reader_read_uint(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readUint8() -> UInt8 {
        let proxyResult = vscf_asn1_reader_read_uint8(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readUint16() -> UInt16 {
        let proxyResult = vscf_asn1_reader_read_uint16(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readUint32() -> UInt32 {
        let proxyResult = vscf_asn1_reader_read_uint32(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: INTEGER.
    @objc public func readUint64() -> UInt64 {
        let proxyResult = vscf_asn1_reader_read_uint64(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: BOOLEAN.
    @objc public func readBool() -> Bool {
        let proxyResult = vscf_asn1_reader_read_bool(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: NULL.
    @objc public func readNull() {
        vscf_asn1_reader_read_null(self.c_ctx)
    }

    /// Read ASN.1 type: OCTET STRING.
    @objc public func readOctetStr() -> Data {
        let proxyResult = vscf_asn1_reader_read_octet_str(self.c_ctx)
        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Read ASN.1 type: UTF8String.
    @objc public func readUtf8Str() -> Data {
        let proxyResult = vscf_asn1_reader_read_utf8_str(self.c_ctx)
        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Read ASN.1 type: OID.
    @objc public func readOid() -> Data {
        let proxyResult = vscf_asn1_reader_read_oid(self.c_ctx)
        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Read raw data of given length.
    @objc public func readData(len: Int) -> Data {
        let proxyResult = vscf_asn1_reader_read_data(self.c_ctx, len)
        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    /// Return element length.
    @objc public func readSequence() -> Int {
        let proxyResult = vscf_asn1_reader_read_sequence(self.c_ctx)
        return proxyResult
    }

    /// Read ASN.1 type: CONSTRUCTED | SET.
    /// Return element length.
    @objc public func readSet() -> Int {
        let proxyResult = vscf_asn1_reader_read_set(self.c_ctx)
        return proxyResult
    }
}
