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

/// Provides interface to the ASN.1 writer.
/// Note, elements are written starting from the buffer ending.
/// Note, that all "write" methods move writing position backward.
@objc(VSCFAsn1Writer) public protocol Asn1Writer : CContext {

    @objc func reset(out: UnsafeMutablePointer<UInt8>, outLen: Int)

    @objc func finish() -> Int

    @objc func error() throws

    @objc func reserve(len: Int) -> UnsafeMutablePointer<UInt8>

    @objc func writeTag(tag: Int32) -> Int

    @objc func writeLen(len: Int) -> Int

    @objc func writeInt(value: Int32) -> Int

    @objc func writeInt8(value: Int8) -> Int

    @objc func writeInt16(value: Int16) -> Int

    @objc func writeInt32(value: Int32) -> Int

    @objc func writeInt64(value: Int64) -> Int

    @objc func writeUint(value: UInt32) -> Int

    @objc func writeUint8(value: UInt8) -> Int

    @objc func writeUint16(value: UInt16) -> Int

    @objc func writeUint32(value: UInt32) -> Int

    @objc func writeUint64(value: UInt64) -> Int

    @objc func writeBool(value: Bool) -> Int

    @objc func writeNull() -> Int

    @objc func writeOctetStr(value: Data) -> Int

    @objc func writeUtf8Str(value: Data) -> Int

    @objc func writeOid(value: Data) -> Int

    @objc func writeSequence(len: Int) -> Int

    @objc func writeSet(len: Int) -> Int
}

/// Implement interface methods
@objc(VSCFAsn1WriterProxy) internal class Asn1WriterProxy: NSObject, Asn1Writer {

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

    /// Reset all internal states and prepare to new ASN.1 writing operations.
    @objc public func reset(out: UnsafeMutablePointer<UInt8>, outLen: Int) {
        vscf_asn1_writer_reset(self.c_ctx, out, outLen)
    }

    /// Move written data to the buffer beginning and forbid further operations.
    /// Returns written size in bytes.
    @objc public func finish() -> Int {
        let proxyResult = vscf_asn1_writer_finish(self.c_ctx)
        return proxyResult
    }

    /// Return last error.
    @objc public func error() throws {
        let proxyResult = vscf_asn1_writer_error(self.c_ctx)
        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Move writing position backward for the given length.
    /// Return current writing position.
    @objc public func reserve(len: Int) -> UnsafeMutablePointer<UInt8> {
        let proxyResult = vscf_asn1_writer_reserve(self.c_ctx, len)
        return proxyResult!
    }

    /// Write ASN.1 tag.
    /// Return count of written bytes.
    @objc public func writeTag(tag: Int32) -> Int {
        let proxyResult = vscf_asn1_writer_write_tag(self.c_ctx, tag)
        return proxyResult
    }

    /// Write length of the following data.
    /// Return count of written bytes.
    @objc public func writeLen(len: Int) -> Int {
        let proxyResult = vscf_asn1_writer_write_len(self.c_ctx, len)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeInt(value: Int32) -> Int {
        let proxyResult = vscf_asn1_writer_write_int(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeInt8(value: Int8) -> Int {
        let proxyResult = vscf_asn1_writer_write_int8(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeInt16(value: Int16) -> Int {
        let proxyResult = vscf_asn1_writer_write_int16(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeInt32(value: Int32) -> Int {
        let proxyResult = vscf_asn1_writer_write_int32(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeInt64(value: Int64) -> Int {
        let proxyResult = vscf_asn1_writer_write_int64(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeUint(value: UInt32) -> Int {
        let proxyResult = vscf_asn1_writer_write_uint(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeUint8(value: UInt8) -> Int {
        let proxyResult = vscf_asn1_writer_write_uint8(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeUint16(value: UInt16) -> Int {
        let proxyResult = vscf_asn1_writer_write_uint16(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeUint32(value: UInt32) -> Int {
        let proxyResult = vscf_asn1_writer_write_uint32(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc public func writeUint64(value: UInt64) -> Int {
        let proxyResult = vscf_asn1_writer_write_uint64(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: BOOLEAN.
    /// Return count of written bytes.
    @objc public func writeBool(value: Bool) -> Int {
        let proxyResult = vscf_asn1_writer_write_bool(self.c_ctx, value)
        return proxyResult
    }

    /// Write ASN.1 type: NULL.
    @objc public func writeNull() -> Int {
        let proxyResult = vscf_asn1_writer_write_null(self.c_ctx)
        return proxyResult
    }

    /// Write ASN.1 type: OCTET STRING.
    /// Return count of written bytes.
    @objc public func writeOctetStr(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafePointer<byte>) -> Int in
            return vscf_asn1_writer_write_octet_str(self.c_ctx, vsc_data(valuePointer, value.count))
        })

        return proxyResult
    }

    /// Write ASN.1 type: UTF8String.
    /// Return count of written bytes.
    @objc public func writeUtf8Str(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafePointer<byte>) -> Int in
            return vscf_asn1_writer_write_utf8_str(self.c_ctx, vsc_data(valuePointer, value.count))
        })

        return proxyResult
    }

    /// Write ASN.1 type: OID.
    /// Return count of written bytes.
    @objc public func writeOid(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafePointer<byte>) -> Int in
            return vscf_asn1_writer_write_oid(self.c_ctx, vsc_data(valuePointer, value.count))
        })

        return proxyResult
    }

    /// Mark previously written data of given length as ASN.1 type: SQUENCE.
    /// Return count of written bytes.
    @objc public func writeSequence(len: Int) -> Int {
        let proxyResult = vscf_asn1_writer_write_sequence(self.c_ctx, len)
        return proxyResult
    }

    /// Mark previously written data of given length as ASN.1 type: SET.
    /// Return count of written bytes.
    @objc public func writeSet(len: Int) -> Int {
        let proxyResult = vscf_asn1_writer_write_set(self.c_ctx, len)
        return proxyResult
    }
}
