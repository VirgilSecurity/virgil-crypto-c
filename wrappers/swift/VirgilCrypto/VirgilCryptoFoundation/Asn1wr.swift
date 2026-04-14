/// Copyright (C) 2015-2022 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
/// (1) Redistributions of source code must retain the above copyright
/// notice, this list of conditions and the following disclaimer.
///
/// (2) Redistributions in binary form must reproduce the above copyright
/// notice, this list of conditions and the following disclaimer in
/// the documentation and/or other materials provided with the
/// distribution.
///
/// (3) Neither the name of the copyright holder nor the names of its
/// contributors may be used to endorse or promote products derived from
/// this software without specific prior written permission.
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

@objc(VSCFAsn1wr) public class Asn1wr: NSObject, Asn1Writer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    public override init() {
        self.c_ctx = vscf_asn1wr_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_asn1wr_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_asn1wr_delete(self.c_ctx)
    }

    @objc public func reset(out: UnsafeMutablePointer<UInt8>, outLen: Int) {
        vscf_asn1wr_reset(self.c_ctx, out, outLen)
    }

    @objc public func finish(doNotAdjust: Bool) -> Int {
        let proxyResult = vscf_asn1wr_finish(self.c_ctx, doNotAdjust)

        return proxyResult
    }

    @objc public func bytes() -> UnsafeMutablePointer<UInt8> {
        let proxyResult = vscf_asn1wr_bytes(self.c_ctx)

        return proxyResult!
    }

    @objc public func len() -> Int {
        let proxyResult = vscf_asn1wr_len(self.c_ctx)

        return proxyResult
    }

    @objc public func writtenLen() -> Int {
        let proxyResult = vscf_asn1wr_written_len(self.c_ctx)

        return proxyResult
    }

    @objc public func unwrittenLen() -> Int {
        let proxyResult = vscf_asn1wr_unwritten_len(self.c_ctx)

        return proxyResult
    }

    @objc public func hasError() -> Bool {
        let proxyResult = vscf_asn1wr_has_error(self.c_ctx)

        return proxyResult
    }

    @objc public func status() throws {
        let proxyResult = vscf_asn1wr_status(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func reserve(len: Int) -> UnsafeMutablePointer<UInt8> {
        let proxyResult = vscf_asn1wr_reserve(self.c_ctx, len)

        return proxyResult!
    }

    @objc public func writeTag(tag: Int32) -> Int {
        let proxyResult = vscf_asn1wr_write_tag(self.c_ctx, tag)

        return proxyResult
    }

    @objc public func writeContextTag(tag: Int32, len: Int) -> Int {
        let proxyResult = vscf_asn1wr_write_context_tag(self.c_ctx, tag, len)

        return proxyResult
    }

    @objc public func writeLen(len: Int) -> Int {
        let proxyResult = vscf_asn1wr_write_len(self.c_ctx, len)

        return proxyResult
    }

    @objc public func writeInt(value: Int32) -> Int {
        let proxyResult = vscf_asn1wr_write_int(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeInt8(value: Int8) -> Int {
        let proxyResult = vscf_asn1wr_write_int8(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeInt16(value: Int16) -> Int {
        let proxyResult = vscf_asn1wr_write_int16(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeInt32(value: Int32) -> Int {
        let proxyResult = vscf_asn1wr_write_int32(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeInt64(value: Int64) -> Int {
        let proxyResult = vscf_asn1wr_write_int64(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeUint(value: UInt32) -> Int {
        let proxyResult = vscf_asn1wr_write_uint(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeUint8(value: UInt8) -> Int {
        let proxyResult = vscf_asn1wr_write_uint8(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeUint16(value: UInt16) -> Int {
        let proxyResult = vscf_asn1wr_write_uint16(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeUint32(value: UInt32) -> Int {
        let proxyResult = vscf_asn1wr_write_uint32(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeUint64(value: UInt64) -> Int {
        let proxyResult = vscf_asn1wr_write_uint64(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeBool(value: Bool) -> Int {
        let proxyResult = vscf_asn1wr_write_bool(self.c_ctx, value)

        return proxyResult
    }

    @objc public func writeNull() -> Int {
        let proxyResult = vscf_asn1wr_write_null(self.c_ctx)

        return proxyResult
    }

    @objc public func writeOctetStr(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafeRawBufferPointer) -> Int in

            return vscf_asn1wr_write_octet_str(self.c_ctx, vsc_data(valuePointer.bindMemory(to: byte.self).baseAddress, value.count))
        })

        return proxyResult
    }

    @objc public func writeOctetStrAsBitstring(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafeRawBufferPointer) -> Int in

            return vscf_asn1wr_write_octet_str_as_bitstring(self.c_ctx, vsc_data(valuePointer.bindMemory(to: byte.self).baseAddress, value.count))
        })

        return proxyResult
    }

    @objc public func writeData(data: Data) -> Int {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> Int in

            return vscf_asn1wr_write_data(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count))
        })

        return proxyResult
    }

    @objc public func writeUtf8Str(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafeRawBufferPointer) -> Int in

            return vscf_asn1wr_write_utf8_str(self.c_ctx, vsc_data(valuePointer.bindMemory(to: byte.self).baseAddress, value.count))
        })

        return proxyResult
    }

    @objc public func writeOid(value: Data) -> Int {
        let proxyResult = value.withUnsafeBytes({ (valuePointer: UnsafeRawBufferPointer) -> Int in

            return vscf_asn1wr_write_oid(self.c_ctx, vsc_data(valuePointer.bindMemory(to: byte.self).baseAddress, value.count))
        })

        return proxyResult
    }

    @objc public func writeSequence(len: Int) -> Int {
        let proxyResult = vscf_asn1wr_write_sequence(self.c_ctx, len)

        return proxyResult
    }

    @objc public func writeSet(len: Int) -> Int {
        let proxyResult = vscf_asn1wr_write_set(self.c_ctx, len)

        return proxyResult
    }

}
