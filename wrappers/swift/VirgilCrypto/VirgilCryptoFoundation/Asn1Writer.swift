/// Copyright (C) 2015-2020 Virgil Security, Inc.
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

    /// Reset all internal states and prepare to new ASN.1 writing operations.
    @objc func reset(out: UnsafeMutablePointer<UInt8>, outLen: Int)

    /// Finalize writing and forbid further operations.
    ///
    /// Note, that ASN.1 structure is always written to the buffer end, and
    /// if argument "do not adjust" is false, then data is moved to the
    /// beginning, otherwise - data is left at the buffer end.
    ///
    /// Returns length of the written bytes.
    @objc func finish(doNotAdjust: Bool) -> Int

    /// Returns pointer to the inner buffer.
    @objc func bytes() -> UnsafeMutablePointer<UInt8>

    /// Returns total inner buffer length.
    @objc func len() -> Int

    /// Returns how many bytes were already written to the ASN.1 structure.
    @objc func writtenLen() -> Int

    /// Returns how many bytes are available for writing.
    @objc func unwrittenLen() -> Int

    /// Return true if status is not "success".
    @objc func hasError() -> Bool

    /// Return error code.
    @objc func status() throws

    /// Move writing position backward for the given length.
    /// Return current writing position.
    @objc func reserve(len: Int) -> UnsafeMutablePointer<UInt8>

    /// Write ASN.1 tag.
    /// Return count of written bytes.
    @objc func writeTag(tag: Int32) -> Int

    /// Write context-specific ASN.1 tag.
    /// Return count of written bytes.
    @objc func writeContextTag(tag: Int32, len: Int) -> Int

    /// Write length of the following data.
    /// Return count of written bytes.
    @objc func writeLen(len: Int) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeInt(value: Int32) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeInt8(value: Int8) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeInt16(value: Int16) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeInt32(value: Int32) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeInt64(value: Int64) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeUint(value: UInt32) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeUint8(value: UInt8) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeUint16(value: UInt16) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeUint32(value: UInt32) -> Int

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    @objc func writeUint64(value: UInt64) -> Int

    /// Write ASN.1 type: BOOLEAN.
    /// Return count of written bytes.
    @objc func writeBool(value: Bool) -> Int

    /// Write ASN.1 type: NULL.
    @objc func writeNull() -> Int

    /// Write ASN.1 type: OCTET STRING.
    /// Return count of written bytes.
    @objc func writeOctetStr(value: Data) -> Int

    /// Write ASN.1 type: BIT STRING with all zero unused bits.
    ///
    /// Return count of written bytes.
    @objc func writeOctetStrAsBitstring(value: Data) -> Int

    /// Write raw data directly to the ASN.1 structure.
    /// Return count of written bytes.
    /// Note, use this method carefully.
    @objc func writeData(data: Data) -> Int

    /// Write ASN.1 type: UTF8String.
    /// Return count of written bytes.
    @objc func writeUtf8Str(value: Data) -> Int

    /// Write ASN.1 type: OID.
    /// Return count of written bytes.
    @objc func writeOid(value: Data) -> Int

    /// Mark previously written data of given length as ASN.1 type: SEQUENCE.
    /// Return count of written bytes.
    @objc func writeSequence(len: Int) -> Int

    /// Mark previously written data of given length as ASN.1 type: SET.
    /// Return count of written bytes.
    @objc func writeSet(len: Int) -> Int
}
