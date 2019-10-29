/// Copyright (C) 2015-2019 Virgil Security, Inc.
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

/// Provides interface to the ASN.1 reader.
/// Note, that all "read" methods move reading position forward.
/// Note, that all "get" do not change reading position.
@objc(VSCFAsn1Reader) public protocol Asn1Reader : CContext {

    /// Reset all internal states and prepare to new ASN.1 reading operations.
    @objc func reset(data: Data)

    /// Return length in bytes how many bytes are left for reading.
    @objc func leftLen() -> Int

    /// Return true if status is not "success".
    @objc func hasError() -> Bool

    /// Return error code.
    @objc func status() throws

    /// Get tag of the current ASN.1 element.
    @objc func getTag() -> Int32

    /// Get length of the current ASN.1 element.
    @objc func getLen() -> Int

    /// Get length of the current ASN.1 element with tag and length itself.
    @objc func getDataLen() -> Int

    /// Read ASN.1 type: TAG.
    /// Return element length.
    @objc func readTag(tag: Int32) -> Int

    /// Read ASN.1 type: context-specific TAG.
    /// Return element length.
    /// Return 0 if current position do not points to the requested tag.
    @objc func readContextTag(tag: Int32) -> Int

    /// Read ASN.1 type: INTEGER.
    @objc func readInt() -> Int32

    /// Read ASN.1 type: INTEGER.
    @objc func readInt8() -> Int8

    /// Read ASN.1 type: INTEGER.
    @objc func readInt16() -> Int16

    /// Read ASN.1 type: INTEGER.
    @objc func readInt32() -> Int32

    /// Read ASN.1 type: INTEGER.
    @objc func readInt64() -> Int64

    /// Read ASN.1 type: INTEGER.
    @objc func readUint() -> UInt32

    /// Read ASN.1 type: INTEGER.
    @objc func readUint8() -> UInt8

    /// Read ASN.1 type: INTEGER.
    @objc func readUint16() -> UInt16

    /// Read ASN.1 type: INTEGER.
    @objc func readUint32() -> UInt32

    /// Read ASN.1 type: INTEGER.
    @objc func readUint64() -> UInt64

    /// Read ASN.1 type: BOOLEAN.
    @objc func readBool() -> Bool

    /// Read ASN.1 type: NULL.
    @objc func readNull()

    /// Read ASN.1 type: NULL, only if it exists.
    /// Note, this method is safe to call even no more data is left for reading.
    @objc func readNullOptional()

    /// Read ASN.1 type: OCTET STRING.
    @objc func readOctetStr() -> Data

    /// Read ASN.1 type: BIT STRING.
    @objc func readBitstringAsOctetStr() -> Data

    /// Read ASN.1 type: UTF8String.
    @objc func readUtf8Str() -> Data

    /// Read ASN.1 type: OID.
    @objc func readOid() -> Data

    /// Read raw data of given length.
    @objc func readData(len: Int) -> Data

    /// Read ASN.1 type: SEQUENCE.
    /// Return element length.
    @objc func readSequence() -> Int

    /// Read ASN.1 type: SET.
    /// Return element length.
    @objc func readSet() -> Int
}
