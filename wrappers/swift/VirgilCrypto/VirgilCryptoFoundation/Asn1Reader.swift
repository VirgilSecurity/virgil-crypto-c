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

@objc(VSCFAsn1Reader) public protocol Asn1Reader : CContext {

    @objc func reset(data: Data)

    @objc func leftLen() -> Int

    @objc func hasError() -> Bool

    /// Return error code.
    @objc func status() throws

    @objc func getTag() -> Int32

    @objc func getLen() -> Int

    @objc func getDataLen() -> Int

    @objc func readTag(tag: Int32) -> Int

    @objc func readContextTag(tag: Int32) -> Int

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

    /// Read ASN.1 type: NULL.
    @objc func readNull()

    /// Read ASN.1 type: NULL, only if it exists.
/// Note, this method is safe to call even no more data is left for reading.
    @objc func readNullOptional()

    @objc func readOctetStr() -> Data

    @objc func readBitstringAsOctetStr() -> Data

    @objc func readUtf8Str() -> Data

    @objc func readOid() -> Data

    @objc func readData(len: Int) -> Data

    @objc func readSequence() -> Int

    @objc func readSet() -> Int
}
