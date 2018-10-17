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

/// This is MbedTLS implementation of ASN.1 reader.
@objc(VSCFAsn1rd) public class Asn1rd : NSObject, Asn1Reader {
    @objc public func reset(data: Data) {
        // TODO: Implement me.
    }

    @objc public func error() throws {
        // TODO: Implement me.
    }

    @objc public func getTag() -> Int {
        // TODO: Implement me.
    }

    @objc public func getLen() -> Int {
        // TODO: Implement me.
    }

    @objc public func readTag(tag: Int) -> Int {
        // TODO: Implement me.
    }

    @objc public func readInt() -> Int {
        // TODO: Implement me.
    }

    @objc public func readInt8() -> Int8 {
        // TODO: Implement me.
    }

    @objc public func readInt16() -> Int16 {
        // TODO: Implement me.
    }

    @objc public func readInt32() -> Int32 {
        // TODO: Implement me.
    }

    @objc public func readInt64() -> Int64 {
        // TODO: Implement me.
    }

    @objc public func readUint() -> UInt {
        // TODO: Implement me.
    }

    @objc public func readUint8() -> UInt8 {
        // TODO: Implement me.
    }

    @objc public func readUint16() -> UInt16 {
        // TODO: Implement me.
    }

    @objc public func readUint32() -> UInt32 {
        // TODO: Implement me.
    }

    @objc public func readUint64() -> UInt64 {
        // TODO: Implement me.
    }

    @objc public func readBool() -> Bool {
        // TODO: Implement me.
    }

    @objc public func readNull() {
        // TODO: Implement me.
    }

    @objc public func readOctetStr() -> Data {
        // TODO: Implement me.
    }

    @objc public func readUtf8Str() -> Data {
        // TODO: Implement me.
    }

    @objc public func readOid() -> Data {
        // TODO: Implement me.
    }

    @objc public func readData(len: Int) -> Data {
        // TODO: Implement me.
    }

    @objc public func readSequence() -> Int {
        // TODO: Implement me.
    }

    @objc public func readSet() -> Int {
        // TODO: Implement me.
    }
}

