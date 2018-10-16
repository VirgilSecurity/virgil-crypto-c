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
@objc(VSCFAsn1rd) public class Asn1rd : Asn1Reader {
    @objc func public reset(data: Data) {
        //  TODO: Implement me.
    }
    @objc func public error() throws {
        //  TODO: Implement me.
    }
    @objc func public getTag() -> Int {
        //  TODO: Implement me.
    }
    @objc func public getLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public readTag(tag: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public readInt() -> Int {
        //  TODO: Implement me.
    }
    @objc func public readInt8() -> Int8 {
        //  TODO: Implement me.
    }
    @objc func public readInt16() -> Int16 {
        //  TODO: Implement me.
    }
    @objc func public readInt32() -> Int32 {
        //  TODO: Implement me.
    }
    @objc func public readInt64() -> Int64 {
        //  TODO: Implement me.
    }
    @objc func public readUint() -> UInt {
        //  TODO: Implement me.
    }
    @objc func public readUint8() -> UInt8 {
        //  TODO: Implement me.
    }
    @objc func public readUint16() -> UInt16 {
        //  TODO: Implement me.
    }
    @objc func public readUint32() -> UInt32 {
        //  TODO: Implement me.
    }
    @objc func public readUint64() -> UInt64 {
        //  TODO: Implement me.
    }
    @objc func public readBool() -> Bool {
        //  TODO: Implement me.
    }
    @objc func public readNull() {
        //  TODO: Implement me.
    }
    @objc func public readOctetStr() -> Data {
        //  TODO: Implement me.
    }
    @objc func public readUtf8Str() -> Data {
        //  TODO: Implement me.
    }
    @objc func public readOid() -> Data {
        //  TODO: Implement me.
    }
    @objc func public readData(len: Int) -> Data {
        //  TODO: Implement me.
    }
    @objc func public readSequence() -> Int {
        //  TODO: Implement me.
    }
    @objc func public readSet() -> Int {
        //  TODO: Implement me.
    }
}

