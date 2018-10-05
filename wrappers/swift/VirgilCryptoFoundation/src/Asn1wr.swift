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

/// This is MbedTLS implementation of ASN.1 writer.
@objc(VSCFAsn1wr) public class Asn1wr : Asn1Writer {
    @objc func public reset() -> Data {
        //  TODO: Implement me.
    }
    @objc func public seal() {
        //  TODO: Implement me.
    }
    @objc func public error() throws {
        //  TODO: Implement me.
    }
    @objc func public reserve(len: Int) -> UInt8 {
        //  TODO: Implement me.
    }
    @objc func public writeTag(tag: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeLen(len: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeInt(value: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeInt8(value: Int8) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeInt16(value: Int16) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeInt32(value: Int32) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeInt64(value: Int64) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUint(value: UInt) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUint8(value: UInt8) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUint16(value: UInt16) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUint32(value: UInt32) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUint64(value: UInt64) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeBool(value: Bool) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeNull() -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeOctetStr(value: Data) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeUtf8Str(value: Data) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeOid(value: Data) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeSequence(len: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public writeSet(len: Int) -> Int {
        //  TODO: Implement me.
    }
}

