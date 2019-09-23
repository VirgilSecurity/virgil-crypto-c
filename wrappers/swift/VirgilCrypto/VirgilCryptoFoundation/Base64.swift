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

/// Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
@objc(VSCFBase64) public class Base64: NSObject {

    /// Calculate length in bytes required to hold an encoded base64 string.
    @objc public static func encodedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_base64_encoded_len(dataLen)

        return proxyResult
    }

    /// Encode given data to the base64 format.
    /// Note, written buffer is NOT null-terminated.
    @objc public static func encode(data: Data) -> Data {
        let strCount = Base64.encodedLen(dataLen: data.count)
        var str = Data(count: strCount)
        var strBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(strBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> Void in
            str.withUnsafeMutableBytes({ (strPointer: UnsafeMutableRawBufferPointer) -> Void in
                vsc_buffer_use(strBuf, strPointer.bindMemory(to: byte.self).baseAddress, strCount)

                vscf_base64_encode(vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), strBuf)
            })
        })
        str.count = vsc_buffer_len(strBuf)

        return str
    }

    /// Calculate length in bytes required to hold a decoded base64 string.
    @objc public static func decodedLen(strLen: Int) -> Int {
        let proxyResult = vscf_base64_decoded_len(strLen)

        return proxyResult
    }

    /// Decode given data from the base64 format.
    @objc public static func decode(str: Data) throws -> Data {
        let dataCount = Base64.decodedLen(strLen: str.count)
        var data = Data(count: dataCount)
        var dataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(dataBuf)
        }

        let proxyResult = str.withUnsafeBytes({ (strPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            data.withUnsafeMutableBytes({ (dataPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(dataBuf, dataPointer.bindMemory(to: byte.self).baseAddress, dataCount)

                return vscf_base64_decode(vsc_data(strPointer.bindMemory(to: byte.self).baseAddress, str.count), dataBuf)
            })
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return data
    }
}
