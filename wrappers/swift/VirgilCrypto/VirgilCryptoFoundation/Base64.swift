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

/// Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
@objc(VSCFBase64) public class Base64: NSObject {

    /// Calculate length in bytes required to hold an encoded base64 string.
    @objc public static func encodedLen(data: Data) -> Int {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Int in
            return vscf_base64_encoded_len(vsc_data(dataPointer, data.count))
        })

        return proxyResult
    }

    /// Encode given data to the base64 format.
    /// Note, written buffer is NOT null-terminated.
    @objc public static func encode(data: Data) -> Data {
        let strCount = Base64.encodedLen(data: data)
        var str = Data(count: strCount)
        var strBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(strBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            str.withUnsafeMutableBytes({ (strPointer: UnsafeMutablePointer<byte>) -> Void in
                vsc_buffer_init(strBuf)
                vsc_buffer_use(strBuf, strPointer, strCount)
                vscf_base64_encode(vsc_data(dataPointer, data.count), strBuf)
            })
        })
        str.count = vsc_buffer_len(strBuf)

        return str
    }

    /// Calculate length in bytes required to hold a decoded base64 string.
    @objc public static func decodedLen(str: Data) -> Int {
        let proxyResult = str.withUnsafeBytes({ (strPointer: UnsafePointer<byte>) -> Int in
            return vscf_base64_decoded_len(vsc_data(strPointer, str.count))
        })

        return proxyResult
    }

    /// Decode given data from the base64 format.
    @objc public static func decode(str: Data) throws -> Data {
        let dataCount = Base64.decodedLen(str: str)
        var data = Data(count: dataCount)
        var dataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(dataBuf)
        }

        let proxyResult = str.withUnsafeBytes({ (strPointer: UnsafePointer<byte>) -> vscf_error_t in
            data.withUnsafeMutableBytes({ (dataPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(dataBuf)
                vsc_buffer_use(dataBuf, dataPointer, dataCount)
                return vscf_base64_decode(vsc_data(strPointer, str.count), dataBuf)
            })
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return data
    }
}
