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

/// Simple PEM wrapper.
@objc(VSCFPem) public class Pem: NSObject {

    /// Return length in bytes required to hold wrapped PEM format.
    @objc public static func wrappedLen(title: String, dataLen: Int) -> Int {
        let proxyResult = vscf_pem_wrapped_len(title, dataLen)

        return proxyResult
    }

    /// Takes binary data and wraps it to the simple PEM format - no
    /// additional information just header-base64-footer.
    /// Note, written buffer is NOT null-terminated.
    @objc public static func wrap(title: String, data: Data) -> Data {
        let pemCount = Pem.wrappedLen(title: title, dataLen: data.count)
        var pem = Data(count: pemCount)
        var pemBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(pemBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            pem.withUnsafeMutableBytes({ (pemPointer: UnsafeMutablePointer<byte>) -> Void in
                vsc_buffer_init(pemBuf)
                vsc_buffer_use(pemBuf, pemPointer, pemCount)

                vscf_pem_wrap(title, vsc_data(dataPointer, data.count), pemBuf)
            })
        })
        pem.count = vsc_buffer_len(pemBuf)

        return pem
    }

    /// Return length in bytes required to hold unwrapped binary.
    @objc public static func unwrappedLen(pemLen: Int) -> Int {
        let proxyResult = vscf_pem_unwrapped_len(pemLen)

        return proxyResult
    }

    /// Takes PEM data and extract binary data from it.
    @objc public static func unwrap(pem: Data) throws -> Data {
        let dataCount = Pem.unwrappedLen(pemLen: pem.count)
        var data = Data(count: dataCount)
        var dataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(dataBuf)
        }

        let proxyResult = pem.withUnsafeBytes({ (pemPointer: UnsafePointer<byte>) -> vscf_status_t in
            data.withUnsafeMutableBytes({ (dataPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
                vsc_buffer_init(dataBuf)
                vsc_buffer_use(dataBuf, dataPointer, dataCount)

                return vscf_pem_unwrap(vsc_data(pemPointer, pem.count), dataBuf)
            })
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return data
    }

    /// Returns PEM title if PEM data is valid, otherwise - empty data.
    @objc public static func title(pem: Data) -> Data {
        let proxyResult = pem.withUnsafeBytes({ (pemPointer: UnsafePointer<byte>) in

            return vscf_pem_title(vsc_data(pemPointer, pem.count))
        })

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }
}
