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

/// CMS based implementation of the class "message info" serialization.
@objc(VSCFMessageInfoDerSerializer) public class MessageInfoDerSerializer: NSObject, Defaults, MessageInfoSerializer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    @objc public let prefixLen: Int = 32

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_message_info_der_serializer_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_message_info_der_serializer_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_message_info_der_serializer_delete(self.c_ctx)
    }

    @objc public func setAsn1Reader(asn1Reader: Asn1Reader) throws {
        vscf_message_info_der_serializer_release_asn1_reader(self.c_ctx)
        let proxyResult = vscf_message_info_der_serializer_use_asn1_reader(self.c_ctx, asn1Reader.c_ctx)
        try WrapperToTheSwiftProgrammingLanguageError.handleStatus(fromC: proxyResult)
    }

    @objc public func setAsn1Writer(asn1Writer: Asn1Writer) throws {
        vscf_message_info_der_serializer_release_asn1_writer(self.c_ctx)
        let proxyResult = vscf_message_info_der_serializer_use_asn1_writer(self.c_ctx, asn1Writer.c_ctx)
        try WrapperToTheSwiftProgrammingLanguageError.handleStatus(fromC: proxyResult)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_message_info_der_serializer_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Return buffer size enough to hold serialized message info.
    @objc public func serializedLen(messageInfo: MessageInfo) -> Int {
        let proxyResult = vscf_message_info_der_serializer_serialized_len(self.c_ctx, messageInfo.c_ctx)

        return proxyResult
    }

    /// Serialize class "message info".
    @objc public func serialize(messageInfo: MessageInfo) -> Data {
        let outCount = self.serializedLen(messageInfo: messageInfo)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)

            vscf_message_info_der_serializer_serialize(self.c_ctx, messageInfo.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Read message info prefix from the given data, and if it is valid,
    /// return a length of bytes of the whole message info.
    ///
    /// Zero returned if length can not be determined from the given data,
    /// and this means that there is no message info at the data beginning.
    @objc public func readPrefix(data: Data) -> Int {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Int in

            return vscf_message_info_der_serializer_read_prefix(self.c_ctx, vsc_data(dataPointer, data.count))
        })

        return proxyResult
    }

    /// Deserialize class "message info".
    @objc public func deserialize(data: Data) throws -> MessageInfo {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) in

            return vscf_message_info_der_serializer_deserialize(self.c_ctx, vsc_data(dataPointer, data.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return MessageInfo.init(take: proxyResult!)
    }
}
