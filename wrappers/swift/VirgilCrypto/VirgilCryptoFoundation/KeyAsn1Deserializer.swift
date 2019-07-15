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

/// Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
@objc(VSCFKeyAsn1Deserializer) public class KeyAsn1Deserializer: NSObject, KeyDeserializer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_key_asn1_deserializer_new()
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
        self.c_ctx = vscf_key_asn1_deserializer_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_key_asn1_deserializer_delete(self.c_ctx)
    }

    @objc public func setAsn1Reader(asn1Reader: Asn1Reader) {
        vscf_key_asn1_deserializer_release_asn1_reader(self.c_ctx)
        vscf_key_asn1_deserializer_use_asn1_reader(self.c_ctx, asn1Reader.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() {
        vscf_key_asn1_deserializer_setup_defaults(self.c_ctx)
    }

    /// Deserialize Public Key by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    @objc public func deserializePublicKeyInplace() throws -> RawPublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_key_asn1_deserializer_deserialize_public_key_inplace(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPublicKey.init(take: proxyResult!)
    }

    /// Deserialize Private Key by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    @objc public func deserializePrivateKeyInplace() throws -> RawPrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_key_asn1_deserializer_deserialize_private_key_inplace(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }

    /// Deserialize given public key as an interchangeable format to the object.
    @objc public func deserializePublicKey(publicKeyData: Data) throws -> RawPublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = publicKeyData.withUnsafeBytes({ (publicKeyDataPointer: UnsafeRawBufferPointer) in

            return vscf_key_asn1_deserializer_deserialize_public_key(self.c_ctx, vsc_data(publicKeyDataPointer.bindMemory(to: byte.self).baseAddress, publicKeyData.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return RawPublicKey.init(take: proxyResult!)
    }

    /// Deserialize given private key as an interchangeable format to the object.
    @objc public func deserializePrivateKey(privateKeyData: Data) throws -> RawPrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = privateKeyData.withUnsafeBytes({ (privateKeyDataPointer: UnsafeRawBufferPointer) in

            return vscf_key_asn1_deserializer_deserialize_private_key(self.c_ctx, vsc_data(privateKeyDataPointer.bindMemory(to: byte.self).baseAddress, privateKeyData.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }
}
