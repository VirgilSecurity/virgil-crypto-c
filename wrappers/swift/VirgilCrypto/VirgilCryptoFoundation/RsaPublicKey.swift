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

@objc(VSCFRsaPublicKey) public class RsaPublicKey: NSObject, Defaults, Alg, Key, Encrypt, Verify, PublicKey, GenerateEphemeralKey {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Defines whether a public key can be imported or not.
    @objc public let canImportPublicKey: Bool = true

    /// Define whether a public key can be exported or not.
    @objc public let canExportPublicKey: Bool = true

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_rsa_public_key_new()
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
        self.c_ctx = vscf_rsa_public_key_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_rsa_public_key_delete(self.c_ctx)
    }

    @objc public func setHash(hash: Hash) {
        vscf_rsa_public_key_release_hash(self.c_ctx)
        vscf_rsa_public_key_use_hash(self.c_ctx, hash.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_rsa_public_key_release_random(self.c_ctx)
        vscf_rsa_public_key_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setAsn1rd(asn1rd: Asn1Reader) {
        vscf_rsa_public_key_release_asn1rd(self.c_ctx)
        vscf_rsa_public_key_use_asn1rd(self.c_ctx, asn1rd.c_ctx)
    }

    @objc public func setAsn1wr(asn1wr: Asn1Writer) {
        vscf_rsa_public_key_release_asn1wr(self.c_ctx)
        vscf_rsa_public_key_use_asn1wr(self.c_ctx, asn1wr.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_rsa_public_key_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_rsa_public_key_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_rsa_public_key_produce_alg_info(self.c_ctx)

        return AlgInfoProxy.init(c_ctx: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_rsa_public_key_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Length of the key in bytes.
    @objc public func keyLen() -> Int {
        let proxyResult = vscf_rsa_public_key_key_len(self.c_ctx)

        return proxyResult
    }

    /// Length of the key in bits.
    @objc public func keyBitlen() -> Int {
        let proxyResult = vscf_rsa_public_key_key_bitlen(self.c_ctx)

        return proxyResult
    }

    /// Encrypt given data.
    @objc public func encrypt(data: Data) throws -> Data {
        let outCount = self.encryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)

                return vscf_rsa_public_key_encrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_rsa_public_key_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Verify data with given public key and signature.
    @objc public func verify(data: Data, signature: Data) -> Bool {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Bool in
            signature.withUnsafeBytes({ (signaturePointer: UnsafePointer<byte>) -> Bool in

                return vscf_rsa_public_key_verify(self.c_ctx, vsc_data(dataPointer, data.count), vsc_data(signaturePointer, signature.count))
            })
        })

        return proxyResult
    }

    /// Export public key in the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func exportPublicKey() throws -> Data {
        let outCount = self.exportedPublicKeyLen()
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)

            return vscf_rsa_public_key_export_public_key(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Return length in bytes required to hold exported public key.
    @objc public func exportedPublicKeyLen() -> Int {
        let proxyResult = vscf_rsa_public_key_exported_public_key_len(self.c_ctx)

        return proxyResult
    }

    /// Import public key from the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func importPublicKey(data: Data) throws {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_status_t in

            return vscf_rsa_public_key_import_public_key(self.c_ctx, vsc_data(dataPointer, data.count))
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Generate ephemeral private key of the same type.
    @objc public func generateEphemeralKey() throws -> PrivateKey {
        var error: vscf_error_t

        let proxyResult = vscf_rsa_public_key_generate_ephemeral_key(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return PrivateKeyProxy.init(c_ctx: proxyResult!)
    }
}
