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

/// This class provides hybrid encryption algorithm that combines symmetric
/// cipher for data encryption and asymmetric cipher and password based
/// cipher for symmetric key encryption.
@objc(VSCFRecipientCipher) public class RecipientCipher: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_recipient_cipher_new()
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
        self.c_ctx = vscf_recipient_cipher_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_recipient_cipher_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_recipient_cipher_release_random(self.c_ctx)
        vscf_recipient_cipher_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setEncryptionCipher(encryptionCipher: Cipher) {
        vscf_recipient_cipher_release_encryption_cipher(self.c_ctx)
        vscf_recipient_cipher_use_encryption_cipher(self.c_ctx, encryptionCipher.c_ctx)
    }

    @objc public func setSignerHash(signerHash: Hash) {
        vscf_recipient_cipher_release_signer_hash(self.c_ctx)
        vscf_recipient_cipher_use_signer_hash(self.c_ctx, signerHash.c_ctx)
    }

    /// Add recipient defined with id and public key.
    @objc public func addKeyRecipient(recipientId: Data, publicKey: PublicKey) {
        recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> Void in

            vscf_recipient_cipher_add_key_recipient(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), publicKey.c_ctx)
        })
    }

    /// Remove all recipients.
    @objc public func clearRecipients() {
        vscf_recipient_cipher_clear_recipients(self.c_ctx)
    }

    /// Add identifier and private key to sign initial plain text.
    /// Return error if the private key can not sign.
    @objc public func addSigner(signerId: Data, privateKey: PrivateKey) throws {
        let proxyResult = signerId.withUnsafeBytes({ (signerIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in

            return vscf_recipient_cipher_add_signer(self.c_ctx, vsc_data(signerIdPointer.bindMemory(to: byte.self).baseAddress, signerId.count), privateKey.c_ctx)
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Remove all signers.
    @objc public func clearSigners() {
        vscf_recipient_cipher_clear_signers(self.c_ctx)
    }

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    @objc public func customParams() -> MessageInfoCustomParams {
        let proxyResult = vscf_recipient_cipher_custom_params(self.c_ctx)

        return MessageInfoCustomParams.init(use: proxyResult!)
    }

    /// Start encryption process.
    @objc public func startEncryption() throws {
        let proxyResult = vscf_recipient_cipher_start_encryption(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Start encryption process with known plain text size.
    ///
    /// Precondition: At least one signer should be added.
    /// Note, store message info footer as well.
    @objc public func startSignedEncryption(dataSize: Int) throws {
        let proxyResult = vscf_recipient_cipher_start_signed_encryption(self.c_ctx, dataSize)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Return buffer length required to hold message info returned by the
    /// "pack message info" method.
    /// Precondition: all recipients and custom parameters should be set.
    @objc public func messageInfoLen() -> Int {
        let proxyResult = vscf_recipient_cipher_message_info_len(self.c_ctx)

        return proxyResult
    }

    /// Return serialized message info to the buffer.
    ///
    /// Precondition: this method should be called after "start encryption".
    /// Precondition: this method should be called before "finish encryption".
    ///
    /// Note, store message info to use it for decryption process,
    /// or place it at the encrypted data beginning (embedding).
    ///
    /// Return message info - recipients public information,
    /// algorithm information, etc.
    @objc public func packMessageInfo() -> Data {
        let messageInfoCount = self.messageInfoLen()
        var messageInfo = Data(count: messageInfoCount)
        var messageInfoBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(messageInfoBuf)
        }

        messageInfo.withUnsafeMutableBytes({ (messageInfoPointer: UnsafeMutableRawBufferPointer) -> Void in
            vsc_buffer_use(messageInfoBuf, messageInfoPointer.bindMemory(to: byte.self).baseAddress, messageInfoCount)

            vscf_recipient_cipher_pack_message_info(self.c_ctx, messageInfoBuf)
        })
        messageInfo.count = vsc_buffer_len(messageInfoBuf)

        return messageInfo
    }

    /// Return buffer length required to hold output of the method
    /// "process encryption" and method "finish" during encryption.
    @objc public func encryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_recipient_cipher_encryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Process encryption of a new portion of data.
    @objc public func processEncryption(data: Data) throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_recipient_cipher_process_encryption(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Accomplish encryption.
    @objc public func finishEncryption() throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_recipient_cipher_finish_encryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    @objc public func startDecryptionWithKey(recipientId: Data, privateKey: PrivateKey, messageInfo: Data) throws {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            messageInfo.withUnsafeBytes({ (messageInfoPointer: UnsafeRawBufferPointer) -> vscf_status_t in

                return vscf_recipient_cipher_start_decryption_with_key(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), privateKey.c_ctx, vsc_data(messageInfoPointer.bindMemory(to: byte.self).baseAddress, messageInfo.count))
            })
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    /// Message Info footer can be empty if it was embedded to encrypted data.
    /// If footer was embedded, method "start decryption with key" can be used.
    @objc public func startVerifiedDecryptionWithKey(recipientId: Data, privateKey: PrivateKey, messageInfo: Data, messageInfoFooter: Data) throws {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            messageInfo.withUnsafeBytes({ (messageInfoPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                messageInfoFooter.withUnsafeBytes({ (messageInfoFooterPointer: UnsafeRawBufferPointer) -> vscf_status_t in

                    return vscf_recipient_cipher_start_verified_decryption_with_key(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), privateKey.c_ctx, vsc_data(messageInfoPointer.bindMemory(to: byte.self).baseAddress, messageInfo.count), vsc_data(messageInfoFooterPointer.bindMemory(to: byte.self).baseAddress, messageInfoFooter.count))
                })
            })
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Return buffer length required to hold output of the method
    /// "process decryption" and method "finish" during decryption.
    @objc public func decryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_recipient_cipher_decryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Process with a new portion of data.
    /// Return error if data can not be encrypted or decrypted.
    @objc public func processDecryption(data: Data) throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_recipient_cipher_process_decryption(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Accomplish decryption.
    @objc public func finishDecryption() throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_recipient_cipher_finish_decryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Return true if data was signed by a sender.
    ///
    /// Precondition: this method should be called after "finish decryption".
    @objc public func isDataSigned() -> Bool {
        let proxyResult = vscf_recipient_cipher_is_data_signed(self.c_ctx)

        return proxyResult
    }

    /// Return information about signers that sign data.
    ///
    /// Precondition: this method should be called after "finish decryption".
    /// Precondition: method "is data signed" returns true.
    @objc public func signerInfos() -> SignerInfoList {
        let proxyResult = vscf_recipient_cipher_signer_infos(self.c_ctx)

        return SignerInfoList.init(use: proxyResult!)
    }

    /// Verify given cipher info.
    @objc public func verifySignerInfo(signerInfo: SignerInfo, publicKey: PublicKey) -> Bool {
        let proxyResult = vscf_recipient_cipher_verify_signer_info(self.c_ctx, signerInfo.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Return buffer length required to hold message footer returned by the
    /// "pack message footer" method.
    ///
    /// Precondition: this method should be called after "finish encryption".
    @objc public func messageInfoFooterLen() -> Int {
        let proxyResult = vscf_recipient_cipher_message_info_footer_len(self.c_ctx)

        return proxyResult
    }

    /// Return serialized message info footer to the buffer.
    ///
    /// Precondition: this method should be called after "finish encryption".
    ///
    /// Note, store message info to use it for verified decryption process,
    /// or place it at the encrypted data ending (embedding).
    ///
    /// Return message info footer - signers public information, etc.
    @objc public func packMessageInfoFooter() -> Data {
        let outCount = self.messageInfoFooterLen()
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> Void in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            vscf_recipient_cipher_pack_message_info_footer(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }
}
