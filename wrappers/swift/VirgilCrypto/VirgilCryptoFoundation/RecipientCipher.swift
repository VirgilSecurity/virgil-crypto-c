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
import VirgilCryptoCommon

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

    @objc public func setCipher(cipher: Cipher) {
        vscf_recipient_cipher_release_cipher(self.c_ctx)
        vscf_recipient_cipher_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    /// Setup dependencies with default values.
    @objc public func setupDefaults() {
        vscf_recipient_cipher_setup_defaults(self.c_ctx)
    }

    /// Add recipient defined with id and public key.
    @objc public func addKeyRecipient(recipientId: Data, publicKey: PublicKey) {
        recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafePointer<byte>) -> Void in
            vscf_recipient_cipher_add_key_recipient(self.c_ctx, vsc_data(recipientIdPointer, recipientId.count), publicKey.c_ctx)
        })
    }

    /// Remove all recipients.
    @objc public func clearRecipients() {
        vscf_recipient_cipher_clear_recipients(self.c_ctx)
    }

    /// Return buffer length required to hold message info returned by the
    /// "start encryption" method.
    /// Precondition: all recipients and custom parameters should be set.
    @objc public func messageInfoLen() -> Int {
        let proxyResult = vscf_recipient_cipher_message_info_len(self.c_ctx)

        return proxyResult
    }

    /// Start encryption process.
    @objc public func startEncryption() throws {
        let proxyResult = vscf_recipient_cipher_start_encryption(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Return serialized message info to the buffer.
    ///
    /// Precondition: this method can be called after "start encryption".
    /// Precondition: this method can be called before "finish encryption".
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

        messageInfo.withUnsafeMutableBytes({ (messageInfoPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(messageInfoBuf)
            vsc_buffer_use(messageInfoBuf, messageInfoPointer, messageInfoCount)
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

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                return vscf_recipient_cipher_process_encryption(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

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

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_recipient_cipher_finish_encryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Initiate decryption process with a recipient private key.
    /// Message info can be empty if it was embedded to encrypted data.
    @objc public func startDecryptionWithKey(recipientId: Data, privateKey: PrivateKey, messageInfo: Data) throws {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafePointer<byte>) -> vscf_error_t in
            messageInfo.withUnsafeBytes({ (messageInfoPointer: UnsafePointer<byte>) -> vscf_error_t in
                return vscf_recipient_cipher_start_decryption_with_key(self.c_ctx, vsc_data(recipientIdPointer, recipientId.count), privateKey.c_ctx, vsc_data(messageInfoPointer, messageInfo.count))
            })
        })

        try FoundationError.handleError(fromC: proxyResult)
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

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                return vscf_recipient_cipher_process_decryption(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

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

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_recipient_cipher_finish_decryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }
}
