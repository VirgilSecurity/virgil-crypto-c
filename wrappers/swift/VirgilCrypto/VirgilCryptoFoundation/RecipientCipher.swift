/// Copyright (C) 2015-2022 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
/// (1) Redistributions of source code must retain the above copyright
/// notice, this list of conditions and the following disclaimer.
///
/// (2) Redistributions in binary form must reproduce the above copyright
/// notice, this list of conditions and the following disclaimer in
/// the documentation and/or other materials provided with the
/// distribution.
///
/// (3) Neither the name of the copyright holder nor the names of its
/// contributors may be used to endorse or promote products derived from
/// this software without specific prior written permission.
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

@objc(VSCFRecipientCipher) public class RecipientCipher: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    public override init() {
        self.c_ctx = vscf_recipient_cipher_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

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

    @objc public func setEncryptionPadding(encryptionPadding: Padding) {
        vscf_recipient_cipher_release_encryption_padding(self.c_ctx)
        vscf_recipient_cipher_use_encryption_padding(self.c_ctx, encryptionPadding.c_ctx)
    }

    @objc public func setPaddingParams(paddingParams: PaddingParams) {
        vscf_recipient_cipher_release_padding_params(self.c_ctx)
        vscf_recipient_cipher_use_padding_params(self.c_ctx, paddingParams.c_ctx)
    }

    @objc public func setSignerHash(signerHash: Hash) {
        vscf_recipient_cipher_release_signer_hash(self.c_ctx)
        vscf_recipient_cipher_use_signer_hash(self.c_ctx, signerHash.c_ctx)
    }

    @objc public func hasKeyRecipient(recipientId: Data) -> Bool {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> Bool in

            return vscf_recipient_cipher_has_key_recipient(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count))
        })

        return proxyResult
    }

    @objc public func addKeyRecipient(recipientId: Data, publicKey: PublicKey) {
        recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> Void in

            vscf_recipient_cipher_add_key_recipient(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), publicKey.c_ctx)
        })
    }

    @objc public func clearRecipients() {
        vscf_recipient_cipher_clear_recipients(self.c_ctx)
    }

    @objc public func addSigner(signerId: Data, privateKey: PrivateKey) throws {
        let proxyResult = signerId.withUnsafeBytes({ (signerIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in

            return vscf_recipient_cipher_add_signer(self.c_ctx, vsc_data(signerIdPointer.bindMemory(to: byte.self).baseAddress, signerId.count), privateKey.c_ctx)
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func clearSigners() {
        vscf_recipient_cipher_clear_signers(self.c_ctx)
    }

    @objc public func customParams() -> MessageInfoCustomParams {
        let proxyResult = vscf_recipient_cipher_custom_params(self.c_ctx)

        return MessageInfoCustomParams.init(use: proxyResult!)
    }

    @objc public func startEncryption() throws {
        let proxyResult = vscf_recipient_cipher_start_encryption(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func startSignedEncryption(dataSize: Int) throws {
        let proxyResult = vscf_recipient_cipher_start_signed_encryption(self.c_ctx, dataSize)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func messageInfoLen() -> Int {
        let proxyResult = vscf_recipient_cipher_message_info_len(self.c_ctx)

        return proxyResult
    }

    @objc public func packMessageInfo() -> Data {
        let messageInfoCount = self.messageInfoLen()
        var messageInfo = Data(count: messageInfoCount)
        let messageInfoBuf = vsc_buffer_new()
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

    @objc public func encryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_recipient_cipher_encryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func processEncryption(data: Data) throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
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

    @objc public func finishEncryption() throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
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

    @objc public func startDecryptionWithKey(recipientId: Data, privateKey: PrivateKey, messageInfo: Data) throws {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            messageInfo.withUnsafeBytes({ (messageInfoPointer: UnsafeRawBufferPointer) -> vscf_status_t in

                return vscf_recipient_cipher_start_decryption_with_key(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), privateKey.c_ctx, vsc_data(messageInfoPointer.bindMemory(to: byte.self).baseAddress, messageInfo.count))
            })
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

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

    @objc public func decryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_recipient_cipher_decryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func processDecryption(data: Data) throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
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

    @objc public func finishDecryption() throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
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

    @objc public func isDataSigned() -> Bool {
        let proxyResult = vscf_recipient_cipher_is_data_signed(self.c_ctx)

        return proxyResult
    }

    @objc public func signerInfos() -> SignerInfoList {
        let proxyResult = vscf_recipient_cipher_signer_infos(self.c_ctx)

        return SignerInfoList.init(use: proxyResult!)
    }

    @objc public func verifySignerInfo(signerInfo: SignerInfo, publicKey: PublicKey) -> Bool {
        let proxyResult = vscf_recipient_cipher_verify_signer_info(self.c_ctx, signerInfo.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    @objc public func messageInfoFooterLen() -> Int {
        let proxyResult = vscf_recipient_cipher_message_info_footer_len(self.c_ctx)

        return proxyResult
    }

    @objc public func packMessageInfoFooter() throws -> Data {
        let outCount = self.messageInfoFooterLen()
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_recipient_cipher_pack_message_info_footer(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

}
