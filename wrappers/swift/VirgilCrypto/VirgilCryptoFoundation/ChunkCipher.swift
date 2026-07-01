// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation

@objc(VSCFChunkCipher) public class ChunkCipher: NSObject, Alg, Encrypt, Decrypt, CipherInfo, Cipher {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    @objc public let nonceLen: Int = 12

    /// Cipher key length in bytes.
    @objc public let keyLen: Int = 32

    /// Cipher key length in bits.
    @objc public let keyBitlen: Int = 256

    /// Cipher block length in bytes.
    @objc public let blockLen: Int = 16

    public override init() {
        self.c_ctx = vscf_chunk_cipher_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_chunk_cipher_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_chunk_cipher_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_chunk_cipher_release_random(self.c_ctx)
        vscf_chunk_cipher_use_random(self.c_ctx, random.c_ctx)
    }

    /// Set the plaintext chunk size in bytes. Default is 65536.
    @objc public func setChunkSize(chunkSize: Int) {
        vscf_chunk_cipher_set_chunk_size(self.c_ctx, chunkSize)
    }

    /// Return the 12-byte initial nonce.
    /// Valid after calling start_encryption; store in CMS custom params for decryption.
    @objc public func nonce() -> Data {
        let proxyResult = vscf_chunk_cipher_nonce(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return nonce length in bytes (always 12).
    @objc public func nonceLen() -> Int {
        let proxyResult = vscf_chunk_cipher_nonce_len(self.c_ctx)

        return proxyResult
    }

    /// Return buffer length required to hold output of process_encryption and finish_encryption.
    @objc public func encryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_encryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Process encryption of a new portion of data.
    @objc public func processEncryption(data: Data) throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_process_encryption(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Encrypt any remaining pending data and finalize the stream.
    @objc public func finishEncryption() throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_chunk_cipher_finish_encryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Return buffer length required to hold output of process_decryption and finish_decryption.
    @objc public func decryptionOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_decryption_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Process decryption of a new portion of data.
    @objc public func processDecryption(data: Data) throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_process_decryption(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Decrypt any remaining pending data and finalize the stream.
    @objc public func finishDecryption() throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_chunk_cipher_finish_decryption(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Return the number of frames the sequential encryption path emits for a plaintext of the
    /// given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
    /// is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
    /// parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
    /// highest index. Requires chunk_size to be set (> 0).
    @objc public func chunkCount(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_chunk_count(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Encrypt a single chunk at an explicit index for random-access / parallel encryption, writing
    /// the frame counter_le64[8] | ciphertext | tag[16]. Independent of the start/process/finish
    /// state machine; requires key, initial nonce, and chunk_size to be set, and the instance to be
    /// in the INITIAL state (call before, or instead of, start_encryption).
    ///
    /// WARNING (nonce safety): each chunk_index must be encrypted at most ONCE per (key, initial_nonce);
    /// AES-GCM nonce reuse is catastrophic. This API is per-call and does NOT track or enforce
    /// uniqueness — the caller owns it. Thread-safe: each call uses a per-call local cipher context and
    /// only reads the instance's key/nonce/chunk_size, so a single configured instance may be used
    /// concurrently from multiple threads for parallel encryption (no shared mutable cipher state, no
    /// lock). Whole-file only: the caller must know the total chunk count (see chunk_count) to place
    /// exactly one is_last frame.
    @objc public func encryptAt(chunkIndex: UInt64, isLast: Bool, plaintext: Data) throws -> Data {
        let outCount = self.encryptionOutLen(dataLen: plaintext.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = plaintext.withUnsafeBytes({ (plaintextPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_encrypt_at(self.c_ctx, chunkIndex, isLast, vsc_data(plaintextPointer.bindMemory(to: byte.self).baseAddress, plaintext.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Authenticate and decrypt a single frame as an explicit chunk index for random-access reads.
    /// The frame's embedded counter is validated against the passed-in chunk_index (a mismatch returns
    /// ERROR_BAD_ENCRYPTED_DATA), so callers must pass the true positional index and never trust the
    /// frame's own counter. Independent of the streaming state machine; requires key, initial nonce,
    /// and chunk_size to be set, and the instance to be in the INITIAL state.
    ///
    /// Thread-safe: uses a per-call local cipher context and only reads the instance's
    /// key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple
    /// threads for parallel/random-access decryption (no shared mutable cipher state, no lock). Note:
    /// this authenticates which frame is last (is_last) and each frame's position, but not the total
    /// number of frames — protect against truncation by authenticating the chunk count out of band
    /// (or deriving it from the ciphertext length).
    @objc public func decryptAt(chunkIndex: UInt64, isLast: Bool, frame: Data) throws -> Data {
        let outCount = self.decryptionOutLen(dataLen: frame.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = frame.withUnsafeBytes({ (framePointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_decrypt_at(self.c_ctx, chunkIndex, isLast, vsc_data(framePointer.bindMemory(to: byte.self).baseAddress, frame.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Set the 12-byte initial nonce. On encryption this is honored (not
    /// regenerated) by start_encryption; on decryption it is required.
    @objc public func setNonce(nonce: Data) {
        nonce.withUnsafeBytes({ (noncePointer: UnsafeRawBufferPointer) in
            vscf_chunk_cipher_set_nonce(self.c_ctx, vsc_data(noncePointer.bindMemory(to: byte.self).baseAddress, nonce.count))
        })
    }

    /// Set the 32-byte AES-256 encryption key.
    @objc public func setKey(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafeRawBufferPointer) in
            vscf_chunk_cipher_set_key(self.c_ctx, vsc_data(keyPointer.bindMemory(to: byte.self).baseAddress, key.count))
        })
    }

    /// Initiate encryption. Generates a random 12-byte initial nonce only if
    /// one was not already set (via set_nonce or restore_alg_info), so an
    /// injected nonce is honored. An RNG failure is captured and surfaced
    /// from the first process_encryption/update/finish call.
    @objc public func startEncryption() {
        vscf_chunk_cipher_start_encryption(self.c_ctx)
    }

    /// Initiate decryption. Caller must set the initial nonce (via set_nonce
    /// or restore_alg_info) before this.
    @objc public func startDecryption() {
        vscf_chunk_cipher_start_decryption(self.c_ctx)
    }

    /// Process encryption or decryption of the given data chunk.
    /// Dispatches to the framed encryption or decryption path depending on
    /// the current state.
    @objc public func update(data: Data) -> Data {
        let outCount = self.outLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                vscf_chunk_cipher_update(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an current mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func outLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an encryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func encryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_encrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an decryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func decryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_decrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Accomplish encryption or decryption process.
    /// Dispatches to finish_encryption or finish_decryption depending on
    /// the current state.
    @objc public func finish() throws -> Data {
        let outCount = self.outLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_chunk_cipher_finish(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_chunk_cipher_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_chunk_cipher_produce_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(take: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_chunk_cipher_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Encrypt given data.
    @objc public func encrypt(data: Data) throws -> Data {
        let outCount = self.encryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_encrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Precise length calculation of encrypted data.
    @objc public func preciseEncryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_precise_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Decrypt given data.
    @objc public func decrypt(data: Data) throws -> Data {
        let outCount = self.decryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_chunk_cipher_decrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Setup IV or nonce.
    @objc public func setNonce(nonce: Data) {
        nonce.withUnsafeBytes({ (noncePointer: UnsafeRawBufferPointer) in
            vscf_chunk_cipher_set_nonce(self.c_ctx, vsc_data(noncePointer.bindMemory(to: byte.self).baseAddress, nonce.count))
        })
    }

    /// Set cipher encryption / decryption key.
    @objc public func setKey(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafeRawBufferPointer) in
            vscf_chunk_cipher_set_key(self.c_ctx, vsc_data(keyPointer.bindMemory(to: byte.self).baseAddress, key.count))
        })
    }

    /// Start sequential encryption.
    @objc public func startEncryption() {
        vscf_chunk_cipher_start_encryption(self.c_ctx)
    }

    /// Start sequential decryption.
    @objc public func startDecryption() {
        vscf_chunk_cipher_start_decryption(self.c_ctx)
    }

    /// Process encryption or decryption of the given data chunk.
    @objc public func update(data: Data) -> Data {
        let outCount = self.outLen(dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                vscf_chunk_cipher_update(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an current mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func outLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an encryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func encryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_encrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an decryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func decryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_chunk_cipher_decrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Accomplish encryption or decryption process.
    @objc public func finish() throws -> Data {
        let outCount = self.outLen(dataLen: 0)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_chunk_cipher_finish(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

}
