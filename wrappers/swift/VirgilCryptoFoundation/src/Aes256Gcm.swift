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

/// Implementation of the symmetric cipher AES-256 bit in a GCM mode.
/// Note, this implementation contains dynamic memory allocations,
/// this should be improved in the future releases.
@objc(VSCFAes256Gcm) public class Aes256Gcm : Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth {
    @objc func public encrypt(data: Data) throws -> Data {
        //  TODO: Implement me.
    }
    @objc func public encryptedLen(dataLen: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public decrypt(data: Data) throws -> Data {
        //  TODO: Implement me.
    }
    @objc func public decryptedLen(dataLen: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public setNonce(nonce: Data) {
        //  TODO: Implement me.
    }
    @objc func public setKey(key: Data) {
        //  TODO: Implement me.
    }
    @objc func public authEncrypt(data: Data, authData: Data) throws -> (out: Data, tag: Data) {
        //  TODO: Implement me.
    }
    @objc func public authEncryptedLen(dataLen: Int) -> Int {
        //  TODO: Implement me.
    }
    @objc func public authDecrypt(data: Data, authData: Data, tag: Data) throws -> Data {
        //  TODO: Implement me.
    }
    @objc func public authDecryptedLen(dataLen: Int) -> Int {
        //  TODO: Implement me.
    }
}

