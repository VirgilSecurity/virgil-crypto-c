/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

package com.virgilsecurity.crypto.foundation;

/*
* Implementation of the symmetric cipher AES-256 bit in a CBC mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
public class Aes256Cbc implements AutoCloseable, Alg, Encrypt, Decrypt, CipherInfo, Cipher {

    public java.nio.ByteBuffer cCtx;

    /* Create underlying C context. */
    public Aes256Cbc() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.aes256Cbc_new();
    }

    /* Wrap underlying C context. */
    Aes256Cbc(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Aes256Cbc getInstance(java.nio.ByteBuffer cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Aes256Cbc(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.aes256Cbc_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.aes256Cbc_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.aes256Cbc_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.aes256Cbc_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Encrypt given data.
    */
    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Cbc_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Cbc_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Cbc_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Cbc_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    */
    public int getNonceLen() {
        return 16;
    }

    /*
    * Cipher key length in bytes.
    */
    public int getKeyLen() {
        return 32;
    }

    /*
    * Cipher key length in bits.
    */
    public int getKeyBitlen() {
        return 256;
    }

    /*
    * Cipher block length in bytes.
    */
    public int getBlockLen() {
        return 16;
    }

    /*
    * Setup IV or nonce.
    */
    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.aes256Cbc_setNonce(this.cCtx, nonce);
    }

    /*
    * Set cipher encryption / decryption key.
    */
    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.aes256Cbc_setKey(this.cCtx, key);
    }

    /*
    * Start sequential encryption.
    */
    public void startEncryption() {
        FoundationJNI.INSTANCE.aes256Cbc_startEncryption(this.cCtx);
    }

    /*
    * Start sequential decryption.
    */
    public void startDecryption() {
        FoundationJNI.INSTANCE.aes256Cbc_startDecryption(this.cCtx);
    }

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public byte[] update(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Cbc_update(this.cCtx, data);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int outLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Cbc_outLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int encryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Cbc_encryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int decryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Cbc_decryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Accomplish encryption or decryption process.
    */
    public byte[] finish() throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Cbc_finish(this.cCtx);
    }
}

