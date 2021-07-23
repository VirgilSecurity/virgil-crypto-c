/*
* Copyright (C) 2015-2021 Virgil Security, Inc.
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
* Implementation of the symmetric cipher AES-256 bit in a GCM mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
public class Aes256Gcm implements AutoCloseable, Alg, Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth {

    public long cCtx;

    /* Create underlying C context. */
    public Aes256Gcm() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.aes256Gcm_new();
    }

    /* Wrap underlying C context. */
    Aes256Gcm(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Aes256Gcm getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Aes256Gcm(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.aes256Gcm_close(ctx);
        }
    }

    /* Close resource. */
    public void close() {
        clearResources();
    }

    /* Finalize resource. */
    protected void finalize() throws Throwable {
        clearResources();
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.aes256Gcm_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.aes256Gcm_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.aes256Gcm_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Encrypt given data.
    */
    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Precise length calculation of encrypted data.
    */
    public int preciseEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_preciseEncryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    */
    public int getNonceLen() {
        return 12;
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
        FoundationJNI.INSTANCE.aes256Gcm_setNonce(this.cCtx, nonce);
    }

    /*
    * Set cipher encryption / decryption key.
    */
    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.aes256Gcm_setKey(this.cCtx, key);
    }

    /*
    * Start sequential encryption.
    */
    public void startEncryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startEncryption(this.cCtx);
    }

    /*
    * Start sequential decryption.
    */
    public void startDecryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startDecryption(this.cCtx);
    }

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public byte[] update(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Gcm_update(this.cCtx, data);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int outLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_outLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int encryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_encryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int decryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_decryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Accomplish encryption or decryption process.
    */
    public byte[] finish() throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finish(this.cCtx);
    }

    /*
    * Defines authentication tag length in bytes.
    */
    public int getAuthTagLen() {
        return 16;
    }

    /*
    * Encrypt given data.
    * If 'tag' is not given, then it will written to the 'enc'.
    */
    public AuthEncryptAuthEncryptResult authEncrypt(byte[] data, byte[] authData) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncrypt(this.cCtx, data, authData);
    }

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
    */
    public int authEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
    * If 'tag' is not given, then it will be taken from the 'enc'.
    */
    public byte[] authDecrypt(byte[] data, byte[] authData, byte[] tag) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecrypt(this.cCtx, data, authData, tag);
    }

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
    */
    public int authDecryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecryptedLen(this.cCtx, dataLen);
    }

    /*
    * Set additional data for for AEAD ciphers.
    */
    public void setAuthData(byte[] authData) {
        FoundationJNI.INSTANCE.aes256Gcm_setAuthData(this.cCtx, authData);
    }

    /*
    * Accomplish an authenticated encryption and place tag separately.
    *
    * Note, if authentication tag should be added to an encrypted data,
    * method "finish" can be used.
    */
    public CipherAuthFinishAuthEncryptionResult finishAuthEncryption() throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finishAuthEncryption(this.cCtx);
    }

    /*
    * Accomplish an authenticated decryption with explicitly given tag.
    *
    * Note, if authentication tag is a part of an encrypted data then,
    * method "finish" can be used for simplicity.
    */
    public byte[] finishAuthDecryption(byte[] tag) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finishAuthDecryption(this.cCtx, tag);
    }
}

