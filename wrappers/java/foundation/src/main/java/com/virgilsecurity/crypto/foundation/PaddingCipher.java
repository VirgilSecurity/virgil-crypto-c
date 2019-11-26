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
* Wraps any symmetric cipher algorithm to add padding to plaintext
* to prevent message guessing attacks based on a ciphertext length.
*/
public class PaddingCipher implements AutoCloseable, Alg, Encrypt, Decrypt, CipherInfo, Cipher {

    public long cCtx;

    /* Create underlying C context. */
    public PaddingCipher() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.paddingCipher_new();
    }

    /* Wrap underlying C context. */
    PaddingCipher(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public int getPaddingFrameDefault() {
        return 160;
    }

    public int getPaddingFrameMin() {
        return 32;
    }

    public int getPaddingFrameMax() {
        return 8 * 1024;
    }

    public int getPaddingSizeLen() {
        return 4;
    }

    public int getPaddingLenMin() {
        return vscf_padding_cipher_PADDING_SIZE_LEN + 1;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.paddingCipher_setRandom(this.cCtx, random);
    }

    public void setCipher(Cipher cipher) {
        FoundationJNI.INSTANCE.paddingCipher_setCipher(this.cCtx, cipher);
    }

    /*
    * Setup padding frame in bytes.
    * The padding frame defines the multiplicator of data length.
    */
    public void setPaddingFrame(int paddingFrame) {
        FoundationJNI.INSTANCE.paddingCipher_setPaddingFrame(this.cCtx, paddingFrame);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static PaddingCipher getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new PaddingCipher(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.paddingCipher_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.paddingCipher_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.paddingCipher_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.paddingCipher_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Encrypt given data.
    */
    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.paddingCipher_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Precise length calculation of encrypted data.
    */
    public int preciseEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_preciseEncryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.paddingCipher_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Return cipher's nonce length or IV length in bytes,
    * or 0 if nonce is not required.
    */
    public int nonceLen() {
        return FoundationJNI.INSTANCE.paddingCipher_nonceLen(this.cCtx);
    }

    /*
    * Return cipher's key length in bytes.
    */
    public int keyLen() {
        return FoundationJNI.INSTANCE.paddingCipher_keyLen(this.cCtx);
    }

    /*
    * Return cipher's key length in bits.
    */
    public int keyBitlen() {
        return FoundationJNI.INSTANCE.paddingCipher_keyBitlen(this.cCtx);
    }

    /*
    * Return cipher's block length in bytes.
    */
    public int blockLen() {
        return FoundationJNI.INSTANCE.paddingCipher_blockLen(this.cCtx);
    }

    /*
    * Setup IV or nonce.
    */
    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.paddingCipher_setNonce(this.cCtx, nonce);
    }

    /*
    * Set cipher encryption / decryption key.
    */
    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.paddingCipher_setKey(this.cCtx, key);
    }

    /*
    * Start sequential encryption.
    */
    public void startEncryption() {
        FoundationJNI.INSTANCE.paddingCipher_startEncryption(this.cCtx);
    }

    /*
    * Start sequential decryption.
    */
    public void startDecryption() {
        FoundationJNI.INSTANCE.paddingCipher_startDecryption(this.cCtx);
    }

    /*
    * Process encryption or decryption of the given data chunk.
    */
    public byte[] update(byte[] data) {
        return FoundationJNI.INSTANCE.paddingCipher_update(this.cCtx, data);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an current mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int outLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_outLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an encryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int encryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_encryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish" in an decryption mode.
    * Pass zero length to define buffer length of the method "finish".
    */
    public int decryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.paddingCipher_decryptedOutLen(this.cCtx, dataLen);
    }

    /*
    * Accomplish encryption or decryption process.
    */
    public byte[] finish() throws FoundationException {
        return FoundationJNI.INSTANCE.paddingCipher_finish(this.cCtx);
    }
}

