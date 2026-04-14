/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

public class Aes256Gcm implements AutoCloseable, Alg, Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth {

    public long cCtx;

    public Aes256Gcm() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.aes256Gcm_new();
    }

    package Aes256Gcm(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public Aes256Gcm getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Aes256Gcm(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.aes256Gcm_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public int getNonceLen() {
        return 12;
    }

    public int getKeyLen() {
        return 32;
    }

    public int getKeyBitlen() {
        return 256;
    }

    public int getBlockLen() {
        return 16;
    }

    public int getAuthTagLen() {
        return 16;
    }

    public AlgId algId() {
        return FoundationJNI.INSTANCE.aes256Gcm_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.aes256Gcm_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.aes256Gcm_restoreAlgInfo(this.cCtx, algInfo);
    }

    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_encrypt(this.cCtx, data);
    }

    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_encryptedLen(this.cCtx, dataLen);
    }

    public int preciseEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_preciseEncryptedLen(this.cCtx, dataLen);
    }

    public byte[] decrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_decrypt(this.cCtx, data);
    }

    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_decryptedLen(this.cCtx, dataLen);
    }

    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.aes256Gcm_setNonce(this.cCtx, nonce);
    }

    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.aes256Gcm_setKey(this.cCtx, key);
    }

    public void startEncryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startEncryption(this.cCtx);
    }

    public void startDecryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startDecryption(this.cCtx);
    }

    public byte[] update(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Gcm_update(this.cCtx, data);
    }

    public int outLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_outLen(this.cCtx, dataLen);
    }

    public int encryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_encryptedOutLen(this.cCtx, dataLen);
    }

    public int decryptedOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_decryptedOutLen(this.cCtx, dataLen);
    }

    public byte[] finish() throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finish(this.cCtx);
    }

    public Aes256GcmAuthEncryptResult authEncrypt(byte[] data, byte[] authData) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncrypt(this.cCtx, data, authData);
    }

    public int authEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncryptedLen(this.cCtx, dataLen);
    }

    public byte[] authDecrypt(byte[] data, byte[] authData, byte[] tag) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecrypt(this.cCtx, data, authData, tag);
    }

    public int authDecryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecryptedLen(this.cCtx, dataLen);
    }

    public void setAuthData(byte[] authData) {
        FoundationJNI.INSTANCE.aes256Gcm_setAuthData(this.cCtx, authData);
    }

    public Aes256GcmFinishAuthEncryptionResult finishAuthEncryption() throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finishAuthEncryption(this.cCtx);
    }

    public byte[] finishAuthDecryption(byte[] tag) throws FoundationException {
        return FoundationJNI.INSTANCE.aes256Gcm_finishAuthDecryption(this.cCtx, tag);
    }

}
