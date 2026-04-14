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

public class RecipientCipher implements AutoCloseable {

    public long cCtx;

    public RecipientCipher() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.recipientCipher_new();
    }

    RecipientCipher(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public RecipientCipher getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new RecipientCipher(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.recipientCipher_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.recipientCipher_setRandom(this.cCtx, random);
    }

    public void setEncryptionCipher(Cipher encryptionCipher) {
        FoundationJNI.INSTANCE.recipientCipher_setEncryptionCipher(this.cCtx, encryptionCipher);
    }

    public void setEncryptionPadding(Padding encryptionPadding) {
        FoundationJNI.INSTANCE.recipientCipher_setEncryptionPadding(this.cCtx, encryptionPadding);
    }

    public void setPaddingParams(PaddingParams paddingParams) {
        FoundationJNI.INSTANCE.recipientCipher_setPaddingParams(this.cCtx, paddingParams);
    }

    public void setSignerHash(Hash signerHash) {
        FoundationJNI.INSTANCE.recipientCipher_setSignerHash(this.cCtx, signerHash);
    }

    public boolean hasKeyRecipient(byte[] recipientId) {
        return FoundationJNI.INSTANCE.recipientCipher_hasKeyRecipient(this.cCtx, recipientId);
    }

    public void addKeyRecipient(byte[] recipientId, PublicKey publicKey) {
        FoundationJNI.INSTANCE.recipientCipher_addKeyRecipient(this.cCtx, recipientId, publicKey);
    }

    public void clearRecipients() {
        FoundationJNI.INSTANCE.recipientCipher_clearRecipients(this.cCtx);
    }

    public void addSigner(byte[] signerId, PrivateKey privateKey) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_addSigner(this.cCtx, signerId, privateKey);
    }

    public void clearSigners() {
        FoundationJNI.INSTANCE.recipientCipher_clearSigners(this.cCtx);
    }

    public MessageInfoCustomParams customParams() {
        return FoundationJNI.INSTANCE.recipientCipher_customParams(this.cCtx);
    }

    public void startEncryption() throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startEncryption(this.cCtx);
    }

    public void startSignedEncryption(int dataSize) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startSignedEncryption(this.cCtx, dataSize);
    }

    public int messageInfoLen() {
        return FoundationJNI.INSTANCE.recipientCipher_messageInfoLen(this.cCtx);
    }

    public byte[] packMessageInfo() {
        return FoundationJNI.INSTANCE.recipientCipher_packMessageInfo(this.cCtx);
    }

    public int encryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.recipientCipher_encryptionOutLen(this.cCtx, dataLen);
    }

    public byte[] processEncryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_processEncryption(this.cCtx, data);
    }

    public byte[] finishEncryption() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_finishEncryption(this.cCtx);
    }

    public void startDecryptionWithKey(byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startDecryptionWithKey(this.cCtx, recipientId, privateKey, messageInfo);
    }

    public void startVerifiedDecryptionWithKey(byte[] recipientId, PrivateKey privateKey, byte[] messageInfo, byte[] messageInfoFooter) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startVerifiedDecryptionWithKey(this.cCtx, recipientId, privateKey, messageInfo, messageInfoFooter);
    }

    public int decryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.recipientCipher_decryptionOutLen(this.cCtx, dataLen);
    }

    public byte[] processDecryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_processDecryption(this.cCtx, data);
    }

    public byte[] finishDecryption() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_finishDecryption(this.cCtx);
    }

    public boolean isDataSigned() {
        return FoundationJNI.INSTANCE.recipientCipher_isDataSigned(this.cCtx);
    }

    public SignerInfoList signerInfos() {
        return FoundationJNI.INSTANCE.recipientCipher_signerInfos(this.cCtx);
    }

    public boolean verifySignerInfo(SignerInfo signerInfo, PublicKey publicKey) {
        return FoundationJNI.INSTANCE.recipientCipher_verifySignerInfo(this.cCtx, signerInfo, publicKey);
    }

    public int messageInfoFooterLen() {
        return FoundationJNI.INSTANCE.recipientCipher_messageInfoFooterLen(this.cCtx);
    }

    public byte[] packMessageInfoFooter() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_packMessageInfoFooter(this.cCtx);
    }

}
