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
* This class provides hybrid encryption algorithm that combines symmetric
* cipher for data encryption and asymmetric cipher and password based
* cipher for symmetric key encryption.
*/
public class RecipientCipher implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public RecipientCipher() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.recipientCipher_new();
    }

    /* Wrap underlying C context. */
    RecipientCipher(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RecipientCipher getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new RecipientCipher(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.recipientCipher_close(this.cCtx);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.recipientCipher_setRandom(this.cCtx, random);
    }

    public void setEncryptionCipher(Cipher encryptionCipher) {
        FoundationJNI.INSTANCE.recipientCipher_setEncryptionCipher(this.cCtx, encryptionCipher);
    }

    public void setSignerHash(Hash signerHash) {
        FoundationJNI.INSTANCE.recipientCipher_setSignerHash(this.cCtx, signerHash);
    }

    /*
    * Add recipient defined with id and public key.
    */
    public void addKeyRecipient(byte[] recipientId, PublicKey publicKey) {
        FoundationJNI.INSTANCE.recipientCipher_addKeyRecipient(this.cCtx, recipientId, publicKey);
    }

    /*
    * Remove all recipients.
    */
    public void clearRecipients() {
        FoundationJNI.INSTANCE.recipientCipher_clearRecipients(this.cCtx);
    }

    /*
    * Add identifier and private key to sign initial plain text.
    * Return error if the private key can not sign.
    */
    public void addSigner(byte[] signerId, PrivateKey privateKey) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_addSigner(this.cCtx, signerId, privateKey);
    }

    /*
    * Remove all signers.
    */
    public void clearSigners() {
        FoundationJNI.INSTANCE.recipientCipher_clearSigners(this.cCtx);
    }

    /*
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    */
    public MessageInfoCustomParams customParams() {
        return FoundationJNI.INSTANCE.recipientCipher_customParams(this.cCtx);
    }

    /*
    * Start encryption process.
    */
    public void startEncryption() throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startEncryption(this.cCtx);
    }

    /*
    * Start encryption process with known plain text size.
    *
    * Precondition: At least one signer should be added.
    * Note, store message info footer as well.
    */
    public void startSignedEncryption(int dataSize) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startSignedEncryption(this.cCtx, dataSize);
    }

    /*
    * Return buffer length required to hold message info returned by the
    * "pack message info" method.
    * Precondition: all recipients and custom parameters should be set.
    */
    public int messageInfoLen() {
        return FoundationJNI.INSTANCE.recipientCipher_messageInfoLen(this.cCtx);
    }

    /*
    * Return serialized message info to the buffer.
    *
    * Precondition: this method should be called after "start encryption".
    * Precondition: this method should be called before "finish encryption".
    *
    * Note, store message info to use it for decryption process,
    * or place it at the encrypted data beginning (embedding).
    *
    * Return message info - recipients public information,
    * algorithm information, etc.
    */
    public byte[] packMessageInfo() {
        return FoundationJNI.INSTANCE.recipientCipher_packMessageInfo(this.cCtx);
    }

    /*
    * Return buffer length required to hold output of the method
    * "process encryption" and method "finish" during encryption.
    */
    public int encryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.recipientCipher_encryptionOutLen(this.cCtx, dataLen);
    }

    /*
    * Process encryption of a new portion of data.
    */
    public byte[] processEncryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_processEncryption(this.cCtx, data);
    }

    /*
    * Accomplish encryption.
    */
    public byte[] finishEncryption() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_finishEncryption(this.cCtx);
    }

    /*
    * Initiate decryption process with a recipient private key.
    * Message Info can be empty if it was embedded to encrypted data.
    */
    public void startDecryptionWithKey(byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startDecryptionWithKey(this.cCtx, recipientId, privateKey, messageInfo);
    }

    /*
    * Initiate decryption process with a recipient private key.
    * Message Info can be empty if it was embedded to encrypted data.
    * Message Info footer can be empty if it was embedded to encrypted data.
    * If footer was embedded, method "start decryption with key" can be used.
    */
    public void startVerifiedDecryptionWithKey(byte[] recipientId, PrivateKey privateKey, byte[] messageInfo, byte[] messageInfoFooter) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startVerifiedDecryptionWithKey(this.cCtx, recipientId, privateKey, messageInfo, messageInfoFooter);
    }

    /*
    * Return buffer length required to hold output of the method
    * "process decryption" and method "finish" during decryption.
    */
    public int decryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.recipientCipher_decryptionOutLen(this.cCtx, dataLen);
    }

    /*
    * Process with a new portion of data.
    * Return error if data can not be encrypted or decrypted.
    */
    public byte[] processDecryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_processDecryption(this.cCtx, data);
    }

    /*
    * Accomplish decryption.
    */
    public byte[] finishDecryption() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_finishDecryption(this.cCtx);
    }

    /*
    * Return true if data was signed by a sender.
    *
    * Precondition: this method should be called after "finish decryption".
    */
    public boolean isDataSigned() {
        return FoundationJNI.INSTANCE.recipientCipher_isDataSigned(this.cCtx);
    }

    /*
    * Return information about signers that sign data.
    *
    * Precondition: this method should be called after "finish decryption".
    * Precondition: method "is data signed" returns true.
    */
    public SignerInfoList signerInfos() {
        return FoundationJNI.INSTANCE.recipientCipher_signerInfos(this.cCtx);
    }

    /*
    * Verify given cipher info.
    */
    public boolean verifySignerInfo(SignerInfo signerInfo, PublicKey publicKey) {
        return FoundationJNI.INSTANCE.recipientCipher_verifySignerInfo(this.cCtx, signerInfo, publicKey);
    }

    /*
    * Return buffer length required to hold message footer returned by the
    * "pack message footer" method.
    *
    * Precondition: this method should be called after "finish encryption".
    */
    public int messageInfoFooterLen() {
        return FoundationJNI.INSTANCE.recipientCipher_messageInfoFooterLen(this.cCtx);
    }

    /*
    * Return serialized message info footer to the buffer.
    *
    * Precondition: this method should be called after "finish encryption".
    *
    * Note, store message info to use it for verified decryption process,
    * or place it at the encrypted data ending (embedding).
    *
    * Return message info footer - signers public information, etc.
    */
    public byte[] packMessageInfoFooter() throws FoundationException {
        return FoundationJNI.INSTANCE.recipientCipher_packMessageInfoFooter(this.cCtx);
    }
}

