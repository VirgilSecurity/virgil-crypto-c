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
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    */
    public MessageInfoCustomParams customParams() {
        return FoundationJNI.INSTANCE.recipientCipher_customParams(this.cCtx);
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
    * Start encryption process.
    */
    public void startEncryption() throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startEncryption(this.cCtx);
    }

    /*
    * Return serialized message info to the buffer.
    *
    * Precondition: this method can be called after "start encryption".
    * Precondition: this method can be called before "finish encryption".
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
    * Message info can be empty if it was embedded to encrypted data.
    */
    public void startDecryptionWithKey(byte[] recipientId, PrivateKey privateKey, byte[] messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.recipientCipher_startDecryptionWithKey(this.cCtx, recipientId, privateKey, messageInfo);
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
}

