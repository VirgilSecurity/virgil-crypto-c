/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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

package com.virgilsecurity.crypto.ratchet;

import com.virgilsecurity.crypto.foundation.*;

/*
* Class for ratchet session between 2 participants
*/
public class RatchetSession implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public RatchetSession() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetSession_new();
    }

    /* Wrap underlying C context. */
    RatchetSession(RatchetContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RatchetSession getInstance(long cCtx) {
        RatchetContextHolder ctxHolder = new RatchetContextHolder(cCtx);
        return new RatchetSession(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            RatchetJNI.INSTANCE.ratchetSession_close(ctx);
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
    * Random used to generate keys
    */
    public void setRng(Random rng) {
        RatchetJNI.INSTANCE.ratchetSession_setRng(this.cCtx, rng);
    }

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public void setupDefaults() throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_setupDefaults(this.cCtx);
    }

    /*
    * Initiates session
    */
    public void initiate(PrivateKey senderIdentityPrivateKey, byte[] senderIdentityKeyId, PublicKey receiverIdentityPublicKey, byte[] receiverIdentityKeyId, PublicKey receiverLongTermPublicKey, byte[] receiverLongTermKeyId, PublicKey receiverOneTimePublicKey, byte[] receiverOneTimeKeyId, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_initiate(this.cCtx, senderIdentityPrivateKey, senderIdentityKeyId, receiverIdentityPublicKey, receiverIdentityKeyId, receiverLongTermPublicKey, receiverLongTermKeyId, receiverOneTimePublicKey, receiverOneTimeKeyId, enablePostQuantum);
    }

    /*
    * Responds to session initiation
    */
    public void respond(PublicKey senderIdentityPublicKey, PrivateKey receiverIdentityPrivateKey, PrivateKey receiverLongTermPrivateKey, PrivateKey receiverOneTimePrivateKey, RatchetMessage message, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_respond(this.cCtx, senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, receiverOneTimePrivateKey, message, enablePostQuantum);
    }

    /*
    * Returns flag that indicates is this session was initiated or responded
    */
    public boolean isInitiator() {
        return RatchetJNI.INSTANCE.ratchetSession_isInitiator(this.cCtx);
    }

    /*
    * Returns true if at least 1 response was successfully decrypted, false - otherwise
    */
    public boolean receivedFirstResponse() {
        return RatchetJNI.INSTANCE.ratchetSession_receivedFirstResponse(this.cCtx);
    }

    /*
    * Returns true if receiver had one time public key
    */
    public boolean receiverHasOneTimePublicKey() {
        return RatchetJNI.INSTANCE.ratchetSession_receiverHasOneTimePublicKey(this.cCtx);
    }

    /*
    * Encrypts data
    */
    public RatchetMessage encrypt(byte[] plainText) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_encrypt(this.cCtx, plainText);
    }

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public int decryptLen(RatchetMessage message) {
        return RatchetJNI.INSTANCE.ratchetSession_decryptLen(this.cCtx, message);
    }

    /*
    * Decrypts message
    */
    public byte[] decrypt(RatchetMessage message) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_decrypt(this.cCtx, message);
    }

    /*
    * Serializes session to buffer
    */
    public byte[] serialize() {
        return RatchetJNI.INSTANCE.ratchetSession_serialize(this.cCtx);
    }

    /*
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    */
    public static RatchetSession deserialize(byte[] input) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_deserialize(input);
    }
}

