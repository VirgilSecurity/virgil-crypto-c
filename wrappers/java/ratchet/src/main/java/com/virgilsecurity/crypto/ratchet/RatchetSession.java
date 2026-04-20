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

package com.virgilsecurity.crypto.ratchet;

import com.virgilsecurity.crypto.foundation.*;

public class RatchetSession implements AutoCloseable {

    public long cCtx;

    public RatchetSession() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetSession_new();
    }

    RatchetSession(RatchetContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static RatchetSession getInstance(long cCtx) {
        RatchetContextHolder ctxHolder = new RatchetContextHolder(cCtx);
        return new RatchetSession(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            RatchetJNI.INSTANCE.ratchetSession_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRng(Random rng) {
        RatchetJNI.INSTANCE.ratchetSession_setRng(this.cCtx, rng);
    }

    public void setupDefaults() throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_setupDefaults(this.cCtx);
    }

    public void initiate(PrivateKey senderIdentityPrivateKey, byte[] senderIdentityKeyId, PublicKey receiverIdentityPublicKey, byte[] receiverIdentityKeyId, PublicKey receiverLongTermPublicKey, byte[] receiverLongTermKeyId, PublicKey receiverOneTimePublicKey, byte[] receiverOneTimeKeyId, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_initiate(this.cCtx, senderIdentityPrivateKey, senderIdentityKeyId, receiverIdentityPublicKey, receiverIdentityKeyId, receiverLongTermPublicKey, receiverLongTermKeyId, receiverOneTimePublicKey, receiverOneTimeKeyId, enablePostQuantum);
    }

    public void initiateNoOneTimeKey(PrivateKey senderIdentityPrivateKey, byte[] senderIdentityKeyId, PublicKey receiverIdentityPublicKey, byte[] receiverIdentityKeyId, PublicKey receiverLongTermPublicKey, byte[] receiverLongTermKeyId, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_initiateNoOneTimeKey(this.cCtx, senderIdentityPrivateKey, senderIdentityKeyId, receiverIdentityPublicKey, receiverIdentityKeyId, receiverLongTermPublicKey, receiverLongTermKeyId, enablePostQuantum);
    }

    public void respond(PublicKey senderIdentityPublicKey, PrivateKey receiverIdentityPrivateKey, PrivateKey receiverLongTermPrivateKey, PrivateKey receiverOneTimePrivateKey, RatchetMessage message, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_respond(this.cCtx, senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, receiverOneTimePrivateKey, message, enablePostQuantum);
    }

    public void respondNoOneTimeKey(PublicKey senderIdentityPublicKey, PrivateKey receiverIdentityPrivateKey, PrivateKey receiverLongTermPrivateKey, RatchetMessage message, boolean enablePostQuantum) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetSession_respondNoOneTimeKey(this.cCtx, senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, message, enablePostQuantum);
    }

    public boolean isInitiator() {
        return RatchetJNI.INSTANCE.ratchetSession_isInitiator(this.cCtx);
    }

    public boolean isPqcEnabled() {
        return RatchetJNI.INSTANCE.ratchetSession_isPqcEnabled(this.cCtx);
    }

    public boolean receivedFirstResponse() {
        return RatchetJNI.INSTANCE.ratchetSession_receivedFirstResponse(this.cCtx);
    }

    public boolean receiverHasOneTimePublicKey() {
        return RatchetJNI.INSTANCE.ratchetSession_receiverHasOneTimePublicKey(this.cCtx);
    }

    public RatchetMessage encrypt(byte[] plainText) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_encrypt(this.cCtx, plainText);
    }

    public int decryptLen(RatchetMessage message) {
        return RatchetJNI.INSTANCE.ratchetSession_decryptLen(this.cCtx, message);
    }

    public byte[] decrypt(RatchetMessage message) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_decrypt(this.cCtx, message);
    }

    public byte[] serialize() {
        return RatchetJNI.INSTANCE.ratchetSession_serialize(this.cCtx);
    }

    public static RatchetSession deserialize(byte[] input) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetSession_deserialize(input);
    }

}
