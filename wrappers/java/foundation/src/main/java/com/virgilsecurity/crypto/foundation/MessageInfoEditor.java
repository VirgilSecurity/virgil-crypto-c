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

public class MessageInfoEditor implements AutoCloseable {

    public long cCtx;

    public MessageInfoEditor() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoEditor_new();
    }

    MessageInfoEditor(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static MessageInfoEditor getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoEditor(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfoEditor_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.messageInfoEditor_setRandom(this.cCtx, random);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_setupDefaults(this.cCtx);
    }

    public void unpack(byte[] messageInfoData) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_unpack(this.cCtx, messageInfoData);
    }

    public void unlock(byte[] ownerRecipientId, PrivateKey ownerPrivateKey) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_unlock(this.cCtx, ownerRecipientId, ownerPrivateKey);
    }

    public void addKeyRecipient(byte[] recipientId, PublicKey publicKey) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_addKeyRecipient(this.cCtx, recipientId, publicKey);
    }

    public boolean removeKeyRecipient(byte[] recipientId) {
        return FoundationJNI.INSTANCE.messageInfoEditor_removeKeyRecipient(this.cCtx, recipientId);
    }

    public void removeAll() {
        FoundationJNI.INSTANCE.messageInfoEditor_removeAll(this.cCtx);
    }

    public int packedLen() {
        return FoundationJNI.INSTANCE.messageInfoEditor_packedLen(this.cCtx);
    }

    public byte[] pack() {
        return FoundationJNI.INSTANCE.messageInfoEditor_pack(this.cCtx);
    }

}
