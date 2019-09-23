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
* Add and/or remove recipients and it's parameters within message info.
*
* Usage:
* 1. Unpack binary message info that was obtained from RecipientCipher.
* 2. Add and/or remove key recipients.
* 3. Pack MessagInfo to the binary data.
*/
public class MessageInfoEditor implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public MessageInfoEditor() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoEditor_new();
    }

    /* Wrap underlying C context. */
    MessageInfoEditor(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static MessageInfoEditor getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoEditor(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.messageInfoEditor_close(this.cCtx);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.messageInfoEditor_setRandom(this.cCtx, random);
    }

    /*
    * Set dependencies to it's defaults.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_setupDefaults(this.cCtx);
    }

    /*
    * Unpack serialized message info.
    *
    * Note that recipients can only be removed but not added.
    * Note, use "unlock" method to be able to add new recipients as well.
    */
    public void unpack(byte[] messageInfoData) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_unpack(this.cCtx, messageInfoData);
    }

    /*
    * Decrypt encryption key this allows adding new recipients.
    */
    public void unlock(byte[] ownerRecipientId, PrivateKey ownerPrivateKey) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_unlock(this.cCtx, ownerRecipientId, ownerPrivateKey);
    }

    /*
    * Add recipient defined with id and public key.
    */
    public void addKeyRecipient(byte[] recipientId, PublicKey publicKey) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoEditor_addKeyRecipient(this.cCtx, recipientId, publicKey);
    }

    /*
    * Remove recipient with a given id.
    * Return false if recipient with given id was not found.
    */
    public boolean removeKeyRecipient(byte[] recipientId) {
        return FoundationJNI.INSTANCE.messageInfoEditor_removeKeyRecipient(this.cCtx, recipientId);
    }

    /*
    * Remove all existent recipients.
    */
    public void removeAll() {
        FoundationJNI.INSTANCE.messageInfoEditor_removeAll(this.cCtx);
    }

    /*
    * Return length of serialized message info.
    * Actual length can be obtained right after applying changes.
    */
    public int packedLen() {
        return FoundationJNI.INSTANCE.messageInfoEditor_packedLen(this.cCtx);
    }

    /*
    * Return serialized message info.
    * Precondition: this method can be called after "apply".
    */
    public byte[] pack() {
        return FoundationJNI.INSTANCE.messageInfoEditor_pack(this.cCtx);
    }
}

