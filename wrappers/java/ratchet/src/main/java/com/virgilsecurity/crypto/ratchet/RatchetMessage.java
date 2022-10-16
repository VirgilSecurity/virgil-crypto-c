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

/*
* Class represents ratchet message
*/
public class RatchetMessage implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public RatchetMessage() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetMessage_new();
    }

    /* Wrap underlying C context. */
    RatchetMessage(RatchetContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RatchetMessage getInstance(long cCtx) {
        RatchetContextHolder ctxHolder = new RatchetContextHolder(cCtx);
        return new RatchetMessage(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            RatchetJNI.INSTANCE.ratchetMessage_close(ctx);
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
    * Returns message type.
    */
    public MsgType getType() {
        return RatchetJNI.INSTANCE.ratchetMessage_getType(this.cCtx);
    }

    /*
    * Returns message counter in current asymmetric ratchet round.
    */
    public long getCounter() {
        return RatchetJNI.INSTANCE.ratchetMessage_getCounter(this.cCtx);
    }

    /*
    * Returns long-term public key, if message is prekey message.
    */
    public byte[] getSenderIdentityKeyId() {
        return RatchetJNI.INSTANCE.ratchetMessage_getSenderIdentityKeyId(this.cCtx);
    }

    /*
    * Returns long-term public key, if message is prekey message.
    */
    public byte[] getReceiverIdentityKeyId() {
        return RatchetJNI.INSTANCE.ratchetMessage_getReceiverIdentityKeyId(this.cCtx);
    }

    /*
    * Returns long-term public key, if message is prekey message.
    */
    public byte[] getReceiverLongTermKeyId() {
        return RatchetJNI.INSTANCE.ratchetMessage_getReceiverLongTermKeyId(this.cCtx);
    }

    /*
    * Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
    */
    public byte[] getReceiverOneTimeKeyId() {
        return RatchetJNI.INSTANCE.ratchetMessage_getReceiverOneTimeKeyId(this.cCtx);
    }

    /*
    * Buffer len to serialize this class.
    */
    public int serializeLen() {
        return RatchetJNI.INSTANCE.ratchetMessage_serializeLen(this.cCtx);
    }

    /*
    * Serializes instance.
    */
    public byte[] serialize() {
        return RatchetJNI.INSTANCE.ratchetMessage_serialize(this.cCtx);
    }

    /*
    * Deserializes instance.
    */
    public static RatchetMessage deserialize(byte[] input) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetMessage_deserialize(input);
    }
}

