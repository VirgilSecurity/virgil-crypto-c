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

package com.virgilsecurity.crypto.ratchet;

import com.virgilsecurity.crypto.foundation.*;

/*
* Ratchet group session.
*/
public class RatchetGroupSession implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public RatchetGroupSession() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetGroupSession_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public RatchetGroupSession(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        RatchetJNI.INSTANCE.ratchetGroupSession_close(this.cCtx);
    }

    /*
    * Random used to generate keys
    */
    public void setRng(Random rng) {
        RatchetJNI.INSTANCE.ratchetGroupSession_setRng(this.cCtx, rng);
    }

    /*
    * Shows whether session was initialized.
    */
    public boolean isInitialized() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_isInitialized(this.cCtx);
    }

    /*
    * Shows whether identity private key was set.
    */
    public boolean isPrivateKeySet() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_isPrivateKeySet(this.cCtx);
    }

    /*
    * Shows whether identity private key was set.
    */
    public boolean isIdSet() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_isIdSet(this.cCtx);
    }

    public int getCurrentEpoch() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_getCurrentEpoch(this.cCtx);
    }

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public void setupDefaults() throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupSession_setupDefaults(this.cCtx);
    }

    /*
    * Sets identity private key.
    */
    public void setPrivateKey(byte[] myPrivateKey) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupSession_setPrivateKey(this.cCtx, myPrivateKey);
    }

    /*
    * Sets identity private key.
    */
    public void setId(byte[] myId) {
        RatchetJNI.INSTANCE.ratchetGroupSession_setId(this.cCtx, myId);
    }

    public byte[] getMyId() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_getMyId(this.cCtx);
    }

    public byte[] getId() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_getId(this.cCtx);
    }

    /*
    * Sets up session. Identity private key should be set separately.
    */
    public void setupSession(RatchetGroupMessage message) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupSession_setupSession(this.cCtx, message);
    }

    /*
    * Encrypts data
    */
    public RatchetGroupMessage encrypt(byte[] plainText) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetGroupSession_encrypt(this.cCtx, plainText);
    }

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public int decryptLen(RatchetGroupMessage message) {
        return RatchetJNI.INSTANCE.ratchetGroupSession_decryptLen(this.cCtx, message);
    }

    /*
    * Decrypts message
    */
    public byte[] decrypt(RatchetGroupMessage message) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetGroupSession_decrypt(this.cCtx, message);
    }

    /*
    * Calculates size of buffer sufficient to store session
    */
    public int serializeLen() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_serializeLen(this.cCtx);
    }

    /*
    * Serializes session to buffer
    */
    public byte[] serialize() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_serialize(this.cCtx);
    }

    /*
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    */
    public static RatchetGroupSession deserialize(byte[] input) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetGroupSession_deserialize(input);
    }

    public RatchetGroupTicket createGroupTicketForAddingMembers() {
        return RatchetJNI.INSTANCE.ratchetGroupSession_createGroupTicketForAddingMembers(this.cCtx);
    }

    public RatchetGroupTicket createGroupTicketForAddingOrRemovingMembers() throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetGroupSession_createGroupTicketForAddingOrRemovingMembers(this.cCtx);
    }
}
