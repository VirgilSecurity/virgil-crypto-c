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
* Group chat encryption session.
*/
public class GroupSession implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public GroupSession() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.groupSession_new();
    }

    /*
    * Sender id len
    */
    public int getSenderIdLen() {
        return 32;
    }

    /*
    * Max plain text len
    */
    public int getMaxPlainTextLen() {
        return 30000;
    }

    /*
    * Max epochs count
    */
    public int getMaxEpochsCount() {
        return 50;
    }

    /*
    * Salt size
    */
    public int getSaltSize() {
        return 32;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static GroupSession getInstance(long cCtx) {
        GroupSession newInstance = new GroupSession();
        newInstance.cCtx = cCtx;
        return newInstance;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.groupSession_close(this.cCtx);
    }

    /*
    * Random
    */
    public void setRng(Random rng) {
        FoundationJNI.INSTANCE.groupSession_setRng(this.cCtx, rng);
    }

    /*
    * Returns current epoch.
    */
    public long getCurrentEpoch() {
        return FoundationJNI.INSTANCE.groupSession_getCurrentEpoch(this.cCtx);
    }

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.groupSession_setupDefaults(this.cCtx);
    }

    /*
    * Returns session id.
    */
    public byte[] getSessionId() {
        return FoundationJNI.INSTANCE.groupSession_getSessionId(this.cCtx);
    }

    /*
    * Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    * Epoch message should be encrypted and signed by trusted group chat member (admin).
    */
    public void addEpoch(GroupSessionMessage message) throws FoundationException {
        FoundationJNI.INSTANCE.groupSession_addEpoch(this.cCtx, message);
    }

    /*
    * Encrypts data
    */
    public GroupSessionMessage encrypt(byte[] plainText, byte[] privateKey, byte[] senderId) throws FoundationException {
        return FoundationJNI.INSTANCE.groupSession_encrypt(this.cCtx, plainText, privateKey, senderId);
    }

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public int decryptLen(GroupSessionMessage message) {
        return FoundationJNI.INSTANCE.groupSession_decryptLen(this.cCtx, message);
    }

    /*
    * Decrypts message
    */
    public byte[] decrypt(GroupSessionMessage message, byte[] publicKey, byte[] senderId) throws FoundationException {
        return FoundationJNI.INSTANCE.groupSession_decrypt(this.cCtx, message, publicKey, senderId);
    }

    /*
    * Creates ticket with new key for removing participants or proactive to rotate encryption key.
    */
    public GroupSessionTicket createGroupTicket() throws FoundationException {
        return FoundationJNI.INSTANCE.groupSession_createGroupTicket(this.cCtx);
    }
}

