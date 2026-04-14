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

import com.virgilsecurity.crypto.common.utils.NativeUtils;

public class RatchetJNI {

    public static final RatchetJNI INSTANCE;

    static {
        NativeUtils.load("vscr_ratchet");
        INSTANCE = new RatchetJNI();
    }

    private RatchetJNI() {
    }

    public native long ratchetMessage_new();

    public native void ratchetMessage_close(long cCtx);

    public native MsgType ratchetMessage_getType(long cCtx);

    public native int ratchetMessage_getCounter(long cCtx);

    public native byte[] ratchetMessage_getSenderIdentityKeyId(long cCtx);

    public native byte[] ratchetMessage_getReceiverIdentityKeyId(long cCtx);

    public native byte[] ratchetMessage_getReceiverLongTermKeyId(long cCtx);

    public native byte[] ratchetMessage_getReceiverOneTimeKeyId(long cCtx);

    public native int ratchetMessage_serializeLen(long cCtx);

    public native byte[] ratchetMessage_serialize(long cCtx);

    public native RatchetMessage ratchetMessage_deserialize(long cCtx, byte[] input) throws RatchetException;

    public native long ratchetSession_new();

    public native void ratchetSession_close(long cCtx);

    public native void ratchetSession_setRng(long cCtx, Random rng);

    public native void ratchetSession_setupDefaults(long cCtx) throws RatchetException;

    public native void ratchetSession_initiate(long cCtx, PrivateKey senderIdentityPrivateKey, byte[] senderIdentityKeyId, PublicKey receiverIdentityPublicKey, byte[] receiverIdentityKeyId, PublicKey receiverLongTermPublicKey, byte[] receiverLongTermKeyId, PublicKey receiverOneTimePublicKey, byte[] receiverOneTimeKeyId, boolean enablePostQuantum) throws RatchetException;

    public native void ratchetSession_initiateNoOneTimeKey(long cCtx, PrivateKey senderIdentityPrivateKey, byte[] senderIdentityKeyId, PublicKey receiverIdentityPublicKey, byte[] receiverIdentityKeyId, PublicKey receiverLongTermPublicKey, byte[] receiverLongTermKeyId, boolean enablePostQuantum) throws RatchetException;

    public native void ratchetSession_respond(long cCtx, PublicKey senderIdentityPublicKey, PrivateKey receiverIdentityPrivateKey, PrivateKey receiverLongTermPrivateKey, PrivateKey receiverOneTimePrivateKey, RatchetMessage message, boolean enablePostQuantum) throws RatchetException;

    public native void ratchetSession_respondNoOneTimeKey(long cCtx, PublicKey senderIdentityPublicKey, PrivateKey receiverIdentityPrivateKey, PrivateKey receiverLongTermPrivateKey, RatchetMessage message, boolean enablePostQuantum) throws RatchetException;

    public native boolean ratchetSession_isInitiator(long cCtx);

    public native boolean ratchetSession_isPqcEnabled(long cCtx);

    public native boolean ratchetSession_receivedFirstResponse(long cCtx);

    public native boolean ratchetSession_receiverHasOneTimePublicKey(long cCtx);

    public native RatchetMessage ratchetSession_encrypt(long cCtx, byte[] plainText) throws RatchetException;

    public native int ratchetSession_decryptLen(long cCtx, RatchetMessage message);

    public native byte[] ratchetSession_decrypt(long cCtx, RatchetMessage message) throws RatchetException;

    public native byte[] ratchetSession_serialize(long cCtx);

    public native RatchetSession ratchetSession_deserialize(long cCtx, byte[] input) throws RatchetException;

}
