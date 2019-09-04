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

import com.virgilsecurity.crypto.common.utils.NativeUtils;

import com.virgilsecurity.crypto.foundation.*;

public class RatchetJNI {

    public static final RatchetJNI INSTANCE;

    static {
        NativeUtils.load("vscr_ratchet");
        INSTANCE = new RatchetJNI();
    }

    private RatchetJNI() {
    }

    public native java.nio.ByteBuffer ratchetKeyId_new();

    public native void ratchetKeyId_close(java.nio.ByteBuffer cCtx);

    /*
    * Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key
    */
    public native byte[] ratchetKeyId_computePublicKeyId(java.nio.ByteBuffer cCtx, byte[] publicKey) throws RatchetException;

    public native java.nio.ByteBuffer ratchetMessage_new();

    public native void ratchetMessage_close(java.nio.ByteBuffer cCtx);

    /*
    * Returns message type.
    */
    public native MsgType ratchetMessage_getType(java.nio.ByteBuffer cCtx);

    /*
    * Returns message counter in current asymmetric ratchet round.
    */
    public native long ratchetMessage_getCounter(java.nio.ByteBuffer cCtx);

    /*
    * Returns long-term public key, if message is prekey message.
    */
    public native byte[] ratchetMessage_getLongTermPublicKey(java.nio.ByteBuffer cCtx);

    /*
    * Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
    */
    public native byte[] ratchetMessage_getOneTimePublicKey(java.nio.ByteBuffer cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int ratchetMessage_serializeLen(java.nio.ByteBuffer cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] ratchetMessage_serialize(java.nio.ByteBuffer cCtx);

    /*
    * Deserializes instance.
    */
    public native RatchetMessage ratchetMessage_deserialize(byte[] input) throws RatchetException;

    public native java.nio.ByteBuffer ratchetSession_new();

    public native void ratchetSession_close(java.nio.ByteBuffer cCtx);

    /*
    * Random used to generate keys
    */
    public native void ratchetSession_setRng(java.nio.ByteBuffer cCtx, Random rng) throws RatchetException;

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetSession_setupDefaults(java.nio.ByteBuffer cCtx) throws RatchetException;

    /*
    * Initiates session
    */
    public native void ratchetSession_initiate(java.nio.ByteBuffer cCtx, byte[] senderIdentityPrivateKey, byte[] receiverIdentityPublicKey, byte[] receiverLongTermPublicKey, byte[] receiverOneTimePublicKey) throws RatchetException;

    /*
    * Responds to session initiation
    */
    public native void ratchetSession_respond(java.nio.ByteBuffer cCtx, byte[] senderIdentityPublicKey, byte[] receiverIdentityPrivateKey, byte[] receiverLongTermPrivateKey, byte[] receiverOneTimePrivateKey, RatchetMessage message) throws RatchetException;

    /*
    * Returns flag that indicates is this session was initiated or responded
    */
    public native boolean ratchetSession_isInitiator(java.nio.ByteBuffer cCtx);

    /*
    * Returns true if at least 1 response was successfully decrypted, false - otherwise
    */
    public native boolean ratchetSession_receivedFirstResponse(java.nio.ByteBuffer cCtx);

    /*
    * Returns true if receiver had one time public key
    */
    public native boolean ratchetSession_receiverHasOneTimePublicKey(java.nio.ByteBuffer cCtx);

    /*
    * Encrypts data
    */
    public native RatchetMessage ratchetSession_encrypt(java.nio.ByteBuffer cCtx, byte[] plainText) throws RatchetException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int ratchetSession_decryptLen(java.nio.ByteBuffer cCtx, RatchetMessage message);

    /*
    * Decrypts message
    */
    public native byte[] ratchetSession_decrypt(java.nio.ByteBuffer cCtx, RatchetMessage message) throws RatchetException;

    /*
    * Serializes session to buffer
    */
    public native byte[] ratchetSession_serialize(java.nio.ByteBuffer cCtx);

    /*
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    */
    public native RatchetSession ratchetSession_deserialize(byte[] input) throws RatchetException;

    public native java.nio.ByteBuffer ratchetGroupParticipantsInfo_new();

    public native void ratchetGroupParticipantsInfo_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer ratchetGroupParticipantsInfo_new(long size);

    /*
    * Add participant info
    */
    public native void ratchetGroupParticipantsInfo_addParticipant(java.nio.ByteBuffer cCtx, byte[] id, byte[] pubKey) throws RatchetException;

    public native java.nio.ByteBuffer ratchetGroupMessage_new();

    public native void ratchetGroupMessage_close(java.nio.ByteBuffer cCtx);

    /*
    * Returns message type.
    */
    public native GroupMsgType ratchetGroupMessage_getType(java.nio.ByteBuffer cCtx);

    /*
    * Returns session id.
    * This method should be called only for group info type.
    */
    public native byte[] ratchetGroupMessage_getSessionId(java.nio.ByteBuffer cCtx);

    /*
    * Returns message counter in current epoch.
    */
    public native long ratchetGroupMessage_getCounter(java.nio.ByteBuffer cCtx);

    /*
    * Returns message epoch.
    */
    public native long ratchetGroupMessage_getEpoch(java.nio.ByteBuffer cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int ratchetGroupMessage_serializeLen(java.nio.ByteBuffer cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] ratchetGroupMessage_serialize(java.nio.ByteBuffer cCtx);

    /*
    * Deserializes instance.
    */
    public native RatchetGroupMessage ratchetGroupMessage_deserialize(byte[] input) throws RatchetException;

    public native java.nio.ByteBuffer ratchetGroupTicket_new();

    public native void ratchetGroupTicket_close(java.nio.ByteBuffer cCtx);

    /*
    * Random used to generate keys
    */
    public native void ratchetGroupTicket_setRng(java.nio.ByteBuffer cCtx, Random rng);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetGroupTicket_setupDefaults(java.nio.ByteBuffer cCtx) throws RatchetException;

    /*
    * Set this ticket to start new group session.
    */
    public native void ratchetGroupTicket_setupTicketAsNew(java.nio.ByteBuffer cCtx, byte[] sessionId) throws RatchetException;

    /*
    * Returns message that should be sent to all participants using secure channel.
    */
    public native RatchetGroupMessage ratchetGroupTicket_getTicketMessage(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer ratchetGroupParticipantsIds_new();

    public native void ratchetGroupParticipantsIds_close(java.nio.ByteBuffer cCtx);

    public native java.nio.ByteBuffer ratchetGroupParticipantsIds_new(long size);

    /*
    * Add participant id to array
    */
    public native void ratchetGroupParticipantsIds_addId(java.nio.ByteBuffer cCtx, byte[] id);

    public native java.nio.ByteBuffer ratchetGroupSession_new();

    public native void ratchetGroupSession_close(java.nio.ByteBuffer cCtx);

    /*
    * Random
    */
    public native void ratchetGroupSession_setRng(java.nio.ByteBuffer cCtx, Random rng) throws RatchetException;

    /*
    * Shows whether session was initialized.
    */
    public native boolean ratchetGroupSession_isInitialized(java.nio.ByteBuffer cCtx);

    /*
    * Shows whether identity private key was set.
    */
    public native boolean ratchetGroupSession_isPrivateKeySet(java.nio.ByteBuffer cCtx);

    /*
    * Shows whether my id was set.
    */
    public native boolean ratchetGroupSession_isMyIdSet(java.nio.ByteBuffer cCtx);

    /*
    * Returns current epoch.
    */
    public native long ratchetGroupSession_getCurrentEpoch(java.nio.ByteBuffer cCtx);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetGroupSession_setupDefaults(java.nio.ByteBuffer cCtx) throws RatchetException;

    /*
    * Sets identity private key.
    */
    public native void ratchetGroupSession_setPrivateKey(java.nio.ByteBuffer cCtx, byte[] myPrivateKey) throws RatchetException;

    /*
    * Sets my id. Should be 32 byte
    */
    public native void ratchetGroupSession_setMyId(java.nio.ByteBuffer cCtx, byte[] myId);

    /*
    * Returns my id.
    */
    public native byte[] ratchetGroupSession_getMyId(java.nio.ByteBuffer cCtx);

    /*
    * Returns session id.
    */
    public native byte[] ratchetGroupSession_getSessionId(java.nio.ByteBuffer cCtx);

    /*
    * Returns number of participants.
    */
    public native long ratchetGroupSession_getParticipantsCount(java.nio.ByteBuffer cCtx);

    /*
    * Sets up session.
    * Use this method when you have newer epoch message and know all participants info.
    * NOTE: Identity private key and my id should be set separately.
    */
    public native void ratchetGroupSession_setupSessionState(java.nio.ByteBuffer cCtx, RatchetGroupMessage message, RatchetGroupParticipantsInfo participants) throws RatchetException;

    /*
    * Sets up session.
    * Use this method when you have message with next epoch, and you know how participants set was changed.
    * NOTE: Identity private key and my id should be set separately.
    */
    public native void ratchetGroupSession_updateSessionState(java.nio.ByteBuffer cCtx, RatchetGroupMessage message, RatchetGroupParticipantsInfo addParticipants, RatchetGroupParticipantsIds removeParticipants) throws RatchetException;

    /*
    * Encrypts data
    */
    public native RatchetGroupMessage ratchetGroupSession_encrypt(java.nio.ByteBuffer cCtx, byte[] plainText) throws RatchetException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int ratchetGroupSession_decryptLen(java.nio.ByteBuffer cCtx, RatchetGroupMessage message);

    /*
    * Decrypts message
    */
    public native byte[] ratchetGroupSession_decrypt(java.nio.ByteBuffer cCtx, RatchetGroupMessage message, byte[] senderId) throws RatchetException;

    /*
    * Serializes session to buffer
    * NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
    */
    public native byte[] ratchetGroupSession_serialize(java.nio.ByteBuffer cCtx);

    /*
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set.
    * You should set separately:
    * - rng
    * - my private key
    */
    public native RatchetGroupSession ratchetGroupSession_deserialize(byte[] input) throws RatchetException;

    /*
    * Creates ticket with new key for adding or removing participants.
    */
    public native RatchetGroupTicket ratchetGroupSession_createGroupTicket(java.nio.ByteBuffer cCtx) throws RatchetException;
}

