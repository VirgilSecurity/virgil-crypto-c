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

    public native long ratchetKeyId_new();

    public native void ratchetKeyId_close(long cCtx);

    /*
    * Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key
    */
    public native byte[] ratchetKeyId_computePublicKeyId(long cCtx, byte[] publicKey) throws RatchetException;

    public native long ratchetMessage_new();

    public native void ratchetMessage_close(long cCtx);

    /*
    * Returns message type.
    */
    public native MsgType ratchetMessage_getType(long cCtx);

    /*
    * Returns message counter in current asymmetric ratchet round.
    */
    public native long ratchetMessage_getCounter(long cCtx);

    /*
    * Returns long-term public key, if message is prekey message.
    */
    public native byte[] ratchetMessage_getLongTermPublicKey(long cCtx);

    /*
    * Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
    */
    public native byte[] ratchetMessage_getOneTimePublicKey(long cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int ratchetMessage_serializeLen(long cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] ratchetMessage_serialize(long cCtx);

    /*
    * Deserializes instance.
    */
    public native RatchetMessage ratchetMessage_deserialize(byte[] input) throws RatchetException;

    public native long ratchetSession_new();

    public native void ratchetSession_close(long cCtx);

    /*
    * Random used to generate keys
    */
    public native void ratchetSession_setRng(long cCtx, Random rng) throws RatchetException;

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetSession_setupDefaults(long cCtx) throws RatchetException;

    /*
    * Initiates session
    */
    public native void ratchetSession_initiate(long cCtx, byte[] senderIdentityPrivateKey, byte[] receiverIdentityPublicKey, byte[] receiverLongTermPublicKey, byte[] receiverOneTimePublicKey) throws RatchetException;

    /*
    * Responds to session initiation
    */
    public native void ratchetSession_respond(long cCtx, byte[] senderIdentityPublicKey, byte[] receiverIdentityPrivateKey, byte[] receiverLongTermPrivateKey, byte[] receiverOneTimePrivateKey, RatchetMessage message) throws RatchetException;

    /*
    * Returns flag that indicates is this session was initiated or responded
    */
    public native boolean ratchetSession_isInitiator(long cCtx);

    /*
    * Returns true if at least 1 response was successfully decrypted, false - otherwise
    */
    public native boolean ratchetSession_receivedFirstResponse(long cCtx);

    /*
    * Returns true if receiver had one time public key
    */
    public native boolean ratchetSession_receiverHasOneTimePublicKey(long cCtx);

    /*
    * Encrypts data
    */
    public native RatchetMessage ratchetSession_encrypt(long cCtx, byte[] plainText) throws RatchetException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int ratchetSession_decryptLen(long cCtx, RatchetMessage message);

    /*
    * Decrypts message
    */
    public native byte[] ratchetSession_decrypt(long cCtx, RatchetMessage message) throws RatchetException;

    /*
    * Serializes session to buffer
    */
    public native byte[] ratchetSession_serialize(long cCtx);

    /*
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    */
    public native RatchetSession ratchetSession_deserialize(byte[] input) throws RatchetException;

    public native long ratchetGroupParticipantsInfo_new();

    public native void ratchetGroupParticipantsInfo_close(long cCtx);

    public native long ratchetGroupParticipantsInfo_new(long size);

    /*
    * Add participant info
    */
    public native void ratchetGroupParticipantsInfo_addParticipant(long cCtx, byte[] id, byte[] pubKey) throws RatchetException;

    public native long ratchetGroupMessage_new();

    public native void ratchetGroupMessage_close(long cCtx);

    /*
    * Returns message type.
    */
    public native GroupMsgType ratchetGroupMessage_getType(long cCtx);

    /*
    * Returns session id.
    * This method should be called only for group info type.
    */
    public native byte[] ratchetGroupMessage_getSessionId(long cCtx);

    /*
    * Returns message sender id.
    * This method should be called only for regular message type.
    */
    public native byte[] ratchetGroupMessage_getSenderId(long cCtx);

    /*
    * Returns message counter in current epoch.
    */
    public native long ratchetGroupMessage_getCounter(long cCtx);

    /*
    * Returns message epoch.
    */
    public native long ratchetGroupMessage_getEpoch(long cCtx);

    /*
    * Buffer len to serialize this class.
    */
    public native int ratchetGroupMessage_serializeLen(long cCtx);

    /*
    * Serializes instance.
    */
    public native byte[] ratchetGroupMessage_serialize(long cCtx);

    /*
    * Deserializes instance.
    */
    public native RatchetGroupMessage ratchetGroupMessage_deserialize(byte[] input) throws RatchetException;

    public native long ratchetGroupTicket_new();

    public native void ratchetGroupTicket_close(long cCtx);

    /*
    * Random used to generate keys
    */
    public native void ratchetGroupTicket_setRng(long cCtx, Random rng);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetGroupTicket_setupDefaults(long cCtx) throws RatchetException;

    /*
    * Set this ticket to start new group session.
    */
    public native void ratchetGroupTicket_setupTicketAsNew(long cCtx) throws RatchetException;

    /*
    * Set session id in case you want to use your own identifier, otherwise - id will be generated for you.
    */
    public native void ratchetGroupTicket_setSessionId(long cCtx, byte[] sessionId);

    /*
    * Returns message that should be sent to all participants using secure channel.
    */
    public native RatchetGroupMessage ratchetGroupTicket_getTicketMessage(long cCtx);

    public native long ratchetGroupParticipantsIds_new();

    public native void ratchetGroupParticipantsIds_close(long cCtx);

    public native long ratchetGroupParticipantsIds_new(long size);

    /*
    * Add participant id to array
    */
    public native void ratchetGroupParticipantsIds_addId(long cCtx, byte[] id);

    public native long ratchetGroupSession_new();

    public native void ratchetGroupSession_close(long cCtx);

    /*
    * Random
    */
    public native void ratchetGroupSession_setRng(long cCtx, Random rng) throws RatchetException;

    /*
    * Shows whether session was initialized.
    */
    public native boolean ratchetGroupSession_isInitialized(long cCtx);

    /*
    * Shows whether identity private key was set.
    */
    public native boolean ratchetGroupSession_isPrivateKeySet(long cCtx);

    /*
    * Shows whether my id was set.
    */
    public native boolean ratchetGroupSession_isMyIdSet(long cCtx);

    /*
    * Returns current epoch.
    */
    public native long ratchetGroupSession_getCurrentEpoch(long cCtx);

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public native void ratchetGroupSession_setupDefaults(long cCtx) throws RatchetException;

    /*
    * Sets identity private key.
    */
    public native void ratchetGroupSession_setPrivateKey(long cCtx, byte[] myPrivateKey) throws RatchetException;

    /*
    * Sets my id. Should be 32 byte
    */
    public native void ratchetGroupSession_setMyId(long cCtx, byte[] myId);

    /*
    * Returns my id.
    */
    public native byte[] ratchetGroupSession_getMyId(long cCtx);

    /*
    * Returns session id.
    */
    public native byte[] ratchetGroupSession_getSessionId(long cCtx);

    /*
    * Returns number of participants.
    */
    public native long ratchetGroupSession_getParticipantsCount(long cCtx);

    /*
    * Sets up session.
    * Use this method when you have newer epoch message and know all participants info.
    * NOTE: Identity private key and my id should be set separately.
    */
    public native void ratchetGroupSession_setupSessionState(long cCtx, RatchetGroupMessage message, RatchetGroupParticipantsInfo participants) throws RatchetException;

    /*
    * Sets up session.
    * Use this method when you have message with next epoch, and you know how participants set was changed.
    * NOTE: Identity private key and my id should be set separately.
    */
    public native void ratchetGroupSession_updateSessionState(long cCtx, RatchetGroupMessage message, RatchetGroupParticipantsInfo addParticipants, RatchetGroupParticipantsIds removeParticipants) throws RatchetException;

    /*
    * Encrypts data
    */
    public native RatchetGroupMessage ratchetGroupSession_encrypt(long cCtx, byte[] plainText) throws RatchetException;

    /*
    * Calculates size of buffer sufficient to store decrypted message
    */
    public native int ratchetGroupSession_decryptLen(long cCtx, RatchetGroupMessage message);

    /*
    * Decrypts message
    */
    public native byte[] ratchetGroupSession_decrypt(long cCtx, RatchetGroupMessage message) throws RatchetException;

    /*
    * Serializes session to buffer
    * NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
    */
    public native byte[] ratchetGroupSession_serialize(long cCtx);

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
    public native RatchetGroupTicket ratchetGroupSession_createGroupTicket(long cCtx) throws RatchetException;
}

