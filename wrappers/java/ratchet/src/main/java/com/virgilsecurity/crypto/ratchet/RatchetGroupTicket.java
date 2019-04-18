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
* Group ticket used to start group session.
*/
public class RatchetGroupTicket implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public RatchetGroupTicket() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetGroupTicket_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public RatchetGroupTicket(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        RatchetJNI.INSTANCE.ratchetGroupTicket_close(this.cCtx);
    }

    /*
    * Random used to generate keys
    */
    public void setRng(Random rng) {
        RatchetJNI.INSTANCE.ratchetGroupTicket_setRng(this.cCtx, rng);
    }

    /*
    * Setups default dependencies:
    * - RNG: CTR DRBG
    */
    public void setupDefaults() throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupTicket_setupDefaults(this.cCtx);
    }

    public void setupTicketAsNew() throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupTicket_setupTicketAsNew(this.cCtx);
    }

    /*
    * Adds participant to chat.
    */
    public void addNewParticipant(byte[] participantId, byte[] publicKey) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupTicket_addNewParticipant(this.cCtx, participantId, publicKey);
    }

    /*
    * Remove participant from chat.
    */
    public void removeParticipant(byte[] participantId) throws RatchetException {
        RatchetJNI.INSTANCE.ratchetGroupTicket_removeParticipant(this.cCtx, participantId);
    }

    /*
    * Generates message that should be sent to all participants using secure channel.
    */
    public RatchetGroupMessage getComplementaryTicketMessage() {
        return RatchetJNI.INSTANCE.ratchetGroupTicket_getComplementaryTicketMessage(this.cCtx);
    }

    /*
    * Generates message that should be sent to all participants using secure channel.
    */
    public RatchetGroupMessage getFullTicketMessage() {
        return RatchetJNI.INSTANCE.ratchetGroupTicket_getFullTicketMessage(this.cCtx);
    }
}

