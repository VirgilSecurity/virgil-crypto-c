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

public class GroupSessionMessage implements AutoCloseable {

    public long cCtx;

    public GroupSessionMessage() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.groupSessionMessage_new();
    }

    package GroupSessionMessage(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public GroupSessionMessage getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new GroupSessionMessage(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.groupSessionMessage_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public int getMaxMessageLen() {
        return 30188;
    }

    public int getMessageVersion() {
        return 1;
    }

    public GroupMsgType getType() {
        return FoundationJNI.INSTANCE.groupSessionMessage_getType(this.cCtx);
    }

    public byte[] getSessionId() {
        return FoundationJNI.INSTANCE.groupSessionMessage_getSessionId(this.cCtx);
    }

    public int getEpoch() {
        return FoundationJNI.INSTANCE.groupSessionMessage_getEpoch(this.cCtx);
    }

    public int serializeLen() {
        return FoundationJNI.INSTANCE.groupSessionMessage_serializeLen(this.cCtx);
    }

    public byte[] serialize() {
        return FoundationJNI.INSTANCE.groupSessionMessage_serialize(this.cCtx);
    }

    public Self deserialize(byte[] input) throws FoundationException {
        return FoundationJNI.INSTANCE.groupSessionMessage_deserialize(input);
    }

}
