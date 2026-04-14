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

public class MessageInfoCustomParams implements AutoCloseable {

    public long cCtx;

    public MessageInfoCustomParams() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoCustomParams_new();
    }

    MessageInfoCustomParams(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public MessageInfoCustomParams getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoCustomParams(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfoCustomParams_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public int getOfIntType() {
        return 1;
    }

    public int getOfStringType() {
        return 2;
    }

    public int getOfDataType() {
        return 3;
    }

    public void addInt(byte[] key, int value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addInt(this.cCtx, key, value);
    }

    public void addString(byte[] key, byte[] value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addString(this.cCtx, key, value);
    }

    public void addData(byte[] key, byte[] value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addData(this.cCtx, key, value);
    }

    public void clear() {
        FoundationJNI.INSTANCE.messageInfoCustomParams_clear(this.cCtx);
    }

    public int findInt(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findInt(this.cCtx, key);
    }

    public byte[] findString(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findString(this.cCtx, key);
    }

    public byte[] findData(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findData(this.cCtx, key);
    }

    public boolean hasParams() {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_hasParams(this.cCtx);
    }

}
