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

public class MessageInfoFooter implements AutoCloseable {

    public long cCtx;

    public MessageInfoFooter() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoFooter_new();
    }

    package MessageInfoFooter(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public MessageInfoFooter getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoFooter(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfoFooter_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public boolean hasSignerInfos() {
        return FoundationJNI.INSTANCE.messageInfoFooter_hasSignerInfos(this.cCtx);
    }

    public SignerInfoList signerInfos() {
        return FoundationJNI.INSTANCE.messageInfoFooter_signerInfos(this.cCtx);
    }

    public AlgInfo signerHashAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfoFooter_signerHashAlgInfo(this.cCtx);
    }

    public byte[] signerDigest() {
        return FoundationJNI.INSTANCE.messageInfoFooter_signerDigest(this.cCtx);
    }

}
