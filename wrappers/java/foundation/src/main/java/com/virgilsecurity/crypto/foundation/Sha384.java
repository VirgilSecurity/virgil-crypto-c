/*
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

public class Sha384 implements AutoCloseable, Alg, Hash {

    public long cCtx;

    public Sha384() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.sha384_new();
    }

    Sha384(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static Sha384 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Sha384(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.sha384_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public int getDigestLen() {
        return 48;
    }

    public int getBlockLen() {
        return 128;
    }

    public AlgId algId() {
        return FoundationJNI.INSTANCE.sha384_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.sha384_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.sha384_restoreAlgInfo(this.cCtx, algInfo);
    }

    public byte[] hash(byte[] data) {
        return FoundationJNI.INSTANCE.sha384_hash(data);
    }

    public void start() {
        FoundationJNI.INSTANCE.sha384_start(this.cCtx);
    }

    public void update(byte[] data) {
        FoundationJNI.INSTANCE.sha384_update(this.cCtx, data);
    }

    public byte[] finish() {
        return FoundationJNI.INSTANCE.sha384_finish(this.cCtx);
    }

}
