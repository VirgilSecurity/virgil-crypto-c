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

public class KeyInfo implements AutoCloseable {

    public long cCtx;

    public KeyInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyInfo_new();
    }

    public KeyInfo(AlgInfo algInfo) {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyInfo_new(algInfo);
    }

    KeyInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public KeyInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyInfo(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.keyInfo_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public boolean isCompound() {
        return FoundationJNI.INSTANCE.keyInfo_isCompound(this.cCtx);
    }

    public boolean isHybrid() {
        return FoundationJNI.INSTANCE.keyInfo_isHybrid(this.cCtx);
    }

    public boolean isCompoundHybrid() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybrid(this.cCtx);
    }

    public boolean isCompoundHybridCipher() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybridCipher(this.cCtx);
    }

    public boolean isCompoundHybridSigner() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybridSigner(this.cCtx);
    }

    public boolean isHybridPostQuantum() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantum(this.cCtx);
    }

    public boolean isHybridPostQuantumCipher() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantumCipher(this.cCtx);
    }

    public boolean isHybridPostQuantumSigner() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantumSigner(this.cCtx);
    }

    public AlgId algId() {
        return FoundationJNI.INSTANCE.keyInfo_algId(this.cCtx);
    }

    public AlgId compoundCipherAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundCipherAlgId(this.cCtx);
    }

    public AlgId compoundSignerAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundSignerAlgId(this.cCtx);
    }

    public AlgId hybridFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_hybridFirstKeyAlgId(this.cCtx);
    }

    public AlgId hybridSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_hybridSecondKeyAlgId(this.cCtx);
    }

    public AlgId compoundHybridCipherFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridCipherFirstKeyAlgId(this.cCtx);
    }

    public AlgId compoundHybridCipherSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridCipherSecondKeyAlgId(this.cCtx);
    }

    public AlgId compoundHybridSignerFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridSignerFirstKeyAlgId(this.cCtx);
    }

    public AlgId compoundHybridSignerSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridSignerSecondKeyAlgId(this.cCtx);
    }

}
