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

public class KeyProvider implements AutoCloseable {

    public long cCtx;

    public KeyProvider() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyProvider_new();
    }

    package KeyProvider(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public KeyProvider getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyProvider(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.keyProvider_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.keyProvider_setRandom(this.cCtx, random);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.keyProvider_setupDefaults(this.cCtx);
    }

    public void setRsaParams(int bitlen) {
        FoundationJNI.INSTANCE.keyProvider_setRsaParams(this.cCtx, bitlen);
    }

    public PrivateKey generatePrivateKey(AlgId algId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generatePrivateKey(this.cCtx, algId);
    }

    public PrivateKey generatePostQuantumPrivateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generatePostQuantumPrivateKey(this.cCtx);
    }

    public PrivateKey generateCompoundPrivateKey(AlgId cipherAlgId, AlgId signerAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateCompoundPrivateKey(this.cCtx, cipherAlgId, signerAlgId);
    }

    public PrivateKey generateHybridPrivateKey(AlgId firstKeyAlgId, AlgId secondKeyAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateHybridPrivateKey(this.cCtx, firstKeyAlgId, secondKeyAlgId);
    }

    public PrivateKey generateCompoundHybridPrivateKey(AlgId cipherFirstKeyAlgId, AlgId cipherSecondKeyAlgId, AlgId signerFirstKeyAlgId, AlgId signerSecondKeyAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateCompoundHybridPrivateKey(this.cCtx, cipherFirstKeyAlgId, cipherSecondKeyAlgId, signerFirstKeyAlgId, signerSecondKeyAlgId);
    }

    public PrivateKey importPrivateKey(byte[] keyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPrivateKey(this.cCtx, keyData);
    }

    public PublicKey importPublicKey(byte[] keyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPublicKey(this.cCtx, keyData);
    }

    public int exportedPublicKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.keyProvider_exportedPublicKeyLen(this.cCtx, publicKey);
    }

    public byte[] exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_exportPublicKey(this.cCtx, publicKey);
    }

    public int exportedPrivateKeyLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.keyProvider_exportedPrivateKeyLen(this.cCtx, privateKey);
    }

    public byte[] exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_exportPrivateKey(this.cCtx, privateKey);
    }

}
