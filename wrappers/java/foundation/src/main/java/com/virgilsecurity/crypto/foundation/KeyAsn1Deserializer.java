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

public class KeyAsn1Deserializer implements AutoCloseable, KeyDeserializer {

    public long cCtx;

    public KeyAsn1Deserializer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyAsn1Deserializer_new();
    }

    package KeyAsn1Deserializer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public KeyAsn1Deserializer getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyAsn1Deserializer(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.keyAsn1Deserializer_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setAsn1Reader(Asn1Reader asn1Reader) {
        FoundationJNI.INSTANCE.keyAsn1Deserializer_setAsn1Reader(this.cCtx, asn1Reader);
    }

    public RawPublicKey deserializePublicKey(byte[] publicKeyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializePublicKey(this.cCtx, publicKeyData);
    }

    public RawPrivateKey deserializePrivateKey(byte[] privateKeyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializePrivateKey(this.cCtx, privateKeyData);
    }

    public void setupDefaults() {
        FoundationJNI.INSTANCE.keyAsn1Deserializer_setupDefaults(this.cCtx);
    }

    public RawPublicKey deserializePublicKeyInplace() throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializePublicKeyInplace(this.cCtx);
    }

    public RawPrivateKey deserializePrivateKeyInplace() throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializePrivateKeyInplace(this.cCtx);
    }

    public RawPrivateKey deserializePkcs8PrivateKeyInplace(int seqLeftLen, int version) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializePkcs8PrivateKeyInplace(this.cCtx, seqLeftLen, version);
    }

    public RawPrivateKey deserializeSec1PrivateKeyInplace(int seqLeftLen, int version, AlgInfo algInfo) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAsn1Deserializer_deserializeSec1PrivateKeyInplace(this.cCtx, seqLeftLen, version, algInfo);
    }

}
