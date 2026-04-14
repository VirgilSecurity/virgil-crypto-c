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

public class AlgInfoDerDeserializer implements AutoCloseable, AlgInfoDeserializer {

    public long cCtx;

    public AlgInfoDerDeserializer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.algInfoDerDeserializer_new();
    }

    AlgInfoDerDeserializer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public AlgInfoDerDeserializer getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new AlgInfoDerDeserializer(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.algInfoDerDeserializer_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setAsn1Reader(Asn1Reader asn1Reader) {
        FoundationJNI.INSTANCE.algInfoDerDeserializer_setAsn1Reader(this.cCtx, asn1Reader);
    }

    public AlgInfo deserialize(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserialize(this.cCtx, data);
    }

    public void setupDefaults() {
        FoundationJNI.INSTANCE.algInfoDerDeserializer_setupDefaults(this.cCtx);
    }

    public AlgInfo deserializeSimpleAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeSimpleAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeKdfAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeKdfAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeHkdfAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeHkdfAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeHmacAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeHmacAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeCipherAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeCipherAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializePbkdf2AlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializePbkdf2AlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializePbes2AlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializePbes2AlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeEccAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeEccAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeCompoundKeyAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeCompoundKeyAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeHybridKeyAlgInfo(OidId oidId) throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeHybridKeyAlgInfo(this.cCtx, oidId);
    }

    public AlgInfo deserializeInplace() throws FoundationException {
        return FoundationJNI.INSTANCE.algInfoDerDeserializer_deserializeInplace(this.cCtx);
    }

}
