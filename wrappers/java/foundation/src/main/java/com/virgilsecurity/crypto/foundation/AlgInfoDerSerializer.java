/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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

/*
* Provide DER serializer of algorithm information.
*/
public class AlgInfoDerSerializer implements AutoCloseable, AlgInfoSerializer {

    public long cCtx;

    /* Create underlying C context. */
    public AlgInfoDerSerializer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.algInfoDerSerializer_new();
    }

    /* Wrap underlying C context. */
    AlgInfoDerSerializer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setAsn1Writer(Asn1Writer asn1Writer) {
        FoundationJNI.INSTANCE.algInfoDerSerializer_setAsn1Writer(this.cCtx, asn1Writer);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() {
        FoundationJNI.INSTANCE.algInfoDerSerializer_setupDefaults(this.cCtx);
    }

    /*
    * Serialize by using internal ASN.1 writer.
    * Note, that caller code is responsible to reset ASN.1 writer with
    * an output buffer.
    */
    public int serializeInplace(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algInfoDerSerializer_serializeInplace(this.cCtx, algInfo);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static AlgInfoDerSerializer getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new AlgInfoDerSerializer(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.algInfoDerSerializer_close(this.cCtx);
    }

    /*
    * Return buffer size enough to hold serialized algorithm.
    */
    public int serializedLen(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algInfoDerSerializer_serializedLen(this.cCtx, algInfo);
    }

    /*
    * Serialize algorithm info to buffer class.
    */
    public byte[] serialize(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algInfoDerSerializer_serialize(this.cCtx, algInfo);
    }
}

