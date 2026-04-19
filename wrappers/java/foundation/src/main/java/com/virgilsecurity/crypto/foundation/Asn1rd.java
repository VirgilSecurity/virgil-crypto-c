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

public class Asn1rd implements AutoCloseable, Asn1Reader {

    public long cCtx;

    public Asn1rd() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.asn1rd_new();
    }

    Asn1rd(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public Asn1rd getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Asn1rd(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.asn1rd_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void reset(byte[] data) {
        FoundationJNI.INSTANCE.asn1rd_reset(this.cCtx, data);
    }

    public int leftLen() {
        return FoundationJNI.INSTANCE.asn1rd_leftLen(this.cCtx);
    }

    public boolean hasError() {
        return FoundationJNI.INSTANCE.asn1rd_hasError(this.cCtx);
    }

    public void status() throws FoundationException {
        FoundationJNI.INSTANCE.asn1rd_status(this.cCtx);
    }

    public int getTag() {
        return FoundationJNI.INSTANCE.asn1rd_getTag(this.cCtx);
    }

    public int getLen() {
        return FoundationJNI.INSTANCE.asn1rd_getLen(this.cCtx);
    }

    public int getDataLen() {
        return FoundationJNI.INSTANCE.asn1rd_getDataLen(this.cCtx);
    }

    public int readTag(int tag) {
        return FoundationJNI.INSTANCE.asn1rd_readTag(this.cCtx, tag);
    }

    public int readContextTag(int tag) {
        return FoundationJNI.INSTANCE.asn1rd_readContextTag(this.cCtx, tag);
    }

    public int readInt() {
        return FoundationJNI.INSTANCE.asn1rd_readInt(this.cCtx);
    }

    public byte readInt8() {
        return FoundationJNI.INSTANCE.asn1rd_readInt8(this.cCtx);
    }

    public short readInt16() {
        return FoundationJNI.INSTANCE.asn1rd_readInt16(this.cCtx);
    }

    public int readInt32() {
        return FoundationJNI.INSTANCE.asn1rd_readInt32(this.cCtx);
    }

    public long readInt64() {
        return FoundationJNI.INSTANCE.asn1rd_readInt64(this.cCtx);
    }

    public int readUint() {
        return FoundationJNI.INSTANCE.asn1rd_readUint(this.cCtx);
    }

    public int readUint8() {
        return FoundationJNI.INSTANCE.asn1rd_readUint8(this.cCtx);
    }

    public int readUint16() {
        return FoundationJNI.INSTANCE.asn1rd_readUint16(this.cCtx);
    }

    public int readUint32() {
        return FoundationJNI.INSTANCE.asn1rd_readUint32(this.cCtx);
    }

    public long readUint64() {
        return FoundationJNI.INSTANCE.asn1rd_readUint64(this.cCtx);
    }

    public boolean readBool() {
        return FoundationJNI.INSTANCE.asn1rd_readBool(this.cCtx);
    }

    public void readNull() {
        FoundationJNI.INSTANCE.asn1rd_readNull(this.cCtx);
    }

    public void readNullOptional() {
        FoundationJNI.INSTANCE.asn1rd_readNullOptional(this.cCtx);
    }

    public byte[] readOctetStr() {
        return FoundationJNI.INSTANCE.asn1rd_readOctetStr(this.cCtx);
    }

    public byte[] readBitstringAsOctetStr() {
        return FoundationJNI.INSTANCE.asn1rd_readBitstringAsOctetStr(this.cCtx);
    }

    public byte[] readUtf8Str() {
        return FoundationJNI.INSTANCE.asn1rd_readUtf8Str(this.cCtx);
    }

    public byte[] readOid() {
        return FoundationJNI.INSTANCE.asn1rd_readOid(this.cCtx);
    }

    public byte[] readData(int len) {
        return FoundationJNI.INSTANCE.asn1rd_readData(this.cCtx, len);
    }

    public int readSequence() {
        return FoundationJNI.INSTANCE.asn1rd_readSequence(this.cCtx);
    }

    public int readSet() {
        return FoundationJNI.INSTANCE.asn1rd_readSet(this.cCtx);
    }

}
