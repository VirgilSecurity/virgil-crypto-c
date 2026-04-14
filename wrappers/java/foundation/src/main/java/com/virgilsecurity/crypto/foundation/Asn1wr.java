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

public class Asn1wr implements AutoCloseable, Asn1Writer {

    public long cCtx;

    public Asn1wr() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.asn1wr_new();
    }

    Asn1wr(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public Asn1wr getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Asn1wr(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.asn1wr_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void reset(byte[] out, int outLen) {
        FoundationJNI.INSTANCE.asn1wr_reset(this.cCtx, out, outLen);
    }

    public int finish(boolean doNotAdjust) {
        return FoundationJNI.INSTANCE.asn1wr_finish(this.cCtx, doNotAdjust);
    }

    public byte bytes() {
        return FoundationJNI.INSTANCE.asn1wr_bytes(this.cCtx);
    }

    public int len() {
        return FoundationJNI.INSTANCE.asn1wr_len(this.cCtx);
    }

    public int writtenLen() {
        return FoundationJNI.INSTANCE.asn1wr_writtenLen(this.cCtx);
    }

    public int unwrittenLen() {
        return FoundationJNI.INSTANCE.asn1wr_unwrittenLen(this.cCtx);
    }

    public boolean hasError() {
        return FoundationJNI.INSTANCE.asn1wr_hasError(this.cCtx);
    }

    public void status() throws FoundationException {
        FoundationJNI.INSTANCE.asn1wr_status(this.cCtx);
    }

    public byte reserve(int len) {
        return FoundationJNI.INSTANCE.asn1wr_reserve(this.cCtx, len);
    }

    public int writeTag(int tag) {
        return FoundationJNI.INSTANCE.asn1wr_writeTag(this.cCtx, tag);
    }

    public int writeContextTag(int tag, int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeContextTag(this.cCtx, tag, len);
    }

    public int writeLen(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeLen(this.cCtx, len);
    }

    public int writeInt(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt(this.cCtx, value);
    }

    public int writeInt8(byte value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt8(this.cCtx, value);
    }

    public int writeInt16(short value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt16(this.cCtx, value);
    }

    public int writeInt32(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt32(this.cCtx, value);
    }

    public int writeInt64(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt64(this.cCtx, value);
    }

    public int writeUint(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint(this.cCtx, value);
    }

    public int writeUint8(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint8(this.cCtx, value);
    }

    public int writeUint16(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint16(this.cCtx, value);
    }

    public int writeUint32(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint32(this.cCtx, value);
    }

    public int writeUint64(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint64(this.cCtx, value);
    }

    public int writeBool(boolean value) {
        return FoundationJNI.INSTANCE.asn1wr_writeBool(this.cCtx, value);
    }

    public int writeNull() {
        return FoundationJNI.INSTANCE.asn1wr_writeNull(this.cCtx);
    }

    public int writeOctetStr(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStr(this.cCtx, value);
    }

    public int writeOctetStrAsBitstring(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStrAsBitstring(this.cCtx, value);
    }

    public int writeData(byte[] data) {
        return FoundationJNI.INSTANCE.asn1wr_writeData(this.cCtx, data);
    }

    public int writeUtf8Str(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUtf8Str(this.cCtx, value);
    }

    public int writeOid(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOid(this.cCtx, value);
    }

    public int writeSequence(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSequence(this.cCtx, len);
    }

    public int writeSet(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSet(this.cCtx, len);
    }

    public boolean mbedtlsHasError(int code) {
        return FoundationJNI.INSTANCE.asn1wr_mbedtlsHasError(this.cCtx, code);
    }

    public int writeTagData(byte[] data, int tag) {
        return FoundationJNI.INSTANCE.asn1wr_writeTagData(this.cCtx, data, tag);
    }

    public int getCurrentElementLen(byte curr, byte end) {
        return FoundationJNI.INSTANCE.asn1wr_getCurrentElementLen(curr, end);
    }

    public void swapElementsOfSet(byte toStart, int toLen, byte fromStart, int fromLen) {
        FoundationJNI.INSTANCE.asn1wr_swapElementsOfSet(toStart, toLen, fromStart, fromLen);
    }

    public boolean secondElementOfSetIsLess(byte firstStart, int firstLen, byte secondStart, int secondLen) {
        return FoundationJNI.INSTANCE.asn1wr_secondElementOfSetIsLess(firstStart, firstLen, secondStart, secondLen);
    }

    public void sortElementsOfSet(int len) {
        FoundationJNI.INSTANCE.asn1wr_sortElementsOfSet(this.cCtx, len);
    }

}
