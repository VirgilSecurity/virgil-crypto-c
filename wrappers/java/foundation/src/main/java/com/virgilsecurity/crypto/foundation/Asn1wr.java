/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
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
* This is MbedTLS implementation of ASN.1 writer.
*/
public class Asn1wr implements AutoCloseable, Asn1Writer {

    public long cCtx;

    /* Create underlying C context. */
    public Asn1wr() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.asn1wr_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public Asn1wr(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.asn1wr_close(this.cCtx);
    }

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
    */
    public void reset(byte[] out, int outLen) {
        FoundationJNI.INSTANCE.asn1wr_reset(this.cCtx, out, outLen);
    }

    /*
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    */
    public int finish(boolean doNotAdjust) {
        return FoundationJNI.INSTANCE.asn1wr_finish(this.cCtx, doNotAdjust);
    }

    /*
    * Returns pointer to the inner buffer.
    */
    public byte bytes() {
        return FoundationJNI.INSTANCE.asn1wr_bytes(this.cCtx);
    }

    /*
    * Returns total inner buffer length.
    */
    public int len() {
        return FoundationJNI.INSTANCE.asn1wr_len(this.cCtx);
    }

    /*
    * Returns how many bytes were already written to the ASN.1 structure.
    */
    public int writtenLen() {
        return FoundationJNI.INSTANCE.asn1wr_writtenLen(this.cCtx);
    }

    /*
    * Returns how many bytes are available for writing.
    */
    public int unwrittenLen() {
        return FoundationJNI.INSTANCE.asn1wr_unwrittenLen(this.cCtx);
    }

    /*
    * Return true if status is not "success".
    */
    public boolean hasError() {
        return FoundationJNI.INSTANCE.asn1wr_hasError(this.cCtx);
    }

    /*
    * Return error code.
    */
    public void status() throws FoundationException {
        FoundationJNI.INSTANCE.asn1wr_status(this.cCtx);
    }

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
    */
    public byte reserve(int len) {
        return FoundationJNI.INSTANCE.asn1wr_reserve(this.cCtx, len);
    }

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
    */
    public int writeTag(int tag) {
        return FoundationJNI.INSTANCE.asn1wr_writeTag(this.cCtx, tag);
    }

    /*
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    */
    public int writeContextTag(int tag, int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeContextTag(this.cCtx, tag, len);
    }

    /*
    * Write length of the following data.
    * Return count of written bytes.
    */
    public int writeLen(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeLen(this.cCtx, len);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeInt(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeInt8(byte value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt8(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeInt16(short value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt16(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeInt32(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt32(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeInt64(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt64(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeUint(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeUint8(short value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint8(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeUint16(int value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint16(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeUint32(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint32(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    public int writeUint64(long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint64(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    */
    public int writeBool(boolean value) {
        return FoundationJNI.INSTANCE.asn1wr_writeBool(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: NULL.
    */
    public int writeNull() {
        return FoundationJNI.INSTANCE.asn1wr_writeNull(this.cCtx);
    }

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    */
    public int writeOctetStr(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStr(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    */
    public int writeOctetStrAsBitstring(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStrAsBitstring(this.cCtx, value);
    }

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    */
    public int writeData(byte[] data) {
        return FoundationJNI.INSTANCE.asn1wr_writeData(this.cCtx, data);
    }

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    */
    public int writeUtf8Str(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUtf8Str(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    */
    public int writeOid(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOid(this.cCtx, value);
    }

    /*
    * Mark previously written data of given length as ASN.1 type: SQUENCE.
    * Return count of written bytes.
    */
    public int writeSequence(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSequence(this.cCtx, len);
    }

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    public int writeSet(int len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSet(this.cCtx, len);
    }
}

