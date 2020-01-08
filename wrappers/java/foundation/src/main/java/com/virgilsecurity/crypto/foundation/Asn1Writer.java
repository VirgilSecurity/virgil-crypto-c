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
* Provides interface to the ASN.1 writer.
* Note, elements are written starting from the buffer ending.
* Note, that all "write" methods move writing position backward.
*/
public interface Asn1Writer {

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
    */
    void reset(byte[] out, int outLen);

    /*
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    */
    int finish(boolean doNotAdjust);

    /*
    * Returns pointer to the inner buffer.
    */
    byte bytes();

    /*
    * Returns total inner buffer length.
    */
    int len();

    /*
    * Returns how many bytes were already written to the ASN.1 structure.
    */
    int writtenLen();

    /*
    * Returns how many bytes are available for writing.
    */
    int unwrittenLen();

    /*
    * Return true if status is not "success".
    */
    boolean hasError();

    /*
    * Return error code.
    */
    void status() throws FoundationException;

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
    */
    byte reserve(int len);

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
    */
    int writeTag(int tag);

    /*
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    */
    int writeContextTag(int tag, int len);

    /*
    * Write length of the following data.
    * Return count of written bytes.
    */
    int writeLen(int len);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeInt(int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeInt8(byte value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeInt16(short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeInt32(int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeInt64(long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeUint(long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeUint8(short value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeUint16(int value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeUint32(long value);

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    int writeUint64(long value);

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    */
    int writeBool(boolean value);

    /*
    * Write ASN.1 type: NULL.
    */
    int writeNull();

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    */
    int writeOctetStr(byte[] value);

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    */
    int writeOctetStrAsBitstring(byte[] value);

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    */
    int writeData(byte[] data);

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    */
    int writeUtf8Str(byte[] value);

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    */
    int writeOid(byte[] value);

    /*
    * Mark previously written data of given length as ASN.1 type: SEQUENCE.
    * Return count of written bytes.
    */
    int writeSequence(int len);

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    int writeSet(int len);
}

