<?php
/**
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

namespace Virgil\CryptoWrapper\Foundation;

/**
* Provides interface to the ASN.1 writer.
* Note, elements are written starting from the buffer ending.
* Note, that all "write" methods move writing position backward.
*/
interface Asn1Writer extends Ctx
{

    /**
    * Reset all internal states and prepare to new ASN.1 writing operations.
    *
    * @param int $out
    * @param int $outLen
    * @return void
    */
    public function reset(int $out, int $outLen): void;

    /**
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    *
    * @param bool $doNotAdjust
    * @return int
    */
    public function finish(bool $doNotAdjust): int;

    /**
    * Returns pointer to the inner buffer.
    *
    * @return string
    */
    public function bytes(): string;

    /**
    * Returns total inner buffer length.
    *
    * @return int
    */
    public function len(): int;

    /**
    * Returns how many bytes were already written to the ASN.1 structure.
    *
    * @return int
    */
    public function writtenLen(): int;

    /**
    * Returns how many bytes are available for writing.
    *
    * @return int
    */
    public function unwrittenLen(): int;

    /**
    * Return true if status is not "success".
    *
    * @return bool
    */
    public function hasError(): bool;

    /**
    * Return error code.
    *
    * @return void
    * @throws \Exception
    */
    public function status(): void;

    /**
    * Move writing position backward for the given length.
    * Return current writing position.
    *
    * @param int $len
    * @return string
    */
    public function reserve(int $len): string;

    /**
    * Write ASN.1 tag.
    * Return count of written bytes.
    *
    * @param int $tag
    * @return int
    */
    public function writeTag(int $tag): int;

    /**
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    *
    * @param int $tag
    * @param int $len
    * @return int
    */
    public function writeContextTag(int $tag, int $len): int;

    /**
    * Write length of the following data.
    * Return count of written bytes.
    *
    * @param int $len
    * @return int
    */
    public function writeLen(int $len): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeInt(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeInt8(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeInt16(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeInt32(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeInt64(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeUint(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeUint8(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeUint16(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeUint32(int $value): int;

    /**
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    *
    * @param int $value
    * @return int
    */
    public function writeUint64(int $value): int;

    /**
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    *
    * @param bool $value
    * @return int
    */
    public function writeBool(bool $value): int;

    /**
    * Write ASN.1 type: NULL.
    *
    * @return int
    */
    public function writeNull(): int;

    /**
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    *
    * @param string $value
    * @return int
    */
    public function writeOctetStr(string $value): int;

    /**
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    *
    * @param string $value
    * @return int
    */
    public function writeOctetStrAsBitstring(string $value): int;

    /**
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    *
    * @param string $data
    * @return int
    */
    public function writeData(string $data): int;

    /**
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    *
    * @param string $value
    * @return int
    */
    public function writeUtf8Str(string $value): int;

    /**
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    *
    * @param string $value
    * @return int
    */
    public function writeOid(string $value): int;

    /**
    * Mark previously written data of given length as ASN.1 type: SEQUENCE.
    * Return count of written bytes.
    *
    * @param int $len
    * @return int
    */
    public function writeSequence(int $len): int;

    /**
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    *
    * @param int $len
    * @return int
    */
    public function writeSet(int $len): int;
}
