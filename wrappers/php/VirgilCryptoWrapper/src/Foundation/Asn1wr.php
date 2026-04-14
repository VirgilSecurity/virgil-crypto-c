<?php
/**
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

namespace Virgil\CryptoWrapper\Foundation;

class Asn1wr implements Asn1Writer
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_asn1wr_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_asn1wr_delete_php($this->ctx);
    }

    /**
    *
    * @param int $$out
    * @param int $$outLen
    * @return void
    */
    public function reset(int $$out, int $$outLen): void
    {
        vscf_asn1wr_reset_php($this->ctx, $$out, $$outLen);
    }

    /**
    *
    * @param bool $$doNotAdjust
    * @return int
    */
    public function finish(bool $$doNotAdjust): int
    {
        return vscf_asn1wr_finish_php($this->ctx, $$doNotAdjust);
    }

    /**
    *
    * @return string
    */
    public function bytes(): string
    {
        return vscf_asn1wr_bytes_php($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function len(): int
    {
        return vscf_asn1wr_len_php($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function writtenLen(): int
    {
        return vscf_asn1wr_written_len_php($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function unwrittenLen(): int
    {
        return vscf_asn1wr_unwritten_len_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function hasError(): bool
    {
        return vscf_asn1wr_has_error_php($this->ctx);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function status(): void
    {
        vscf_asn1wr_status_php($this->ctx);
    }

    /**
    *
    * @param int $$len
    * @return string
    */
    public function reserve(int $$len): string
    {
        return vscf_asn1wr_reserve_php($this->ctx, $$len);
    }

    /**
    *
    * @param int $$tag
    * @return int
    */
    public function writeTag(int $$tag): int
    {
        return vscf_asn1wr_write_tag_php($this->ctx, $$tag);
    }

    /**
    *
    * @param int $$tag
    * @param int $$len
    * @return int
    */
    public function writeContextTag(int $$tag, int $$len): int
    {
        return vscf_asn1wr_write_context_tag_php($this->ctx, $$tag, $$len);
    }

    /**
    *
    * @param int $$len
    * @return int
    */
    public function writeLen(int $$len): int
    {
        return vscf_asn1wr_write_len_php($this->ctx, $$len);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeInt(int $$value): int
    {
        return vscf_asn1wr_write_int_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeInt8(int $$value): int
    {
        return vscf_asn1wr_write_int8_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeInt16(int $$value): int
    {
        return vscf_asn1wr_write_int16_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeInt32(int $$value): int
    {
        return vscf_asn1wr_write_int32_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeInt64(int $$value): int
    {
        return vscf_asn1wr_write_int64_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeUint(int $$value): int
    {
        return vscf_asn1wr_write_uint_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeUint8(int $$value): int
    {
        return vscf_asn1wr_write_uint8_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeUint16(int $$value): int
    {
        return vscf_asn1wr_write_uint16_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeUint32(int $$value): int
    {
        return vscf_asn1wr_write_uint32_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$value
    * @return int
    */
    public function writeUint64(int $$value): int
    {
        return vscf_asn1wr_write_uint64_php($this->ctx, $$value);
    }

    /**
    *
    * @param bool $$value
    * @return int
    */
    public function writeBool(bool $$value): int
    {
        return vscf_asn1wr_write_bool_php($this->ctx, $$value);
    }

    /**
    *
    * @return int
    */
    public function writeNull(): int
    {
        return vscf_asn1wr_write_null_php($this->ctx);
    }

    /**
    *
    * @param string $$value
    * @return int
    */
    public function writeOctetStr(string $$value): int
    {
        return vscf_asn1wr_write_octet_str_php($this->ctx, $$value);
    }

    /**
    *
    * @param string $$value
    * @return int
    */
    public function writeOctetStrAsBitstring(string $$value): int
    {
        return vscf_asn1wr_write_octet_str_as_bitstring_php($this->ctx, $$value);
    }

    /**
    *
    * @param string $$data
    * @return int
    */
    public function writeData(string $$data): int
    {
        return vscf_asn1wr_write_data_php($this->ctx, $$data);
    }

    /**
    *
    * @param string $$value
    * @return int
    */
    public function writeUtf8Str(string $$value): int
    {
        return vscf_asn1wr_write_utf8_str_php($this->ctx, $$value);
    }

    /**
    *
    * @param string $$value
    * @return int
    */
    public function writeOid(string $$value): int
    {
        return vscf_asn1wr_write_oid_php($this->ctx, $$value);
    }

    /**
    *
    * @param int $$len
    * @return int
    */
    public function writeSequence(int $$len): int
    {
        return vscf_asn1wr_write_sequence_php($this->ctx, $$len);
    }

    /**
    *
    * @param int $$len
    * @return int
    */
    public function writeSet(int $$len): int
    {
        return vscf_asn1wr_write_set_php($this->ctx, $$len);
    }

    /**
    * Get C context.
    *
    * @return resource
    */
    public function getCtx()
    {
        return $this->ctx;
    }
}
