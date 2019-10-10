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

namespace VirgilCrypto\Foundation;

/**
* This is MbedTLS implementation of ASN.1 reader.
*/
class Asn1rd implements Asn1Reader
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
        $this->ctx = is_null($ctx) ? vscf_asn1rd_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_asn1rd_delete_php($this->ctx);
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

    /**
    * Reset all internal states and prepare to new ASN.1 reading operations.
    *
    * @param string $data
    * @return void
    */
    public function reset(string $data): void
    {
        vscf_asn1rd_reset_php($this->ctx, $data);
    }

    /**
    * Return length in bytes how many bytes are left for reading.
    *
    * @return int
    */
    public function leftLen(): int
    {
        return vscf_asn1rd_left_len_php($this->ctx);
    }

    /**
    * Return true if status is not "success".
    *
    * @return bool
    */
    public function hasError(): bool
    {
        return vscf_asn1rd_has_error_php($this->ctx);
    }

    /**
    * Return error code.
    *
    * @return void
    * @throws \Exception
    */
    public function status(): void
    {
        vscf_asn1rd_status_php($this->ctx);
    }

    /**
    * Get tag of the current ASN.1 element.
    *
    * @return int
    */
    public function getTag(): int
    {
        return vscf_asn1rd_get_tag_php($this->ctx);
    }

    /**
    * Get length of the current ASN.1 element.
    *
    * @return int
    */
    public function getLen(): int
    {
        return vscf_asn1rd_get_len_php($this->ctx);
    }

    /**
    * Get length of the current ASN.1 element with tag and length itself.
    *
    * @return int
    */
    public function getDataLen(): int
    {
        return vscf_asn1rd_get_data_len_php($this->ctx);
    }

    /**
    * Read ASN.1 type: TAG.
    * Return element length.
    *
    * @param int $tag
    * @return int
    */
    public function readTag(int $tag): int
    {
        return vscf_asn1rd_read_tag_php($this->ctx, $tag);
    }

    /**
    * Read ASN.1 type: context-specific TAG.
    * Return element length.
    * Return 0 if current position do not points to the requested tag.
    *
    * @param int $tag
    * @return int
    */
    public function readContextTag(int $tag): int
    {
        return vscf_asn1rd_read_context_tag_php($this->ctx, $tag);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt(): int
    {
        return vscf_asn1rd_read_int_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt8(): int
    {
        return vscf_asn1rd_read_int8_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt16(): int
    {
        return vscf_asn1rd_read_int16_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt32(): int
    {
        return vscf_asn1rd_read_int32_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt64(): int
    {
        return vscf_asn1rd_read_int64_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint(): int
    {
        return vscf_asn1rd_read_uint_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint8(): int
    {
        return vscf_asn1rd_read_uint8_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint16(): int
    {
        return vscf_asn1rd_read_uint16_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint32(): int
    {
        return vscf_asn1rd_read_uint32_php($this->ctx);
    }

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint64(): int
    {
        return vscf_asn1rd_read_uint64_php($this->ctx);
    }

    /**
    * Read ASN.1 type: BOOLEAN.
    *
    * @return bool
    */
    public function readBool(): bool
    {
        return vscf_asn1rd_read_bool_php($this->ctx);
    }

    /**
    * Read ASN.1 type: NULL.
    *
    * @return void
    */
    public function readNull(): void
    {
        vscf_asn1rd_read_null_php($this->ctx);
    }

    /**
    * Read ASN.1 type: NULL, only if it exists.
    * Note, this method is safe to call even no more data is left for reading.
    *
    * @return void
    */
    public function readNullOptional(): void
    {
        vscf_asn1rd_read_null_optional_php($this->ctx);
    }

    /**
    * Read ASN.1 type: OCTET STRING.
    *
    * @return string
    */
    public function readOctetStr(): string
    {
        return vscf_asn1rd_read_octet_str_php($this->ctx);
    }

    /**
    * Read ASN.1 type: BIT STRING.
    *
    * @return string
    */
    public function readBitstringAsOctetStr(): string
    {
        return vscf_asn1rd_read_bitstring_as_octet_str_php($this->ctx);
    }

    /**
    * Read ASN.1 type: UTF8String.
    *
    * @return string
    */
    public function readUtf8Str(): string
    {
        return vscf_asn1rd_read_utf8_str_php($this->ctx);
    }

    /**
    * Read ASN.1 type: OID.
    *
    * @return string
    */
    public function readOid(): string
    {
        return vscf_asn1rd_read_oid_php($this->ctx);
    }

    /**
    * Read raw data of given length.
    *
    * @param int $len
    * @return string
    */
    public function readData(int $len): string
    {
        return vscf_asn1rd_read_data_php($this->ctx, $len);
    }

    /**
    * Read ASN.1 type: SEQUENCE.
    * Return element length.
    *
    * @return int
    */
    public function readSequence(): int
    {
        return vscf_asn1rd_read_sequence_php($this->ctx);
    }

    /**
    * Read ASN.1 type: SET.
    * Return element length.
    *
    * @return int
    */
    public function readSet(): int
    {
        return vscf_asn1rd_read_set_php($this->ctx);
    }
}
