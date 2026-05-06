<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

class AlgInfoDerSerializer implements AlgInfoSerializer
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
        $this->ctx = is_null($ctx) ? vscf_alg_info_der_serializer_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_alg_info_der_serializer_delete_php($this->ctx);
    }

    /**
    *
    * @param Asn1Writer $$asn1Writer
    * @return void
    */
    public function useAsn1Writer(Asn1Writer $$asn1Writer): void
    {
        vscf_alg_info_der_serializer_use_asn1_writer_php($this->ctx, $$asn1Writer);
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return string
    */
    public function serialize(AlgInfo $$algInfo): string
    {
        return vscf_alg_info_der_serializer_serialize_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_alg_info_der_serializer_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param AlgId $$algId
    * @return bool
    */
    public static function isAlgRequireNullParams(AlgId $$algId): bool
    {
        return vscf_alg_info_der_serializer_is_alg_require_null_params_php($$algId);
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedSimpleAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_simple_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeSimpleAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_simple_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedKdfAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_kdf_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeKdfAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_kdf_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedHkdfAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeHkdfAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_hkdf_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedHmacAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_hmac_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeHmacAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_hmac_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedCipherAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_cipher_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeCipherAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_cipher_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedPbkdf2AlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializePbkdf2AlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedPbes2AlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializePbes2AlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_pbes2_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedEccAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_ecc_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeEccAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_ecc_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedCompoundKeyAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeCompoundKeyAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_compound_key_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializedHybridKeyAlgInfoLen(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialized_hybrid_key_alg_info_len_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeHybridKeyAlgInfo(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_hybrid_key_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return int
    */
    public function serializeInplace(AlgInfo $$algInfo): int
    {
        return vscf_alg_info_der_serializer_serialize_inplace_php($this->ctx, $$algInfo->getCtx());
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
