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

class AlgInfoDerDeserializer implements AlgInfoDeserializer
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
        $this->ctx = is_null($ctx) ? vscf_alg_info_der_deserializer_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_alg_info_der_deserializer_delete_php($this->ctx);
    }

    /**
    *
    * @param Asn1Reader $$asn1Reader
    * @return void
    */
    public function useAsn1Reader(Asn1Reader $$asn1Reader): void
    {
        vscf_alg_info_der_deserializer_use_asn1_reader_php($this->ctx, $$asn1Reader);
    }

    /**
    *
    * @param string $$data
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserialize(string $$data): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_php($this->ctx, $$data);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_alg_info_der_deserializer_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeSimpleAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_simple_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeKdfAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_kdf_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeHkdfAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeHmacAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_hmac_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeCipherAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_cipher_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializePbkdf2AlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializePbes2AlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeEccAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_ecc_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeCompoundKeyAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param OidId $$oidId
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeHybridKeyAlgInfo(OidId $$oidId): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info_php($this->ctx, $$oidId);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function deserializeInplace(): AlgInfo
    {
        $ctx = vscf_alg_info_der_deserializer_deserialize_inplace_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
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
