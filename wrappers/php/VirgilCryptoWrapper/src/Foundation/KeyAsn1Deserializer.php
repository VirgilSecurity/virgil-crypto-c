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

class KeyAsn1Deserializer implements KeyDeserializer
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
        $this->ctx = is_null($ctx) ? vscf_key_asn1_deserializer_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_key_asn1_deserializer_delete_php($this->ctx);
    }

    /**
    *
    * @param Asn1Reader $$asn1Reader
    * @return void
    */
    public function useAsn1Reader(Asn1Reader $$asn1Reader): void
    {
        vscf_key_asn1_deserializer_use_asn1_reader_php($this->ctx, $$asn1Reader);
    }

    /**
    *
    * @param string $$publicKeyData
    * @return RawPublicKey
    * @throws \Exception
    */
    public function deserializePublicKey(string $$publicKeyData): RawPublicKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_public_key_php($this->ctx, $$publicKeyData);
        return new RawPublicKey($ctx);
    }

    /**
    *
    * @param string $$privateKeyData
    * @return RawPrivateKey
    * @throws \Exception
    */
    public function deserializePrivateKey(string $$privateKeyData): RawPrivateKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_private_key_php($this->ctx, $$privateKeyData);
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_key_asn1_deserializer_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @return RawPublicKey
    * @throws \Exception
    */
    public function deserializePublicKeyInplace(): RawPublicKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_public_key_inplace_php($this->ctx);
        return new RawPublicKey($ctx);
    }

    /**
    *
    * @return RawPrivateKey
    * @throws \Exception
    */
    public function deserializePrivateKeyInplace(): RawPrivateKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_private_key_inplace_php($this->ctx);
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @param int $$seqLeftLen
    * @param int $$version
    * @return RawPrivateKey
    * @throws \Exception
    */
    public function deserializePkcs8PrivateKeyInplace(int $$seqLeftLen, int $$version): RawPrivateKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_pkcs8_private_key_inplace_php($this->ctx, $$seqLeftLen, $$version);
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @param int $$seqLeftLen
    * @param int $$version
    * @param AlgInfo $$algInfo
    * @return RawPrivateKey
    * @throws \Exception
    */
    public function deserializeSec1PrivateKeyInplace(int $$seqLeftLen, int $$version, AlgInfo $$algInfo): RawPrivateKey
    {
        $ctx = vscf_key_asn1_deserializer_deserialize_sec1_private_key_inplace_php($this->ctx, $$seqLeftLen, $$version, $$algInfo->getCtx());
        return new RawPrivateKey($ctx);
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
