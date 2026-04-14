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

class GroupSession
{

    /**
    * @var
    */
    private $ctx;

    const SENDER_ID_LEN = 32;
    const MAX_PLAIN_TEXT_LEN = 30000;
    const MAX_EPOCHS_COUNT = 50;
    const SALT_SIZE = 32;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_group_session_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_group_session_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$rng
    * @return void
    */
    public function useRng(Random $$rng): void
    {
        vscf_group_session_use_rng_php($this->ctx, $$rng);
    }

    /**
    *
    * @return int
    */
    public function getCurrentEpoch(): int
    {
        return vscf_group_session_get_current_epoch_php($this->ctx);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_group_session_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function getSessionId(): string
    {
        return vscf_group_session_get_session_id_php($this->ctx);
    }

    /**
    *
    * @param GroupSessionMessage $$message
    * @return void
    * @throws \Exception
    */
    public function addEpoch(GroupSessionMessage $$message): void
    {
        vscf_group_session_add_epoch_php($this->ctx, $$message);
    }

    /**
    *
    * @param string $$plainText
    * @param PrivateKey $$privateKey
    * @return GroupSessionMessage
    * @throws \Exception
    */
    public function encrypt(string $$plainText, PrivateKey $$privateKey): GroupSessionMessage
    {
        $ctx = vscf_group_session_encrypt_php($this->ctx, $$plainText, $$privateKey->getCtx());
        return new GroupSessionMessage($ctx);
    }

    /**
    *
    * @param GroupSessionMessage $$message
    * @return int
    */
    public function decryptLen(GroupSessionMessage $$message): int
    {
        return vscf_group_session_decrypt_len_php($this->ctx, $$message);
    }

    /**
    *
    * @param GroupSessionMessage $$message
    * @param PublicKey $$publicKey
    * @return string
    * @throws \Exception
    */
    public function decrypt(GroupSessionMessage $$message, PublicKey $$publicKey): string
    {
        return vscf_group_session_decrypt_php($this->ctx, $$message, $$publicKey->getCtx());
    }

    /**
    *
    * @return GroupSessionTicket
    * @throws \Exception
    */
    public function createGroupTicket(): GroupSessionTicket
    {
        $ctx = vscf_group_session_create_group_ticket_php($this->ctx);
        return new GroupSessionTicket($ctx);
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
