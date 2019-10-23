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
* Group ticket used to start group session, remove participants or proactive to rotate encryption key.
*/
class GroupSessionTicket
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
        $this->ctx = is_null($ctx) ? vscf_group_session_ticket_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_group_session_ticket_delete_php($this->ctx);
    }

    /**
    * @param Random $rng
    * @return void
    */
    public function useRng(Random $rng): void
    {
        vscf_group_session_ticket_use_rng_php($this->ctx, $rng->getCtx());
    }

    /**
    * Setups default dependencies:
    * - RNG: CTR DRBG
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_group_session_ticket_setup_defaults_php($this->ctx);
    }

    /**
    * Set this ticket to start new group session.
    *
    * @param string $sessionId
    * @return void
    * @throws \Exception
    */
    public function setupTicketAsNew(string $sessionId): void
    {
        vscf_group_session_ticket_setup_ticket_as_new_php($this->ctx, $sessionId);
    }

    /**
    * Returns message that should be sent to all participants using secure channel.
    *
    * @return GroupSessionMessage
    */
    public function getTicketMessage(): GroupSessionMessage
    {
        $ctx = vscf_group_session_ticket_get_ticket_message_php($this->ctx);
        return new GroupSessionMessage($ctx);
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
