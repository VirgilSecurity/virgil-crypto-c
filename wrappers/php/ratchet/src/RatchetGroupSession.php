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

namespace Virgil\CryptoWrapper\Ratchet;

/**
* Ratchet group session.
*/
class RatchetGroupSession
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
        $this->ctx = is_null($ctx) ? vscr_ratchet_group_session_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscr_ratchet_group_session_delete_php($this->ctx);
    }

    /**
    * @param VirgilCryptoWrapper\Foundation\Random $rng
    * @return void
    */
    public function useRng(VirgilCryptoWrapper\Foundation\Random $rng): void
    {
        vscr_ratchet_group_session_use_rng_php($this->ctx, $rng->getCtx());
    }

    /**
    * Shows whether session was initialized.
    *
    * @return bool
    */
    public function isInitialized(): bool
    {
        return vscr_ratchet_group_session_is_initialized_php($this->ctx);
    }

    /**
    * Shows whether identity private key was set.
    *
    * @return bool
    */
    public function isPrivateKeySet(): bool
    {
        return vscr_ratchet_group_session_is_private_key_set_php($this->ctx);
    }

    /**
    * Shows whether my id was set.
    *
    * @return bool
    */
    public function isMyIdSet(): bool
    {
        return vscr_ratchet_group_session_is_my_id_set_php($this->ctx);
    }

    /**
    * Returns current epoch.
    *
    * @return int
    */
    public function getCurrentEpoch(): int
    {
        return vscr_ratchet_group_session_get_current_epoch_php($this->ctx);
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
        vscr_ratchet_group_session_setup_defaults_php($this->ctx);
    }

    /**
    * Sets identity private key.
    *
    * @param string $myPrivateKey
    * @return void
    * @throws \Exception
    */
    public function setPrivateKey(string $myPrivateKey): void
    {
        vscr_ratchet_group_session_set_private_key_php($this->ctx, $myPrivateKey);
    }

    /**
    * Sets my id. Should be 32 byte
    *
    * @param string $myId
    * @return void
    */
    public function setMyId(string $myId): void
    {
        vscr_ratchet_group_session_set_my_id_php($this->ctx, $myId);
    }

    /**
    * Returns my id.
    *
    * @return string
    */
    public function getMyId(): string
    {
        return vscr_ratchet_group_session_get_my_id_php($this->ctx);
    }

    /**
    * Returns session id.
    *
    * @return string
    */
    public function getSessionId(): string
    {
        return vscr_ratchet_group_session_get_session_id_php($this->ctx);
    }

    /**
    * Returns number of participants.
    *
    * @return int
    */
    public function getParticipantsCount(): int
    {
        return vscr_ratchet_group_session_get_participants_count_php($this->ctx);
    }

    /**
    * Sets up session.
    * Use this method when you have newer epoch message and know all participants info.
    * NOTE: Identity private key and my id should be set separately.
    *
    * @param RatchetGroupMessage $message
    * @param RatchetGroupParticipantsInfo $participants
    * @return void
    * @throws \Exception
    */
    public function setupSessionState(RatchetGroupMessage $message, RatchetGroupParticipantsInfo $participants): void
    {
        vscr_ratchet_group_session_setup_session_state_php($this->ctx, $message->getCtx(), $participants->getCtx());
    }

    /**
    * Sets up session.
    * Use this method when you have message with next epoch, and you know how participants set was changed.
    * NOTE: Identity private key and my id should be set separately.
    *
    * @param RatchetGroupMessage $message
    * @param RatchetGroupParticipantsInfo $addParticipants
    * @param RatchetGroupParticipantsIds $removeParticipants
    * @return void
    * @throws \Exception
    */
    public function updateSessionState(RatchetGroupMessage $message, RatchetGroupParticipantsInfo $addParticipants, RatchetGroupParticipantsIds $removeParticipants): void
    {
        vscr_ratchet_group_session_update_session_state_php($this->ctx, $message->getCtx(), $addParticipants->getCtx(), $removeParticipants->getCtx());
    }

    /**
    * Encrypts data
    *
    * @param string $plainText
    * @return RatchetGroupMessage
    */
    public function encrypt(string $plainText): RatchetGroupMessage
    {
        $ctx = vscr_ratchet_group_session_encrypt_php($this->ctx, $plainText);
        return new RatchetGroupMessage($ctx);
    }

    /**
    * Calculates size of buffer sufficient to store decrypted message
    *
    * @param RatchetGroupMessage $message
    * @return int
    */
    public function decryptLen(RatchetGroupMessage $message): int
    {
        return vscr_ratchet_group_session_decrypt_len_php($this->ctx, $message->getCtx());
    }

    /**
    * Decrypts message
    *
    * @param RatchetGroupMessage $message
    * @param string $senderId
    * @return string
    * @throws \Exception
    */
    public function decrypt(RatchetGroupMessage $message, string $senderId): string
    {
        return vscr_ratchet_group_session_decrypt_php($this->ctx, $message->getCtx(), $senderId);
    }

    /**
    * Serializes session to buffer
    * NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
    *
    * @return Buffer
    */
    public function serialize(): Buffer
    {
        $ctx = vscr_ratchet_group_session_serialize_php($this->ctx);
        return new Buffer($ctx);
    }

    /**
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set.
    * You should set separately:
    * - rng
    * - my private key
    *
    * @param string $input
    * @return RatchetGroupSession
    */
    public static function deserialize(string $input): RatchetGroupSession
    {
        $ctx = vscr_ratchet_group_session_deserialize_php($input);
        return new RatchetGroupSession($ctx);
    }

    /**
    * Creates ticket with new key for adding or removing participants.
    *
    * @return RatchetGroupTicket
    */
    public function createGroupTicket(): RatchetGroupTicket
    {
        $ctx = vscr_ratchet_group_session_create_group_ticket_php($this->ctx);
        return new RatchetGroupTicket($ctx);
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
