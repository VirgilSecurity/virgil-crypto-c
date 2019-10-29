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

namespace VirgilCrypto\Ratchet;

/**
* Class for ratchet session between 2 participants
*/
class RatchetSession
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
        $this->ctx = is_null($ctx) ? vscr_ratchet_session_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscr_ratchet_session_delete_php($this->ctx);
    }

    /**
    * @param VirgilCrypto\Foundation\Random $rng
    * @return void
    */
    public function useRng(VirgilCrypto\Foundation\Random $rng): void
    {
        vscr_ratchet_session_use_rng_php($this->ctx, $rng->getCtx());
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
        vscr_ratchet_session_setup_defaults_php($this->ctx);
    }

    /**
    * Initiates session
    *
    * @param string $senderIdentityPrivateKey
    * @param string $receiverIdentityPublicKey
    * @param string $receiverLongTermPublicKey
    * @param string $receiverOneTimePublicKey
    * @return void
    * @throws \Exception
    */
    public function initiate(string $senderIdentityPrivateKey, string $receiverIdentityPublicKey, string $receiverLongTermPublicKey, string $receiverOneTimePublicKey): void
    {
        vscr_ratchet_session_initiate_php($this->ctx, $senderIdentityPrivateKey, $receiverIdentityPublicKey, $receiverLongTermPublicKey, $receiverOneTimePublicKey);
    }

    /**
    * Responds to session initiation
    *
    * @param string $senderIdentityPublicKey
    * @param string $receiverIdentityPrivateKey
    * @param string $receiverLongTermPrivateKey
    * @param string $receiverOneTimePrivateKey
    * @param RatchetMessage $message
    * @return void
    * @throws \Exception
    */
    public function respond(string $senderIdentityPublicKey, string $receiverIdentityPrivateKey, string $receiverLongTermPrivateKey, string $receiverOneTimePrivateKey, RatchetMessage $message): void
    {
        vscr_ratchet_session_respond_php($this->ctx, $senderIdentityPublicKey, $receiverIdentityPrivateKey, $receiverLongTermPrivateKey, $receiverOneTimePrivateKey, $message->getCtx());
    }

    /**
    * Returns flag that indicates is this session was initiated or responded
    *
    * @return bool
    */
    public function isInitiator(): bool
    {
        return vscr_ratchet_session_is_initiator_php($this->ctx);
    }

    /**
    * Returns true if at least 1 response was successfully decrypted, false - otherwise
    *
    * @return bool
    */
    public function receivedFirstResponse(): bool
    {
        return vscr_ratchet_session_received_first_response_php($this->ctx);
    }

    /**
    * Returns true if receiver had one time public key
    *
    * @return bool
    */
    public function receiverHasOneTimePublicKey(): bool
    {
        return vscr_ratchet_session_receiver_has_one_time_public_key_php($this->ctx);
    }

    /**
    * Encrypts data
    *
    * @param string $plainText
    * @return RatchetMessage
    */
    public function encrypt(string $plainText): RatchetMessage
    {
        $ctx = vscr_ratchet_session_encrypt_php($this->ctx, $plainText);
        return new RatchetMessage($ctx);
    }

    /**
    * Calculates size of buffer sufficient to store decrypted message
    *
    * @param RatchetMessage $message
    * @return int
    */
    public function decryptLen(RatchetMessage $message): int
    {
        return vscr_ratchet_session_decrypt_len_php($this->ctx, $message->getCtx());
    }

    /**
    * Decrypts message
    *
    * @param RatchetMessage $message
    * @return string
    * @throws \Exception
    */
    public function decrypt(RatchetMessage $message): string
    {
        return vscr_ratchet_session_decrypt_php($this->ctx, $message->getCtx());
    }

    /**
    * Serializes session to buffer
    *
    * @return Buffer
    */
    public function serialize(): Buffer
    {
        $ctx = vscr_ratchet_session_serialize_php($this->ctx);
        return new Buffer($ctx);
    }

    /**
    * Deserializes session from buffer.
    * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    *
    * @param string $input
    * @return RatchetSession
    */
    public static function deserialize(string $input): RatchetSession
    {
        $ctx = vscr_ratchet_session_deserialize_php($input);
        return new RatchetSession($ctx);
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
