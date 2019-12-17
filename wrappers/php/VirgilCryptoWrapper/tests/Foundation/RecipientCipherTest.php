<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

namespace Virgil\CryptoWrapperTests\Foundation;

use Virgil\CryptoWrapper\Foundation\KeyAsn1Deserializer;
use Virgil\CryptoWrapper\Foundation\KeyProvider;
use Virgil\CryptoWrapper\Foundation\RecipientCipher;

class RecipientCipherTest extends \PHPUnit\Framework\TestCase
{
    private $keyProvider;
    private $keyAsn1Deserializer;
    private $recipientCipher;

    const RECIPIENT_CIPHER_ED25519_PUBLIC_KEY = "302A300506032B657003210086614074B7A5D1130448BE69A4A25CE58DBF760A87BBF92A03ADD973F38ECE7C";
    const RECIPIENT_CIPHER_ED25519_PRIVATE_KEY = "302E020100300506032B65700422042010DA87566B446EDB74AFA6EB6754774367081EFA5FCD39C19E64A36830445B1B";
    const RECIPIENT_CIPHER_ED25519_RECIPIENT_ID = "6A078258DF744E6A91EF004057FAA4B24D339FB1C03D6C19C5ED52EBB520A3B4";
    const RECIPIENT_CIPHER_ENCRYPTED_MESSAGE = "308201600201003082015906092A864886F70D010703A082014A308201460201023182011730820113020102A02204206A078258DF744E6A91EF004057FAA4B24D339FB1C03D6C19C5ED52EBB520A3B4300506032B65700481E23081DF020100302A300506032B6570032100E2C5A1528C6801D466B7F8C726BD40CBF69EB3777982EAB65661AEAD55C848943018060728818C71020502300D060960864801650304020205003041300D06096086480165030402020500043031264EE2B79BCD1D3018FD4CCB2A01D9F7E3A20C50DE44C6914EF74B09B003277BAEE71F7F3D43D3C69B2AF583D7B6443051301D060960864801650304012A0410BE9ECE2B4D387B2E488B452E1000758204307962974C37C5566FD64EF54A04B9A677C13644589443E124CA2AFEE98B2AE8D3630338D08E62F98710641C93D176EBB1302606092A864886F70D0107013019060960864801650304012E040C4BDEE5FBECF47A6F8D8B3DD1A0B611ADD64BF4A3F88CB602FB4C979087C7A19A65743F578F9B7DBD550CC3B3307A7CBF1938AA8B19B53615CBB8370437A9C9488DCB63F327A3601920336A97A4767C68F992FBED9C3BD819AD6F1F445AEF9E30DF7926EAA7B5";
    const RECIPIENT_CIPHER_MESSAGE = "56697267696C205365637572697479204C69627261727920666F7220430A";
    const RECIPIENT_CIPHER_MESSAGE_2 = "56697267696C205365637572697479204C69627261727920666F7220430A56697267696C205365637572697479204C69627261727920666F7220430A56697267696C2053656375726974";

    protected function setUp()
    {
        $this->keyProvider = new KeyProvider();
        $this->keyAsn1Deserializer = new KeyAsn1Deserializer();
        $this->recipientCipher = new RecipientCipher();
    }

    protected function tearDown()
    {
        unset($this->recipientCipher);
        unset($this->keyAsn1Deserializer);
        unset($this->keyProvider);
    }

    public function test_RecipientCipher_encryptDecryptWithEd25519KeyRecipient()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $keyDeserializer = $this->keyAsn1Deserializer;
        $keyDeserializer->setupDefaults();

        $publicKey = $keyProvider->importPublicKey(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_PUBLIC_KEY));
        $privateKey = $keyProvider->importPrivateKey(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_PRIVATE_KEY));

        $recipientCipher = $this->recipientCipher;
        $recipientCipher->addKeyRecipient(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_RECIPIENT_ID), $publicKey);

        $recipientCipher->startEncryption();
        $encryptedMessage = $recipientCipher->packMessageInfo();
        $encryptedMessage .= $recipientCipher->processEncryption(self::unhexlify(self::RECIPIENT_CIPHER_MESSAGE));
        $encryptedMessage .= $recipientCipher->finishEncryption();

        $messageInfo = "";
        $recipientCipher->startDecryptionWithKey(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_RECIPIENT_ID), $privateKey, $messageInfo);
        $decryptedMessage = $recipientCipher->processDecryption($encryptedMessage);
        $decryptedMessage .= $recipientCipher->finishDecryption();

        $this->assertEquals(self::unhexlify(self::RECIPIENT_CIPHER_MESSAGE), $decryptedMessage);
    }

    public function test_RecipientCipher_decryptWithEd25519PublicKey()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $keyDeserializer = $this->keyAsn1Deserializer;
        $keyDeserializer->setupDefaults();

        $privateKey = $keyProvider->importPrivateKey(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_PRIVATE_KEY));

        $recipientCipher = $this->recipientCipher;

        $messageInfo = "";

        $recipientCipher->startDecryptionWithKey(self::unhexlify(self::RECIPIENT_CIPHER_ED25519_RECIPIENT_ID),
            $privateKey, $messageInfo);

        $decryptedMessage = $recipientCipher->processDecryption(self::unhexlify
        (self::RECIPIENT_CIPHER_ENCRYPTED_MESSAGE));

        $decryptedMessage .= $recipientCipher->finishDecryption();

        $this->assertEquals(self::unhexlify(self::RECIPIENT_CIPHER_MESSAGE_2), $decryptedMessage);
    }

    /**
     * @param string $string
     * @return string
     */
    private static function unhexlify(string $string): string
    {
        return pack("H*", $string);
    }
}