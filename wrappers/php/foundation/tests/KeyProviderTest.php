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

namespace VirgilCrypto\Foundation\Tests;

use VirgilCrypto\Foundation\AlgId;
use VirgilCrypto\Foundation\Ed25519;
use VirgilCrypto\Foundation\KeyAsn1Deserializer;
use VirgilCrypto\Foundation\KeyMaterialRng;
use VirgilCrypto\Foundation\KeyProvider;
use VirgilCrypto\Foundation\RecipientCipher;
use VirgilCrypto\Foundation\Rsa;

class KeyProviderTest extends \PHPUnit\Framework\TestCase
{
    private $keyProvider;
    private $keyAsn1Deserializer;
    private $recipientCipher;
    private $ed25519;
    private $keyMaterialRng;
    private $rsa;

    const KEY_PROVIDER_MESSAGE_SHA512_DIGEST = "6D49D5E34AD7A0359FB00628AACD41DA3C62341EF204008EA87D40729AA5FBD81CC1809762A8051185264DB094044EF8E12C4B27781DE558F397DAA2078C568D";
    const DETERMINISTIC_KEY_KEY_MATERIAL = "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
    const DETERMINISTIC_KEY_ED25519_PRIVATE_KEY = "79F9458B7266A90A9B155B13763559FB6B748D30E38C3D802F6A4A812852750B";
    const DETERMINISTIC_KEY_RSA4096_PRIVATE_KEY = "308209270201000282020100D8817A9E8F8F951DBCBFEF32D56D0462C17232ED1467D8169E298275C81B027BDA778806B8B4ACCCA5EA07F113DF220BFC2C32BFD833BF203BBAE912264F97ED2B391C67D2DB4612EEBA060EFDAB83BBB915A7F54F2043160169CCD1075DB240213B080B4C31842A5A27B346A5088786E014E2F0C2C888A4ACBA6DFA1992156FF94766A7BA7B661A10999ED5B997D27679C5C7878F40EC607ED95AEE7E0B25735ADE4B72A2C52B0C0322F527A8AEBDF5B2CF28A60095F4ED69A169FB2386AE4684CFCB44F0F58C7A5C7008B1B0886B5EC8EBF2F21CDD164E7276E3959342C59D77D18D233508A288EFB150B0C0542E7015B6D536AE644BB17BE3BFED6927EE4E8CC98AD406E90581AC2ACA20979AA9AA36AFB500E1756ED0D33173AC6200453DBAD3FD8AFB6476F2293DBA9C8E1024FCC8A5D2D0889BEFA8F9FEF5C39E4B2721E279E138BFA994CE323237D527B647AC28140ADDA8A502B153B867FC444F7531F87793050981E0BD72470918DD6545C4F8E78B111B9E7F54E2AD0F58DCD7B97E6041DE3E37F7F7003695E2EA460B98FB4DF3075A9CBC942C297AD3821696DF83F8E3D6E40515739093FE37FE382B118E902F31AB51378B9D9DBE176910BF31DC2C3E361D62661122E80544438BE892A4A4E50D21E9CC2A1B50554FD76031AF431A83415C2AFF22F74604AD2F81E40238CE443AB15D39B4B0C728882DF8E40E1902030100010282020010EEB36DD2317B0A8BD800F79B4C7EE2D05943955A1AB30235D56E4012E9D5DC64DE2353CF3F46226D396BEC954EC6A5644FFA9A196916A20939D97F93627731D3C7102B288900A67B682E101F13BA664497E67E5F7558F9D01B7BAABF663B0A1BEF377656BBAAA7FB4C0E8FD05965EC0CFB65324A318FCA3D3E095ADD8418CC1C9552787CB3A8ED11EE49C7525006E4402AD12B8F6F16ED870E2DB7E840ABE9A52A2C81672C7F6CDD93EED36EB457E3EEDB97C4BFD7FA8354D70C6859436FBED1254532FB9B60A4B33509E107BAEB96CAA4F567AD0D3770E42FDB25B812294D62F10F16395017121998E70423CE91A12F79909C49B04B61329CC1C66A0A76EF25CF25AC29F521A7F01A68DA8666FD78083D0B9147F8C796163DD985A3CD81842785F8843928B752EE1236740E17903CA13473BFC5F257B9447F2D415BD47B7798662D6B9F60B63EA57782C2558F0A24AFE35E4850F4FEE5F86FD5D1698693818ED935E7357A0BFB118D2967EDA975174E8588AFA8B0F788D30376DC3DAB89E8CBE534685E3111E42D76B9F6E68AFC45CFC0C0356720C3CB2E3CBBF0F8E18DC848CB1EFEAF6550BA75191590947A332F1244493E0603DEE0E2288F6E57AFB28CA427226657BAD097B96B027BC49603F9FD63B30D967165E50DFC6AF596A24CCEA63A86BEEE874B589E5C4E8A71BCCB8B2B68696B5AAF57202D47CAA487B6F6590282010100FF13F2D6D0810D5015B4892746E6ABFD568E1A6661CDBFE47D83EDB5D8650D2B1FAEB56E7B26725A2D36F368EA37649BA30DC2565D5C04EF02A85A9F0C705A039FAA47859A0E8C80622580A18C5759661ACB18545DB80F4D690C754A46D3B69522989FC700B95C29B82686273B3034748B88FD9E277843C3A9FE287F29256F5CD4274BF7E31465AAC8BD458BA5E9E4BBC9A07661A8A5C7A5CB2997C2E13EBF820ABD5DA4F7729EBE09DCF1354E9597D93D54B30B7E72744FE6325EFCC8422DCEF5B5B0917C44BB529AB29E3133017E8082DE5077AA07E949E07C365CB40FE173D2FC07207067917151B379AFA39BCC7CA2A3D0A8D5635FA0D1D3DEFAAAC0ADA50282010100D949D5DB6AD5C5584880D836F6131EC37DA87E647ACEA37797FC19C79F26A0DA23C48236D6C09A801723E547F0E20CD00E3D70634F07CB2E07CC645330BDF140219BA3E61A2D182B43A4842A06BC9EB906DD34619F91AE5756A3F1A250983CC5396CEF6020F1CCF7F15B2CF4ED3B7F81F182A742FC82528D92AC0FA574DFFC8C3146BBD9F7D12888AE6816D532A146B9D58EA0F297EDFF25F209B3886D154380A3EF4B216A62EB35B11607CB552DE753B4BB00C4DEE31D35A41830A610B23F323691C8B9B7DF3D767F7B75B5B17E49C21EB207E51609830CA118B57C7DA337C5FCD31F4A1322B9A8D4E1338FD654220ED583DA7FCC1AAB18144C8C6A4DA39C65028201004508D81B4D58F00A71A567CD4A8219A039F1C1B15DDCFA875375063BC5F22B6B356AEA4D9964E1640882ABC40447B3A1EFB2449B6D2EFF62D47C4DF267C26C8A3887344E3350A6B4045C140124E36B1D9838C93FE411718AC8D88751EFF352A1F038105E2293081F7E6866BC6D67717AED5CC90F29AD81E18DBB6CA865B16CFF59A7BD06BCDD835A8273BF43B946A11235D288D78B763A9F6369C15A0BEE1894906589D7A0E4D393A945B3BE72A347F29287BEE1687A7F82345203A53469BCCE1B6FEDF6A20454125A2DE76477627B233AC8024D30A66D7C02167BFC00FB9F4FE2953534915766649DF10E08FC25A9653DFB49F8B7AFEA6CB2FD3D86E7F9B7C50282010000A1442B74ADD5FAA18B2E154AB5577B7D9BC57209211C3C368696948B939317CECEBD09E7A97B492FC7FCDC2E88993CE92DA86BC148E67FE5A9E40891B59B4372557F2E259947DEA83D8BDC8B5474A958A9BF8320F14D2E17A43609206EB08E69D235077450FF2520E000CB5CFCB52BED4551B2D20496B4AE5E2D556F774EC621467138FA8CF2AF22C24E7EA3BCEFF58DF6F1E48228407B1DAE8584B9BC3C0BDD6DCE2BF4A100C9910FDD49EB9F4C7263ADBF1CD300998F1440B5B3658CFEBDE88697AC622A1585886D153447A5741549FD7E245DE1FD2D46324A246840D6E28E0F16A22258116DB9E04543FF7D12F4340E43CDE70B94BF671FA9B08D3512390282010038937D87C46679D4C3D35C9C0C00D3118CC6A65ECA004D8C035E807A42F9B647DAF65029102D080BB48090F685C189E15DFFC4DBC19AC859310CBC857A67295C63DEFE3C80164EBD528EEEC11D1152D81D7CC7F9AE6BE75B8F5DE28A698F942AD130FE35B1E08E20F4D7DA3ECED899E3E4AAF536D26EFAF92BA5A1F8ED42587FD67498ED7501CF577CF49A671CA677A3914D28475E2BE60C833D56D6E16130702A1EDD3EF15902DF49849FDFBE57A3C2A5CD494D5C6A959F285BA121A72F6E94F8587080CDA1816B2B8D57491E9FF3272BFCAE053DF80B022D15866F788F16659DCECFC7893106D455113C3FF42F2F4392C8344CB30C8C9FC2AD83553DDBB7D2";
    const ED25519_PRIVATE_KEY = "4D43344341514177425159444B32567742434945494573434C484E506358502B";
    const ED25519_PRIVATE_KEY_PKCS8_DER = "302E020100300506032B6570042204204D43344341514177425159444B32567742434945494573434C484E506358502B";
    const ED25519_PUBLIC_KEY = "E7349DD5EB23233766F3192E2D9D4D26D8A2671D71E8AED48053B47F55F47032";
    const ED25519_PUBLIC_KEY_PKCS8_DER = "302A300506032B6570032100E7349DD5EB23233766F3192E2D9D4D26D8A2671D71E8AED48053B47F55F47032";
    const ED25519_MESSAGE_SHA256_DIGEST = "3684A316A74AB39BD2C29A2E862F05795BE949B212C920C43D21D4CE9D41016A";
    const ED25519_SHA256_SIGNATURE = "F22BD5B9648C906B1951DEED256CE295114B0B699A068FC52C156B4FF3EFA5AE035E48F447E9E21F6D6339E5508F6B273271F76FC90DF95C0E965436482E1402";
    const ED25519_RANDOM = "4D43344341514177425159444B32567742434945494573434C484E506358502B";
    const ED25519_ENCRYPTED_MESSAGE = "3081DB020100302A300506032B6570032100854F7797283006AE5E474DFB612C41CBDBD17CD3D31B2160211E6B66D88712A43016060728818C71020502300B0609608648016503040202303F300B06096086480165030402020430A7A6B8EF584C2B419D7A43A88ABAA6565EF633B280E8EF3BA61975F536164650965426F4C7CC8B3E842175E1EA1319533051301D060960864801650304012A041028C8A5D13A37EF6C9A0A35AB9427FB0F04306440C128087ED091EF380EE3D4B832C66293700EA965DDDD254D18830268548E09D24CFA08F4015864E2EEE1CF0B3477";
    const ED25519_MESSAGE = "3237643230393430656630363034643232396332346535613565623230623136";
    const RSA_PCKS8_2048_PUBLIC_KEY_DER = "30820121300D06092A864886F70D01010105000382010E003082010902820100537CC7E8FB4B0975739F3FF613D01A98D5039EB859C0FD8B01DF72A63673EFAD121C33746F2A1C1BE43999CFC545FAB897569131AE7EB76013E87AC32707A9C910F13AA798CFA05E78711B716BB5C8F3A70BADD37E9375ACF752C1D096A9EFBAED8484721E9EBB0865FD0C5547094617D713F86F92A32F43D6FD3B52D5855C7384504AAD7FDF95CEFFEF806AED6B75EBD650B733EEEEEA53479EF38F59C5F68290724A62EDD013DBB6EEA566FD5CB44E7ACDC027E48F7DB620DE7ECAB187C314987BADE4CBE1D19DD43B0C86EFF900EB4EE1F793E8D033D9459B146AAFF9971DC1C727408E9722A91D27AE3BB3151E97AEC7F3605622A0E38B8BB4EA46E610EB0203010001";
    const RSA_PCKS8_2048_PRIVATE_KEY_DER = "308204BC020100300D06092A864886F70D0101010500048204A6308204A202010002820100537CC7E8FB4B0975739F3FF613D01A98D5039EB859C0FD8B01DF72A63673EFAD121C33746F2A1C1BE43999CFC545FAB897569131AE7EB76013E87AC32707A9C910F13AA798CFA05E78711B716BB5C8F3A70BADD37E9375ACF752C1D096A9EFBAED8484721E9EBB0865FD0C5547094617D713F86F92A32F43D6FD3B52D5855C7384504AAD7FDF95CEFFEF806AED6B75EBD650B733EEEEEA53479EF38F59C5F68290724A62EDD013DBB6EEA566FD5CB44E7ACDC027E48F7DB620DE7ECAB187C314987BADE4CBE1D19DD43B0C86EFF900EB4EE1F793E8D033D9459B146AAFF9971DC1C727408E9722A91D27AE3BB3151E97AEC7F3605622A0E38B8BB4EA46E610EB02030100010282010048A0A077F943C9B2B726AE49AFEAB57886B6637913FB63956DC7A8C11755BC06DF5E5114D52FD8CC1ABA51280201629EFA68805EABE1E83C589541564BB9CAE5F32B274F6D0C12029CDC28777EAFE164B4C8E02AC04E1F6C9CAB0D981BB931A777C07447A2838B493F0FE78EB801454CAFF9DB81941B099F0683BCFBCE6BF984347FC0F3B693A4A355687FD464AA7289D34C5B866895DD41AABB54D0B340747567469CEAA36F3920DF1C393C9B8FCA824E2BE741A094D792259D5CB71A981EED7127181E61B9147F2573982D7A31C705B089C3881DD285AB0E8DC775249CE3AFCCC19CE1FBA4676B84DD79057AA2B0E872A5EEC98357E31B0B58DCCBF601D22102818100A379B8FDB31D795325613B14722C91C2DF5B4B1D7968FA1803DC574493F0727AFEA82A1A83763532B4A4484971D7898A179BAFF921996C74DD920B5A011957451C3C5EE0178A0E5B5673C56D560EC54FCB1E18D6A8BD0B1215F020CB1DEF12DB0325F9337F4039A79FCAAE335E069423675A000F1F7337FC861F0A246355A0DD0281810082BD6F58F121E6C8DCA3D62C2079AE7DADD8D9F18C678A36E1D97EBA58D7392D5C641B23EF4F172EF645027F6DF8EAD0EBDA154B723B98212DD1BF7C4B90AA8AAD06FEABEEAA3F8CBBE02EB8D0E5B819356BCE6C0F559E259FF4FF11C45BEA46DFABF7983D059AB6AE28C2BC64E5D3335E96B2A446371CF31917A370F02A38670281807021791383FDAE8FAAAF23D025748ED2C5542094EA0768AC7A517406951733DF4BB7DB916E24F1DE82EBC0ADA809B8CCE0DEA878D164247190DDB12D9E5D5C700A2B1AC4C940A8125C9D728949A33E123A77BD7FD8243B68BF658388EF52627399983D73E6500E7BFCEE104929B08782354D15874A02451FD07B90005FA6877D0281804A9F93D1A178E74098E78F148AC8C97704E6B4A771AB9BB16DC1F5DAA960D74AF3E453B5741FA1ACF5763851C1D4853B1093DEF9BC4F15AB427AE9202A057DC23FB6B160338ECB4D29E370E79E9CB032FB51F875A75F08309397848B8097B22617FF1108BD33D8B612BC4342C318872F57FB0E2643C9AB657A5A0AB928EC005B02818100946945F81BD813FD29F99DA0EE71D994CC3025FC781AC9A31D734951A5D765C9A3F76D35A518B6804E5C7A1CC95C2DF4DEFC6900850A2C8BADEC1C1AA4516A8A47BBBE739BE793FB635ECDE6928AEF688420A833B54FCA49265473AECA518B64A77A3C020A7667EA76DCCF1F85C567EBBD944808BB175227D828213993E80301";

    protected function setUp()
    {
        $this->keyProvider = new KeyProvider();
        $this->keyAsn1Deserializer = new KeyAsn1Deserializer();
        $this->recipientCipher = new RecipientCipher();
        $this->ed25519 = new Ed25519();
        $this->keyMaterialRng = new KeyMaterialRng();
        $this->rsa = new Rsa();
    }

    protected function tearDown()
    {
        unset($this->rsa);
        unset($this->keyMaterialRng);
        unset($this->ed25519);
        unset($this->recipientCipher);
        unset($this->keyAsn1Deserializer);
        unset($this->keyProvider);
    }

    public function test_KeyProvider_generatePrivateKeyEd25519()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::ED25519());

        $this->assertNotNull($privateKey);

        // TODO!
        $this->assertEquals(AlgId::ED25519(), $privateKey->algId());

        $this->assertEquals(32, $privateKey->len());
    }

    public function test_KeyProvider_generatePrivateKeyEd25519AndThenDoEncryptDecrypt()
    {
        $ed25519 = $this->ed25519;
        $ed25519->setupDefaults();

        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::ED25519());

        $publicKey = $privateKey->extractPublicKey();

        $plainMessage = "test data";
        $encryptedData = $ed25519->encrypt($publicKey, $plainMessage);

        $decryptedData = $ed25519->decrypt($privateKey, $encryptedData);

        // TODO!
        // py: decrypted_data.decode()
        $this->assertEquals($plainMessage, $decryptedData);
    }

    public function test_KeyProvider_generatePrivateKeyEd25519AndThenDoSignHashAndVerifyHash()
    {
        $ed25519 = $this->ed25519;
        $ed25519->setupDefaults();

        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults;

        $privateKey = $keyProvider->generatePrivateKey(AlgId::ED25519());
        $publicKey = $privateKey->extractPublicKey();

        $signature = $ed25519->signHash($privateKey, AlgId::SHA512(), self::unhexlify(self::KEY_PROVIDER_MESSAGE_SHA512_DIGEST));

        $verified = $ed25519->verifyHash($publicKey, AlgId::SHA512(), self::unhexlify(self::KEY_PROVIDER_MESSAGE_SHA512_DIGEST), $signature);

        $this->assertTrue($verified);
    }

    public function test_KeyProvider_generatePrivateKeyEd25519WithKeyMaterialRng()
    {
        $ed25519 = $this->ed25519;
        $ed25519->setupDefaults();

        $keyMaterialRng = $this->keyMaterialRng;
        $keyMaterialRng->resetKeyMaterial(self::unhexlify(self::DETERMINISTIC_KEY_KEY_MATERIAL));

        $keyProvider = $this->keyProvider;
        $keyProvider->setRandom($keyMaterialRng);
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::ED25519());
        $this->assertNotNull($privateKey);

        $exportedPrivateKey = $ed25519->exportPrivateKey($privateKey);

        $this->assertNotNull($exportedPrivateKey);
        $this->assertEquals(self::unhexlify(self::DETERMINISTIC_KEY_ED25519_PRIVATE_KEY), $exportedPrivateKey->data());
    }

    public function test_KeyProvider_generatePrivateKeyRsa2048()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setRsaParams(2048);
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::RSA());

        $this->assertNotNull($privateKey);
        // TODO!
        $this->assertEquals(AlgId::RSA(), $privateKey->algId());
        $this->assertEquals(2048, $privateKey->bitlen());
    }

    public function test_KeyProvider_generatePrivateKeyRsa2048AndThenDoEncryptDecrypt()
    {
        $rsa = $this->rsa;
        $rsa->setupDefaults();

        $keyProvider = $this->keyProvider;
        $keyProvider->setRsaParams(2048);
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::RSA());
        $this->assertNotNull($privateKey);

        $publicKey = $privateKey->extractPublicKey();
        $this->assertNotNull($publicKey);

        $plainMessage = "test data";

        $encryptedData = $rsa->encrypt($publicKey, $plainMessage);
        $decryptedData = $rsa->decrypt($privateKey, $encryptedData);

        // TODO!
        // py: decrypted_data.decode()
        $this->assertEquals($plainMessage, $decryptedData);
    }

    public function test_KeyProvider_generatePrivateKeyRsa2048AndThenDoSignHashAndVerifyHash()
    {
        $rsa = $this->rsa;
        $rsa->setupDefaults();

        $keyProvider = $this->keyProvider;
        $keyProvider->setRsaParams(2048);
        $keyProvider->setupDefauts();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::RSA());
        $this->assertNotNull($privateKey);

        $publicKey = $privateKey->extractPublicKey();
        $this->assertNotNull($publicKey);

        $signature = $rsa->signHash($privateKey, AlgId::SHA512(), self::unhexlify(self::KEY_PROVIDER_MESSAGE_SHA512_DIGEST));

        $verified = $rsa->verifyHash($publicKey, AlgId::SHA512(), self::unhexlify(self::KEY_PROVIDER_MESSAGE_SHA512_DIGEST), $signature);

        $this->assertTrue($verified);
    }

    public function test_KeyProvider_generatePrivateKeyRsa4096WithKeyMaterialRng()
    {
        $rsa = $this->rsa;
        $rsa->setupDefaults();

        $keyMaterialRng = $this->keyMaterialRng;
        $keyMaterialRng->resetKeyMaterial(self::unhexlify(self::DETERMINISTIC_KEY_KEY_MATERIAL));

        $keyProvider = $this->keyProvider;
        $keyProvider->setRandom($keyMaterialRng);
        $keyProvider->setRsaParams(4096);
        $keyProvider->setupDefauls();

        $privateKey = $keyProvider->generatePrivateKey(AlgId::RSA());
        $this->assertNotNull($privateKey);

        $exportedPrivateKey = $rsa->exportPrivateKey($privateKey);
        $this->assertNotNull($exportedPrivateKey);

        $this->assertEquals(self::unhexlify(self::DETERMINISTIC_KEY_RSA4096_PRIVATE_KEY), $exportedPrivateKey->data());
    }

    public function test_KeyProvider_importPublicKeyEd25519AndThenExport()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $publicKey = $keyProvider->importPubliKey(self::unhexlify(self::ED25519_PUBLIC_KEY_PKCS8_DER));
        $this->assertNotNull($publicKey);

        $exportedPublicKey = $keyProvider->exportPublicKey($publicKey);
        $this->assertNotNull($exportedPublicKey);

        $this->assertEquals(self::unhexlify(self::ED25519_PUBLIC_KEY_PKCS8_DER), $exportedPublicKey);
    }

    public function test_KeyProvider_importPublicKeyEd25519FromCorruptedData()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $testData = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";
        // TODO!
        $this->expectException(\Exception::class);
        $keyProvider->importPublicKey($testData);
    }

    public function test_KeyProvider_importPrivateKeyEd25519AndThenExport()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->importPrivateKey(self::unhexlify(self::ED25519_PRIVATE_KEY_PKCS8_DER));
        $this->assertNotNull($privateKey);

        $exportedPrivateKey = $keyProvider->exportPrivateKey($privateKey);
        $this->assertNotNull($exportedPrivateKey);

        $this->assertEquals(self::unhexlify(self::ED25519_PRIVATE_KEY_PKCS8_DER), $exportedPrivateKey);
    }

    public function test_KeyProvider_importPublicKeyRsa2048AndThenExport()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $publicKey = $keyProvider->importPublicKey(self::unhexlify(self::RSA_PCKS8_2048_PUBLIC_KEY_DER));
        $this->assertNotNull($publicKey);

        $exportedPublicKey = $keyProvider->export_publicKey($publicKey);
        $this->assertNotNull($exportedPublicKey);

        $this->assertEquals(self::unhexlify(self::RSA_PCKS8_2048_PUBLIC_KEY_DER), $exportedPublicKey);
    }

    public function test_KeyProvider_importPrivateKeyRsa2048AndThenExport()
    {
        $keyProvider = $this->keyProvider;
        $keyProvider->setupDefaults();

        $privateKey = $keyProvider->importPrivateKey(self::unhexlify(self::RSA_PCKS8_2048_PRIVATE_KEY_DER));
        $this->assertNotNull($privateKey);

        $exportedPrivateKey = $keyProvider->exportPrivateKey($privateKey);
        $this->assertNotNull($exportedPrivateKey);

        $this->assertEquals(self::unhexlify(self::RSA_PCKS8_2048_PRIVATE_KEY_DER), $exportedPrivateKey);
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