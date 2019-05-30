const initFoundation = require('../../foundation');

describe('KeyProvider', () => {
  let foundation;
  let keyProvider;

  beforeEach(async () => {
    foundation = await initFoundation();
    keyProvider = new foundation.KeyProvider();
    keyProvider.setupDefaults();
  });

  describe('generatePrivateKey', () => {
    test('generate private key ed25519', () => {
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      expect(privateKey).toBeInstanceOf(foundation.Ed25519PrivateKey);
      expect(privateKey.algId()).toBe(foundation.AlgId.ED25519);
      expect(privateKey.keyBitlen()).toBe(256);
    });

    test('generate private key ed25519 and then do encrypt / decrypt', () => {
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const publicKey = privateKey.extractPublicKey();
      const data = Buffer.from('data');
      const encrypted = publicKey.encrypt(data);
      const decrypted = privateKey.decrypt(encrypted);
      expect(Buffer.compare(decrypted, data)).toBe(0);
    });

    test('generate private key ed25519 and then do sign hash / verify hash', () => {
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const publicKey = privateKey.extractPublicKey();
      const digest = Buffer.from(
        '6d49d5e34ad7a0359fb00628aacd41da3c62341ef204008ea87d40729aa5fbd81cc1809762a8051185264db094044ef8e12c4b27781de558f397daa2078c568d',
        'hex',
      );
      const signature = privateKey.signHash(digest, foundation.AlgId.SHA512);
      const verified = publicKey.verifyHash(digest, foundation.AlgId.SHA512, signature);
      expect(verified).toBeTruthy();
    });

    test('generate private key ed25519 with key material rng', () => {
      const keyMaterialRng = new foundation.KeyMaterialRng();
      const keyMaterial = Buffer.from(
        'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
        'hex',
      );
      keyMaterialRng.resetKeyMaterial(keyMaterial);
      keyProvider.random = keyMaterialRng;
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const exportedPrivateKey = privateKey.exportPrivateKey();
      const expectedPrivateKey = Buffer.from(
        '79f9458b7266a90a9b155b13763559fb6b748d30e38c3d802f6a4a812852750b',
        'hex',
      );
      expect(Buffer.compare(exportedPrivateKey, expectedPrivateKey)).toBe(0);
    });

    test('generate private key rsa 2048', () => {
      const bitlen = 2048;
      keyProvider.setRsaParams(bitlen);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      expect(privateKey).toBeInstanceOf(foundation.RsaPrivateKey);
      expect(privateKey.algId()).toBe(foundation.AlgId.RSA);
      expect(privateKey.keyBitlen()).toBe(bitlen);
    });

    test('generate private key rsa 2048 and then do encrypt / decrypt', () => {
      keyProvider.setRsaParams(2048);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const publicKey = privateKey.extractPublicKey();
      const data = Buffer.from('data');
      const encrypted = publicKey.encrypt(data);
      const decrypted = privateKey.decrypt(encrypted);
      expect(Buffer.compare(decrypted, data)).toBe(0);
    });

    test('generate private key rsa 2048 and then do sign hash / verify hash', () => {
      keyProvider.setRsaParams(2048);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const publicKey = privateKey.extractPublicKey();
      const digest = Buffer.from(
        '6d49d5e34ad7a0359fb00628aacd41da3c62341ef204008ea87d40729aa5fbd81cc1809762a8051185264db094044ef8e12c4b27781de558f397daa2078c568d',
        'hex',
      );
      const signature = privateKey.signHash(digest, foundation.AlgId.SHA512);
      const verified = publicKey.verifyHash(digest, foundation.AlgId.SHA512, signature);
      expect(verified).toBeTruthy();
    });

    test('generate private key rsa 4096 with key material rng', () => {
      const keyMaterialRng = new foundation.KeyMaterialRng();
      const keyMaterial = Buffer.from(
        'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
        'hex',
      );
      keyMaterialRng.resetKeyMaterial(keyMaterial);
      keyProvider.random = keyMaterialRng;
      keyProvider.setRsaParams(4096);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const exportedKey = privateKey.exportPrivateKey();
      const expectedKey = Buffer.from(
        '308209270201000282020100d8817a9e8f8f951dbcbfef32d56d0462c17232ed1467d8169e298275c81b027bda778806b8b4accca5ea07f113df220bfc2c32bfd833bf203bbae912264f97ed2b391c67d2db4612eeba060efdab83bbb915a7f54f2043160169ccd1075db240213b080b4c31842a5a27b346a5088786e014e2f0c2c888a4acba6dfa1992156ff94766a7ba7b661a10999ed5b997d27679c5c7878f40ec607ed95aee7e0b25735ade4b72a2c52b0c0322f527a8aebdf5b2cf28a60095f4ed69a169fb2386ae4684cfcb44f0f58c7a5c7008b1b0886b5ec8ebf2f21cdd164e7276e3959342c59d77d18d233508a288efb150b0c0542e7015b6d536ae644bb17be3bfed6927ee4e8cc98ad406e90581ac2aca20979aa9aa36afb500e1756ed0d33173ac6200453dbad3fd8afb6476f2293dba9c8e1024fcc8a5d2d0889befa8f9fef5c39e4b2721e279e138bfa994ce323237d527b647ac28140adda8a502b153b867fc444f7531f87793050981e0bd72470918dd6545c4f8e78b111b9e7f54e2ad0f58dcd7b97e6041de3e37f7f7003695e2ea460b98fb4df3075a9cbc942c297ad3821696df83f8e3d6e40515739093fe37fe382b118e902f31ab51378b9d9dbe176910bf31dc2c3e361d62661122e80544438be892a4a4e50d21e9cc2a1b50554fd76031af431a83415c2aff22f74604ad2f81e40238ce443ab15d39b4b0c728882df8e40e1902030100010282020010eeb36dd2317b0a8bd800f79b4c7ee2d05943955a1ab30235d56e4012e9d5dc64de2353cf3f46226d396bec954ec6a5644ffa9a196916a20939d97f93627731d3c7102b288900a67b682e101f13ba664497e67e5f7558f9d01b7baabf663b0a1bef377656bbaaa7fb4c0e8fd05965ec0cfb65324a318fca3d3e095add8418cc1c9552787cb3a8ed11ee49c7525006e4402ad12b8f6f16ed870e2db7e840abe9a52a2c81672c7f6cdd93eed36eb457e3eedb97c4bfd7fa8354d70c6859436fbed1254532fb9b60a4b33509e107baeb96caa4f567ad0d3770e42fdb25b812294d62f10f16395017121998e70423ce91a12f79909c49b04b61329cc1c66a0a76ef25cf25ac29f521a7f01a68da8666fd78083d0b9147f8c796163dd985a3cd81842785f8843928b752ee1236740e17903ca13473bfc5f257b9447f2d415bd47b7798662d6b9f60b63ea57782c2558f0a24afe35e4850f4fee5f86fd5d1698693818ed935e7357a0bfb118d2967eda975174e8588afa8b0f788d30376dc3dab89e8cbe534685e3111e42d76b9f6e68afc45cfc0c0356720c3cb2e3cbbf0f8e18dc848cb1efeaf6550ba75191590947a332f1244493e0603dee0e2288f6e57afb28ca427226657bad097b96b027bc49603f9fd63b30d967165e50dfc6af596a24ccea63a86beee874b589e5c4e8a71bccb8b2b68696b5aaf57202d47caa487b6f6590282010100ff13f2d6d0810d5015b4892746e6abfd568e1a6661cdbfe47d83edb5d8650d2b1faeb56e7b26725a2d36f368ea37649ba30dc2565d5c04ef02a85a9f0c705a039faa47859a0e8c80622580a18c5759661acb18545db80f4d690c754a46d3b69522989fc700b95c29b82686273b3034748b88fd9e277843c3a9fe287f29256f5cd4274bf7e31465aac8bd458ba5e9e4bbc9a07661a8a5c7a5cb2997c2e13ebf820abd5da4f7729ebe09dcf1354e9597d93d54b30b7e72744fe6325efcc8422dcef5b5b0917c44bb529ab29e3133017e8082de5077aa07e949e07c365cb40fe173d2fc07207067917151b379afa39bcc7ca2a3d0a8d5635fa0d1d3defaaac0ada50282010100d949d5db6ad5c5584880d836f6131ec37da87e647acea37797fc19c79f26a0da23c48236d6c09a801723e547f0e20cd00e3d70634f07cb2e07cc645330bdf140219ba3e61a2d182b43a4842a06bc9eb906dd34619f91ae5756a3f1a250983cc5396cef6020f1ccf7f15b2cf4ed3b7f81f182a742fc82528d92ac0fa574dffc8c3146bbd9f7d12888ae6816d532a146b9d58ea0f297edff25f209b3886d154380a3ef4b216a62eb35b11607cb552de753b4bb00c4dee31d35a41830a610b23f323691c8b9b7df3d767f7b75b5b17e49c21eb207e51609830ca118b57c7da337c5fcd31f4a1322b9a8d4e1338fd654220ed583da7fcc1aab18144c8c6a4da39c65028201004508d81b4d58f00a71a567cd4a8219a039f1c1b15ddcfa875375063bc5f22b6b356aea4d9964e1640882abc40447b3a1efb2449b6d2eff62d47c4df267c26c8a3887344e3350a6b4045c140124e36b1d9838c93fe411718ac8d88751eff352a1f038105e2293081f7e6866bc6d67717aed5cc90f29ad81e18dbb6ca865b16cff59a7bd06bcdd835a8273bf43b946a11235d288d78b763a9f6369c15a0bee1894906589d7a0e4d393a945b3be72a347f29287bee1687a7f82345203a53469bcce1b6fedf6a20454125a2de76477627b233ac8024d30a66d7c02167bfc00fb9f4fe2953534915766649df10e08fc25a9653dfb49f8b7afea6cb2fd3d86e7f9b7c50282010000a1442b74add5faa18b2e154ab5577b7d9bc57209211c3c368696948b939317cecebd09e7a97b492fc7fcdc2e88993ce92da86bc148e67fe5a9e40891b59b4372557f2e259947dea83d8bdc8b5474a958a9bf8320f14d2e17a43609206eb08e69d235077450ff2520e000cb5cfcb52bed4551b2d20496b4ae5e2d556f774ec621467138fa8cf2af22c24e7ea3bceff58df6f1e48228407b1dae8584b9bc3c0bdd6dce2bf4a100c9910fdd49eb9f4c7263adbf1cd300998f1440b5b3658cfebde88697ac622a1585886d153447a5741549fd7e245de1fd2d46324a246840d6e28e0f16a22258116db9e04543ff7d12f4340e43cde70b94bf671fa9b08d3512390282010038937d87c46679d4c3d35c9c0c00d3118cc6a65eca004d8c035e807a42f9b647daf65029102d080bb48090f685c189e15dffc4dbc19ac859310cbc857a67295c63defe3c80164ebd528eeec11d1152d81d7cc7f9ae6be75b8f5de28a698f942ad130fe35b1e08e20f4d7da3eced899e3e4aaf536d26efaf92ba5a1f8ed42587fd67498ed7501cf577cf49a671ca677a3914d28475e2be60c833d56d6e16130702a1edd3ef15902df49849fdfbe57a3c2a5cd494d5c6a959f285ba121a72f6e94f8587080cda1816b2b8d57491e9ff3272bfcae053df80b022d15866f788f16659dcecfc7893106d455113c3ff42f2f4392c8344cb30c8c9fc2ad83553ddbb7d2',
        'hex',
      );
      expect(Buffer.compare(exportedKey, expectedKey)).toBe(0);
    });
  });

  describe('importPublicKey / exportPublicKey', () => {
    test('ed25519', () => {
      const publicKeyBuffer = Buffer.from(
        '302a300506032b6570032100e7349dd5eb23233766f3192e2d9d4d26d8a2671d71e8aed48053b47f55f47032',
        'hex',
      );
      const publicKey = keyProvider.importPublicKey(publicKeyBuffer);
      const exportedKey = keyProvider.exportPublicKey(publicKey);
      expect(Buffer.compare(exportedKey, publicKeyBuffer)).toBe(0);
    });

    test('rsa', () => {
      const publicKeyBuffer = Buffer.from(
        '30820121300d06092a864886f70d01010105000382010e003082010902820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb0203010001',
        'hex',
      );
      const publicKey = keyProvider.importPublicKey(publicKeyBuffer);
      const exportedKey = keyProvider.exportPublicKey(publicKey);
      expect(Buffer.compare(exportedKey, privateKeyBuffer)).toBe(0);
    });
  });

  describe('importPrivateKey / exportPrivateKey', () => {
    test('ed25519', () => {
      const privateKeyBuffer = Buffer.from(
        '302e020100300506032b6570042204204d43344341514177425159444b32567742434945494573434c484e506358502b',
        'hex',
      );
      const privateKey = keyProvider.importPrivateKey(privateKeyBuffer);
      const exportedKey = keyProvider.exportPrivateKey(privateKey);
      expect(Buffer.compare(exportedKey, privateKeyBuffer)).toBe(0);
    });

    test('rsa', () => {
      const privateKeyBuffer = Buffer.from(
        '308204bc020100300d06092a864886f70d0101010500048204a6308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      )
      const privateKey = keyProvider.importPrivateKey(privateKeyBuffer);
      const exportedKey = keyProvider.exportPrivateKey(privateKey);
      expect(Buffer.compare(exportedKey, privateKeyBuffer)).toBe(0);
    });
  });
});
