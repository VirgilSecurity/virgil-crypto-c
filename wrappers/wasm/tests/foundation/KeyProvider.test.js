const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('KeyProvider', () => {
  let foundation;
  let keyProvider;

  beforeEach(async () => {
    foundation = await initFoundation();
    keyProvider = new foundation.KeyProvider();
    keyProvider.setupDefaults();
  });

  afterEach(() => {
    keyProvider.delete();
  });

  describe('generatePrivateKey', () => {
    test('generate private key ed25519', () => {
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      expect(privateKey).toBeInstanceOf(foundation.RawPrivateKey);
      expect(privateKey.algId()).toBe(foundation.AlgId.ED25519);
      expect(privateKey.bitlen()).toBe(256);
      privateKey.delete();
    });

    test('generate private key ed25519 and then do encrypt / decrypt', () => {
      const ed25519 = new foundation.Ed25519();
      ed25519.setupDefaults();
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const publicKey = privateKey.getPublicKey();
      const data = hexToUint8Array('64617461');
      const encrypted = ed25519.encrypt(publicKey, data);
      const decrypted = ed25519.decrypt(privateKey, encrypted);
      expect(decrypted.toString()).toBe(data.toString());
      ed25519.delete();
      privateKey.delete();
      publicKey.delete();
    });

    test('generate private key ed25519 and then do sign hash / verify hash', () => {
      const ed25519 = new foundation.Ed25519();
      ed25519.setupDefaults();
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const publicKey = privateKey.getPublicKey();
      const digest = hexToUint8Array('77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876');
      const signer = new foundation.Signer();
      const hash = new foundation.Sha512();
      const random = new foundation.CtrDrbg();
      random.setupDefaults();
      signer.hash = hash;
      signer.random = random;
      signer.reset();
      signer.appendData(digest);
      const signature = signer.sign(privateKey);
      const verifier = new foundation.Verifier();
      verifier.reset(signature);
      verifier.appendData(digest);
      const verified = verifier.verify(publicKey);
      expect(verified).toBeTruthy();
      ed25519.delete();
      signer.delete();
      hash.delete();
      random.delete();
      verifier.delete();
      privateKey.delete();
      publicKey.delete();
    });

    test('generate private key ed25519 with key material rng', () => {
      const keyMaterialRng = new foundation.KeyMaterialRng();
      const keyMaterial = hexToUint8Array('abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab');
      keyMaterialRng.resetKeyMaterial(keyMaterial);
      keyProvider.random = keyMaterialRng;
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.ED25519);
      const exportedPrivateKey = keyProvider.exportPrivateKey(privateKey);
      const expectedPrivateKey = hexToUint8Array('302e020100300506032b65700422042079f9458b7266a90a9b155b13763559fb6b748d30e38c3d802f6a4a812852750b');
      expect(exportedPrivateKey.toString()).toBe(expectedPrivateKey.toString());
      keyMaterialRng.delete();
      privateKey.delete();
    });

    test('generate private key rsa 2048', () => {
      const bitlen = 2048;
      keyProvider.setRsaParams(bitlen);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      expect(privateKey).toBeInstanceOf(foundation.RsaPrivateKey);
      expect(privateKey.algId()).toBe(foundation.AlgId.RSA);
      expect(privateKey.bitlen()).toBe(bitlen);
      privateKey.delete();
    });

    test('generate private key rsa 2048 and then do encrypt / decrypt', () => {
      keyProvider.setRsaParams(2048);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const publicKey = privateKey.extractPublicKey();
      const recipientId = hexToUint8Array('726563697069656e74');
      const data = hexToUint8Array('64617461');
      const recipientCipher = new foundation.RecipientCipher();
      recipientCipher.addKeyRecipient(recipientId, publicKey);
      recipientCipher.startEncryption();
      const messageInfo = recipientCipher.packMessageInfo();
      const processEncryption = recipientCipher.processEncryption(data);
      const finishEncryption = recipientCipher.finishEncryption();
      const encryptedMessage = new Uint8Array(
        messageInfo.length + processEncryption.length + finishEncryption.length,
      );
      encryptedMessage.set(messageInfo);
      encryptedMessage.set(processEncryption, messageInfo.length);
      encryptedMessage.set(finishEncryption, messageInfo.length + processEncryption.length);
      recipientCipher.startDecryptionWithKey(recipientId, privateKey, new Uint8Array());
      const processDecryption = recipientCipher.processDecryption(encryptedMessage);
      const finishDecryption = recipientCipher.finishDecryption();
      const result = new Uint8Array(processDecryption.length + finishDecryption.length);
      result.set(processDecryption);
      result.set(finishDecryption, processDecryption.length);
      expect(result.toString()).toBe(data.toString());
      recipientCipher.delete();
      privateKey.delete();
      publicKey.delete();
    });

    test('generate private key rsa 2048 and then do sign hash / verify hash', () => {
      keyProvider.setRsaParams(2048);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const publicKey = privateKey.extractPublicKey();
      const digest = hexToUint8Array('77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876');
      const signer = new foundation.Signer();
      const hash = new foundation.Sha512();
      const random = new foundation.CtrDrbg();
      random.setupDefaults();
      signer.hash = hash;
      signer.random = random;
      signer.reset();
      signer.appendData(digest);
      const signature = signer.sign(privateKey);
      const verifier = new foundation.Verifier();
      verifier.reset(signature);
      verifier.appendData(digest);
      const verified = verifier.verify(publicKey);
      expect(verified).toBeTruthy();
      signer.delete();
      hash.delete();
      random.delete();
      verifier.delete();
      privateKey.delete();
      publicKey.delete();
    });

    test('generate private key rsa 4096 with key material rng', () => {
      const keyMaterialRng = new foundation.KeyMaterialRng();
      const keyMaterial = hexToUint8Array('abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab');
      keyMaterialRng.resetKeyMaterial(keyMaterial);
      keyProvider.random = keyMaterialRng;
      keyProvider.setRsaParams(4096);
      const privateKey = keyProvider.generatePrivateKey(foundation.AlgId.RSA);
      const exportedKey = keyProvider.exportPrivateKey(privateKey);
      const expectedKey = hexToUint8Array('30820941020100300d06092a864886f70d01010105000482092b308209270201000282020100d8817a9e8f8f951dbcbfef32d56d0462c17232ed1467d8169e298275c81b027bda778806b8b4accca5ea07f113df220bfc2c32bfd833bf203bbae912264f97ed2b391c67d2db4612eeba060efdab83bbb915a7f54f2043160169ccd1075db240213b080b4c31842a5a27b346a5088786e014e2f0c2c888a4acba6dfa1992156ff94766a7ba7b661a10999ed5b997d27679c5c7878f40ec607ed95aee7e0b25735ade4b72a2c52b0c0322f527a8aebdf5b2cf28a60095f4ed69a169fb2386ae4684cfcb44f0f58c7a5c7008b1b0886b5ec8ebf2f21cdd164e7276e3959342c59d77d18d233508a288efb150b0c0542e7015b6d536ae644bb17be3bfed6927ee4e8cc98ad406e90581ac2aca20979aa9aa36afb500e1756ed0d33173ac6200453dbad3fd8afb6476f2293dba9c8e1024fcc8a5d2d0889befa8f9fef5c39e4b2721e279e138bfa994ce323237d527b647ac28140adda8a502b153b867fc444f7531f87793050981e0bd72470918dd6545c4f8e78b111b9e7f54e2ad0f58dcd7b97e6041de3e37f7f7003695e2ea460b98fb4df3075a9cbc942c297ad3821696df83f8e3d6e40515739093fe37fe382b118e902f31ab51378b9d9dbe176910bf31dc2c3e361d62661122e80544438be892a4a4e50d21e9cc2a1b50554fd76031af431a83415c2aff22f74604ad2f81e40238ce443ab15d39b4b0c728882df8e40e1902030100010282020010eeb36dd2317b0a8bd800f79b4c7ee2d05943955a1ab30235d56e4012e9d5dc64de2353cf3f46226d396bec954ec6a5644ffa9a196916a20939d97f93627731d3c7102b288900a67b682e101f13ba664497e67e5f7558f9d01b7baabf663b0a1bef377656bbaaa7fb4c0e8fd05965ec0cfb65324a318fca3d3e095add8418cc1c9552787cb3a8ed11ee49c7525006e4402ad12b8f6f16ed870e2db7e840abe9a52a2c81672c7f6cdd93eed36eb457e3eedb97c4bfd7fa8354d70c6859436fbed1254532fb9b60a4b33509e107baeb96caa4f567ad0d3770e42fdb25b812294d62f10f16395017121998e70423ce91a12f79909c49b04b61329cc1c66a0a76ef25cf25ac29f521a7f01a68da8666fd78083d0b9147f8c796163dd985a3cd81842785f8843928b752ee1236740e17903ca13473bfc5f257b9447f2d415bd47b7798662d6b9f60b63ea57782c2558f0a24afe35e4850f4fee5f86fd5d1698693818ed935e7357a0bfb118d2967eda975174e8588afa8b0f788d30376dc3dab89e8cbe534685e3111e42d76b9f6e68afc45cfc0c0356720c3cb2e3cbbf0f8e18dc848cb1efeaf6550ba75191590947a332f1244493e0603dee0e2288f6e57afb28ca427226657bad097b96b027bc49603f9fd63b30d967165e50dfc6af596a24ccea63a86beee874b589e5c4e8a71bccb8b2b68696b5aaf57202d47caa487b6f6590282010100ff13f2d6d0810d5015b4892746e6abfd568e1a6661cdbfe47d83edb5d8650d2b1faeb56e7b26725a2d36f368ea37649ba30dc2565d5c04ef02a85a9f0c705a039faa47859a0e8c80622580a18c5759661acb18545db80f4d690c754a46d3b69522989fc700b95c29b82686273b3034748b88fd9e277843c3a9fe287f29256f5cd4274bf7e31465aac8bd458ba5e9e4bbc9a07661a8a5c7a5cb2997c2e13ebf820abd5da4f7729ebe09dcf1354e9597d93d54b30b7e72744fe6325efcc8422dcef5b5b0917c44bb529ab29e3133017e8082de5077aa07e949e07c365cb40fe173d2fc07207067917151b379afa39bcc7ca2a3d0a8d5635fa0d1d3defaaac0ada50282010100d949d5db6ad5c5584880d836f6131ec37da87e647acea37797fc19c79f26a0da23c48236d6c09a801723e547f0e20cd00e3d70634f07cb2e07cc645330bdf140219ba3e61a2d182b43a4842a06bc9eb906dd34619f91ae5756a3f1a250983cc5396cef6020f1ccf7f15b2cf4ed3b7f81f182a742fc82528d92ac0fa574dffc8c3146bbd9f7d12888ae6816d532a146b9d58ea0f297edff25f209b3886d154380a3ef4b216a62eb35b11607cb552de753b4bb00c4dee31d35a41830a610b23f323691c8b9b7df3d767f7b75b5b17e49c21eb207e51609830ca118b57c7da337c5fcd31f4a1322b9a8d4e1338fd654220ed583da7fcc1aab18144c8c6a4da39c65028201004508d81b4d58f00a71a567cd4a8219a039f1c1b15ddcfa875375063bc5f22b6b356aea4d9964e1640882abc40447b3a1efb2449b6d2eff62d47c4df267c26c8a3887344e3350a6b4045c140124e36b1d9838c93fe411718ac8d88751eff352a1f038105e2293081f7e6866bc6d67717aed5cc90f29ad81e18dbb6ca865b16cff59a7bd06bcdd835a8273bf43b946a11235d288d78b763a9f6369c15a0bee1894906589d7a0e4d393a945b3be72a347f29287bee1687a7f82345203a53469bcce1b6fedf6a20454125a2de76477627b233ac8024d30a66d7c02167bfc00fb9f4fe2953534915766649df10e08fc25a9653dfb49f8b7afea6cb2fd3d86e7f9b7c50282010000a1442b74add5faa18b2e154ab5577b7d9bc57209211c3c368696948b939317cecebd09e7a97b492fc7fcdc2e88993ce92da86bc148e67fe5a9e40891b59b4372557f2e259947dea83d8bdc8b5474a958a9bf8320f14d2e17a43609206eb08e69d235077450ff2520e000cb5cfcb52bed4551b2d20496b4ae5e2d556f774ec621467138fa8cf2af22c24e7ea3bceff58df6f1e48228407b1dae8584b9bc3c0bdd6dce2bf4a100c9910fdd49eb9f4c7263adbf1cd300998f1440b5b3658cfebde88697ac622a1585886d153447a5741549fd7e245de1fd2d46324a246840d6e28e0f16a22258116db9e04543ff7d12f4340e43cde70b94bf671fa9b08d3512390282010038937d87c46679d4c3d35c9c0c00d3118cc6a65eca004d8c035e807a42f9b647daf65029102d080bb48090f685c189e15dffc4dbc19ac859310cbc857a67295c63defe3c80164ebd528eeec11d1152d81d7cc7f9ae6be75b8f5de28a698f942ad130fe35b1e08e20f4d7da3eced899e3e4aaf536d26efaf92ba5a1f8ed42587fd67498ed7501cf577cf49a671ca677a3914d28475e2be60c833d56d6e16130702a1edd3ef15902df49849fdfbe57a3c2a5cd494d5c6a959f285ba121a72f6e94f8587080cda1816b2b8d57491e9ff3272bfcae053df80b022d15866f788f16659dcecfc7893106d455113c3ff42f2f4392c8344cb30c8c9fc2ad83553ddbb7d2');
      expect(exportedKey.toString()).toBe(expectedKey.toString());
      keyMaterialRng.delete();
      privateKey.delete();
    });
  });

  describe('importPublicKey / exportPublicKey', () => {
    test('ed25519', () => {
      const publicKeyBuffer = hexToUint8Array('302a300506032b657003210060a3c1fe1cf6aa6bf6b184f38e7b2045b047eb1aabe06063fd025b869625bf7a');
      const publicKey = keyProvider.importPublicKey(publicKeyBuffer);
      const exportedKey = keyProvider.exportPublicKey(publicKey);
      expect(exportedKey.toString()).toBe(publicKeyBuffer.toString());
      publicKey.delete();
    });

    test('rsa', () => {
      const publicKeyBuffer = hexToUint8Array('30820122300d06092a864886f70d01010105000382010f003082010a0282010100c73f6fd32119925e9fe5422ae4b2725b2ee5f32fee0d11680105128f3051ed98537504b58150a303919f25240873a78ca7dd93022c88b8a9a7345aec80f785da19e5de970e21ee42bd8fe4a0c4d2f00770695ef6da03b4397cf85ce45aed38a2933a26654076a7ffbef7f0a9974ad86441e37d0becd7abe679cc3611e604f48c8f5c46fb03c42f57cbba31d36981c58592ce5cf5c6544d349530ba8451a2154775b71413897c36ca3ff4f38cb538f4b22bd0fb7b315ca1de1858ed0e860aa6748bf3e97b62707d0407eeac7d521fcd50251fc2088b7122a379d3c7aec7eac9fa06585723d9daf0e59e900fbea715aa32d32aa5bfaab36bcc0772e93a62d1af0d0203010001');
      const publicKey = keyProvider.importPublicKey(publicKeyBuffer);
      const exportedKey = keyProvider.exportPublicKey(publicKey);
      expect(exportedKey.toString()).toBe(publicKeyBuffer.toString());
      publicKey.delete();
    });
  });

  describe('importPrivateKey / exportPrivateKey', () => {
    test('ed25519', () => {
      const privateKeyBuffer = hexToUint8Array('302e020100300506032b65700422042032c7e266734c044dc5ffa809167f3011dc73de2d908a932e40c7341d8bbe2f35');
      const privateKey = keyProvider.importPrivateKey(privateKeyBuffer);
      const exportedKey = keyProvider.exportPrivateKey(privateKey);
      expect(exportedKey.toString()).toBe(privateKeyBuffer.toString());
      privateKey.delete();
    });

    test('rsa', () => {
      const privateKeyBuffer = hexToUint8Array('308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100c73f6fd32119925e9fe5422ae4b2725b2ee5f32fee0d11680105128f3051ed98537504b58150a303919f25240873a78ca7dd93022c88b8a9a7345aec80f785da19e5de970e21ee42bd8fe4a0c4d2f00770695ef6da03b4397cf85ce45aed38a2933a26654076a7ffbef7f0a9974ad86441e37d0becd7abe679cc3611e604f48c8f5c46fb03c42f57cbba31d36981c58592ce5cf5c6544d349530ba8451a2154775b71413897c36ca3ff4f38cb538f4b22bd0fb7b315ca1de1858ed0e860aa6748bf3e97b62707d0407eeac7d521fcd50251fc2088b7122a379d3c7aec7eac9fa06585723d9daf0e59e900fbea715aa32d32aa5bfaab36bcc0772e93a62d1af0d02030100010282010021e28a787bfd16d4ebd977e6c68d0880b4599c018f38feb852d01387717ec56aedea8d39f6fb89359eaad38cacb94a89d3b48d7f45a69ccd1168087c87345139b5c4cf959dec2c52825d79d2d3965206d9d9b9b23e8279c07b1ddbe2640a4ae2ef29e904b83155c1db2edc696316f1f51ef57abb2ff4bfc1cafded461ef9c1c2e6f0ebb54045d4d6d829d9bfdc5746ce1a40125f255ee68aa9f8b7bfd27deb8ad0b782cd9645baea7e6b21ad2e249b3cec45a75a2721f0ecbf8c7ea9b3539ff1d917dda1039efdae500600a0db3088197079a3b9e527ecd3d4ae9b55791530dd572670d835c725081d261c56b4805436b53dbd95b626741bb15c18de6267006b02818100ea91b9db8404ee696de6751a0406ab2baf75d24bf7d52b1c45cb3186f7006816032d44077a33a0560960e98f631a8675b861906ea4c220c81b5b9e46dea03d4c394ba78d64a826c7593d06e169232de173e8966dd40814c4cc7157c44086007c6349205d26220614e5bc8adf83f5ebaa3936ee7c32e2c884d3482e1c0ffb45ef02818100d9739668f72c0b16841f8f409cc09d6ffe8f5d9ad348d921fad0fa8629ade23c04c61dfa76ba6dc557db7b4cabc86d1f18aeeca1f07b4fa706aa50f22b6ef9b0a47aa5cd1df92f4f2aecf00b03d12ba2a27d999135c437d9e357057120ecf59ff3c115d8c69839b23421333e8dc1a2bd88c5bf62582607c0956f0032a80536c302818068765170e3105724789f03537cab839b46de8fb2e941f39af9b20df26f19ad40f0553e509e2953a43d34fd8eafb1e66392a3507115caa652b76c4bc67fea98a1d37a4fb9f633b4615eea809fedf48ec032a0482dcd197436585db99a5aa9d2999295c465f74f7ba9decde282bbffceddd5f112b018f14a1f6d005e187d3d87dd02818100d89cb00437d483e7160e6a212f0520cfe380e4f9c9e7138529d8eaf6a2a6386b194651aea27eebc25dd6a168aae6a8ed05259b4b65c7307d6dc2538829840eeecba9f167f6a7b75ce1a1cd2cebcc7def30767577955bb55733840843bd4ccf115b3bc88b7ca93f302985b90a6323b4fda1357b8477d2ca7e295dbd90b89719090281803113295063fb431954b56710ee2cef6feb55465c432b709009c9bb7df189cc2b24ae6e4bd4fc46301145ccb6dd8bed3e55caeece8e45d467baeba576cbb47dae2c3f4893c4c041c1a97f8e92ce94732bb4984b9a16b2d13831a1ba0b808c9772f39072d6c3a31a2cb16d53853b93d536876640f7a56d302be73998ae170b4ee7');
      const privateKey = keyProvider.importPrivateKey(privateKeyBuffer);
      const exportedKey = keyProvider.exportPrivateKey(privateKey);
      expect(exportedKey.toString()).toBe(privateKeyBuffer.toString());
      privateKey.delete();
    });
  });
});
