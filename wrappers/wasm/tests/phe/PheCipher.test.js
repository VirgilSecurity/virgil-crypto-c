const initPhe = require('../../dist/phe/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('PheCipher', () => {
  let phe;
  let pheCipher;
  let pheClient;
  let pheServer;

  beforeEach(async () => {
    phe = await initPhe();
    pheCipher = new phe.PheCipher();
    pheClient = new phe.PheClient();
    pheServer = new phe.PheServer();
    pheCipher.setupDefaults();
    pheClient.setupDefaults();
    pheServer.setupDefaults();
  });

  describe('encrypt', () => {
    it('should work', () => {
      const serverKeyPair = pheServer.generateServerKeyPair();
      const clientKeyPair = pheServer.generateServerKeyPair();
      pheClient.setKeys(clientKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey);
      const enrollment = pheServer.getEnrollment(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
      );
      const password = hexToUint8Array('70617373776f7264');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const data = hexToUint8Array('64617461');
      const result = pheCipher.encrypt(data, accountKey);
      expect(result).toBeInstanceOf(Uint8Array);
    });
  });

  describe('decrypt', () => {
    it('should work', () => {
      const serverKeyPair = pheServer.generateServerKeyPair();
      const clientKeyPair = pheServer.generateServerKeyPair();
      pheClient.setKeys(clientKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey);
      const enrollment = pheServer.getEnrollment(
        serverKeyPair.serverPrivateKey,
        serverKeyPair.serverPublicKey,
      );
      const password = hexToUint8Array('70617373776f7264');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const data = hexToUint8Array('64617461');
      const encrypted = pheCipher.encrypt(data, accountKey);
      const result = pheCipher.decrypt(encrypted, accountKey);
      expect(result.toString()).toBe(data.toString());
    });
  });
});
