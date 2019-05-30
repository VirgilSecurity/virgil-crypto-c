const util = require('util');
const initPhe = require('../../phe');

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
      const password = Buffer.from('password');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const data = Buffer.from('data');
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
      const password = Buffer.from('password');
      const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, password);
      const data = Buffer.from('data');
      const encrypted = pheCipher.encrypt(data, accountKey);
      const result = pheCipher.decrypt(encrypted, accountKey);
      expect(Buffer.compare(result, data)).toBe(0);
    });
  });
});
