const util = require('util');
const initPhe = require('../../phe');

describe('PheServer', () => {
  let phe;
  let pheServer;
  let pheClient;

  beforeEach(async () => {
    phe = await initPhe();
    pheServer = new phe.PheServer();
    pheClient = new phe.PheClient();
    pheServer.setupDefaults();
    pheClient.setupDefaults();
  });

  describe('generateServerKeyPair', () => {
    it('should work', () => {
      const { serverPrivateKey, serverPublicKey } = pheServer.generateServerKeyPair();
      expect(serverPrivateKey).toBeInstanceOf(Uint8Array);
      expect(serverPublicKey).toBeInstanceOf(Uint8Array);
    });
  });

  describe('getEnrollment', () => {
    it('should work', () => {
      const { serverPrivateKey, serverPublicKey } = pheServer.generateServerKeyPair();
      const enrollment = pheServer.getEnrollment(serverPrivateKey, serverPublicKey);
      expect(enrollment).toBeInstanceOf(Uint8Array);
    });
  });

  describe('verifyPassword', () => {
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
      const request = pheClient.createVerifyPasswordRequest(password, enrollmentRecord);
      const response = pheServer.verifyPassword(serverKeyPair.serverPrivateKey, serverKeyPair.serverPublicKey, request);
      expect(response).toBeInstanceOf(Uint8Array);
    });
  });
});
