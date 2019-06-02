const initFoundation = require('../../foundation');

describe('RsaPrivateKey', () => {
  let foundation;
  let rsaPrivateKey;

  beforeEach(async () => {
    foundation = await initFoundation();
    rsaPrivateKey = new foundation.RsaPrivateKey();
    rsaPrivateKey.setupDefaults();
  });

  describe('keyLen', () => {
    it('should work', () => {
      const privateKey = Buffer.from(
        '308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      );
      rsaPrivateKey.importPrivateKey(privateKey);
      const keyLen = rsaPrivateKey.keyLen();
      expect(keyLen).toBe(256);
    });
  });

  describe('exportPrivateKey', () => {
    it('should work', () => {
      const privateKey = Buffer.from(
        '308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      );
      rsaPrivateKey.importPrivateKey(privateKey);
      const result = rsaPrivateKey.exportPrivateKey();
      expect(Buffer.compare(result, privateKey)).toBe(0);
    });
  });

  describe('decrypt', () => {
    it('should work', () => {
      const fakeRandom = new foundation.FakeRandom();
      fakeRandom.setupSourceByte(0xab);
      rsaPrivateKey.random = fakeRandom;
      const privateKey = Buffer.from(
        '308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      );
      rsaPrivateKey.importPrivateKey(privateKey);
      const data = Buffer.from(
        '39cffa1dcae1f3145000d9a73e14ac5e8e80e6c37e64910fea4f858e2d3a1d5c1f324ebee77ba8f67f843d466c890e2d57e08dc90efe279788b957b39d3520f0953d0810d98b23d3e4a91a0f011cb1422bcf090ae987fe6fe77f68db46dfca838be3784339372bd4d703196408d56980570b401c37e29d01b4f93924ee2ead079234507cd3c470629d2b0442d62877ea3ab9e31e15459cc22b8c212437a52036d5d63f6a011c7fde16753d9393a208f6c302323c4e636a92c830c7e43fc80848b9b1b70b7b6be4df7ea1f176c50c8e19c7c6d102ff8bd8a0baa356df8ec8c00d2f479922088d735dbc175bee38748f86adff514066492ccac241bfaf3ff189e6',
        'hex',
      );
      const decrypedData = rsaPrivateKey.decrypt(data);
      const expectedResult = Buffer.from('456e6372797074206d6521', 'hex');
      expect(Buffer.compare(decrypedData, expectedResult)).toBe(0);
    });
  });

  describe('extractPublicKey', () => {
    it('should work', () => {
      const privateKey = Buffer.from(
        '308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      );
      rsaPrivateKey.importPrivateKey(privateKey);
      const publicKey = rsaPrivateKey.extractPublicKey();
      const key = publicKey.exportPublicKey();
      const expectedKey = Buffer.from(
        '3082010902820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb0203010001',
        'hex',
      );
      expect(publicKey).toBeInstanceOf(foundation.RsaPublicKey);
      expect(Buffer.compare(key, expectedKey)).toBe(0);
    });
  });

  describe('signHash', () => {
    it('should work', () => {
      const fakeRandom = new foundation.FakeRandom();
      fakeRandom.setupSourceByte(0xab);
      rsaPrivateKey.random = fakeRandom;
      const privateKey = Buffer.from(
        '308204a202010002820100537cc7e8fb4b0975739f3ff613d01a98d5039eb859c0fd8b01df72a63673efad121c33746f2a1c1be43999cfc545fab897569131ae7eb76013e87ac32707a9c910f13aa798cfa05e78711b716bb5c8f3a70badd37e9375acf752c1d096a9efbaed8484721e9ebb0865fd0c5547094617d713f86f92a32f43d6fd3b52d5855c7384504aad7fdf95ceffef806aed6b75ebd650b733eeeeea53479ef38f59c5f68290724a62edd013dbb6eea566fd5cb44e7acdc027e48f7db620de7ecab187c314987bade4cbe1d19dd43b0c86eff900eb4ee1f793e8d033d9459b146aaff9971dc1c727408e9722a91d27ae3bb3151e97aec7f3605622a0e38b8bb4ea46e610eb02030100010282010048a0a077f943c9b2b726ae49afeab57886b6637913fb63956dc7a8c11755bc06df5e5114d52fd8cc1aba51280201629efa68805eabe1e83c589541564bb9cae5f32b274f6d0c12029cdc28777eafe164b4c8e02ac04e1f6c9cab0d981bb931a777c07447a2838b493f0fe78eb801454caff9db81941b099f0683bcfbce6bf984347fc0f3b693a4a355687fd464aa7289d34c5b866895dd41aabb54d0b340747567469ceaa36f3920df1c393c9b8fca824e2be741a094d792259d5cb71a981eed7127181e61b9147f2573982d7a31c705b089c3881dd285ab0e8dc775249ce3afccc19ce1fba4676b84dd79057aa2b0e872a5eec98357e31b0b58dccbf601d22102818100a379b8fdb31d795325613b14722c91c2df5b4b1d7968fa1803dc574493f0727afea82a1a83763532b4a4484971d7898a179baff921996c74dd920b5a011957451c3c5ee0178a0e5b5673c56d560ec54fcb1e18d6a8bd0b1215f020cb1def12db0325f9337f4039a79fcaae335e069423675a000f1f7337fc861f0a246355a0dd0281810082bd6f58f121e6c8dca3d62c2079ae7dadd8d9f18c678a36e1d97eba58d7392d5c641b23ef4f172ef645027f6df8ead0ebda154b723b98212dd1bf7c4b90aa8aad06feabeeaa3f8cbbe02eb8d0e5b819356bce6c0f559e259ff4ff11c45bea46dfabf7983d059ab6ae28c2bc64e5d3335e96b2a446371cf31917a370f02a38670281807021791383fdae8faaaf23d025748ed2c5542094ea0768ac7a517406951733df4bb7db916e24f1de82ebc0ada809b8cce0dea878d164247190ddb12d9e5d5c700a2b1ac4c940a8125c9d728949a33e123a77bd7fd8243b68bf658388ef52627399983d73e6500e7bfcee104929b08782354d15874a02451fd07b90005fa6877d0281804a9f93d1a178e74098e78f148ac8c97704e6b4a771ab9bb16dc1f5daa960d74af3e453b5741fa1acf5763851c1d4853b1093def9bc4f15ab427ae9202a057dc23fb6b160338ecb4d29e370e79e9cb032fb51f875a75f08309397848b8097b22617ff1108bd33d8b612bc4342c318872f57fb0e2643c9ab657a5a0ab928ec005b02818100946945f81bd813fd29f99da0ee71d994cc3025fc781ac9a31d734951a5d765c9a3f76d35a518b6804e5c7a1cc95c2df4defc6900850a2c8badec1c1aa4516a8a47bbbe739be793fb635ecde6928aef688420a833b54fca49265473aeca518b64a77a3c020a7667ea76dccf1f85c567ebbd944808bb175227d828213993e80301',
        'hex',
      );
      rsaPrivateKey.importPrivateKey(privateKey);
      const digest = Buffer.from(
        '6d49d5e34ad7a0359fb00628aacd41da3c62341ef204008ea87d40729aa5fbd81cc1809762a8051185264db094044ef8e12c4b27781de558f397daa2078c568d',
        'hex',
      );
      const signature = rsaPrivateKey.signHash(digest, foundation.AlgId.SHA512);
      const expectedSignature = Buffer.from(
        '0a14d169396162c906e5d815a42238a68614218d204f5843177143e64794e679ed90dffca3fc6fc62d44315c1483005501e48e8e858e397fcb5399087e1bd49eaed94d4f2c1c83c8b7d4e1d3cf847f2f74dd662225572e742d17bf4637a0947ba4b672b173b7d05826daf1dd9ae9736ff65c2f4a8e67cff91f5b1413a6e3d9c8290f80b2379d2114e751fa1dcb0f8fb8a688db6130cd04ea3069cac6e5747cc2965e6107e82af0ca199db752ccd6d2089c783a4aaddbeef3c56c4406c85be3a5b2741c9a287b075abd529337e18b4b95e72d3fc4ce26234b77ef9ef3a635ba08ffaa4cc052ff676d46a9976d9751c01e27dcfb23be29aa8c9cc2cb47da8b5418',
        'hex',
      );
      expect(Buffer.compare(signature, expectedSignature)).toBe(0);
    });
  });

  describe('generateKey', () => {
    it('should work', () => {
      const keyMaterialRng = new foundation.KeyMaterialRng();
      const keyMaterial = Buffer.from(
        '77fa8f446f07587127700998742ba4c8e60bac5ef52e5326c7f928cc2a80ebe0',
        'hex',
      );
      keyMaterialRng.resetKeyMaterial(keyMaterial);
      rsaPrivateKey.random = keyMaterialRng;
      rsaPrivateKey.setKeygenParams(2048);
      rsaPrivateKey.generateKey();
      const key = rsaPrivateKey.exportPrivateKey();
      const expectedKey = Buffer.from(
        '308204a40201000282010100e3dbc3c888842df8bf63bcefb40c2e9db528a883d8dac65ac0e72074b21a500104a81bb5fcb4c115ae330e2161b9c2f655416e4b256812c6c770839ce5e02722b2775c591befa090be7a7059b09608ab90e2ee796434c326eb2c98243a980dc66310eda8791df01f84b9799befe9cb45107afba9d2ebd4086067bced0110ec99ff4882fa485f22122bb09fccfac8c579ad1b787e6282913b7ec72db7b5df0a27f4a3353b6a3b57b46932b277c08aef43cc4708a4f551fedc7844d35ac442494d1a3fd805b4d9967d864d88a18e54e73792b321e1b9370d6ec83d3a98963af3508c41c0d8fe64053131416f461566966391575e8d7fe57ddfd6ce50bf4decd88f0203010001028201006cf58b32daad327a8fb2f7073cf6d257d1e84664fe0ee7e93ff3861ea7885397990d766ad913ea7d1e97057bcb0a94834d1383d56566d60bbe153caa8b765be088acf1391f55c05756ee9fc913db3afc27c58cb9f9c40d4a100d7c175ef99524b7fcc158ddca06285c448135a34d0e49d16eade770981b05826c38f8b098d23a8eb04e6610961fb933ddc7b9647cf6a5b146e5b412504c6e42913f67aba23866f10936a5c53db1fbb2abd4e2255b56b8290c5b2be385c5ca077c931fffd4778931fe8a35decd07ad79d7e07cbed4d1489ea91ed4c74be50613b2808e3ffbd2467475b701ed54be6a5efd05df7bccdd80d74fd5c563f308cc8cb016565429ba4902818100f96d727b9ad54d11a8885804f86e80e63d08a362a28a0c9ff27050d3b118303533678e28fdba2687f3a2de2b9d9076d6b441d0ccd49201df45f3af599deccaae3313ce70c666bd26a1d36388369c013efc2d23f48d18bc86c4ee55d05780d04ed309e66b9deefb230b20193425c527ccfd13bcff447bcfeb6b2d5579309cc59b02818100e9dcd1eb56a990a6ca50ba267caf475f58ac69bb0a432c95bd80b625a55de8465fe4a238496eb66b3b09645210af44b6c718bf6f61fae60b70c958c513c5525524a6ef3399d2439a34efb0b8dbefd2ef2fac486d17fc3366abe3ca9434add0f0fce93dde41fd90bfa4e3b231636b68df5b1e4c9d80717daa235ced771f71c21d028181009728b9f9a8a2dddaf6bcf242c8e0072401170c154995ca02e0e52a46b08b8d23a0ac805ddd2e840d5e1c74f20fc22e12fe18e8d64978d6c39ddc0987910aa0e623343ca6e1c5ff99baf6a5da35e623672d6299e8a9ddb4db23dba08beb8bb8321cf961f8143571631269f87c3eeb95ac482f3f19a0423c865a6495e92509cd4302818100d1879555039a7d0dd32aacfe1aac788806ccc3165fc57bc6d5b8e279ac460cfc30a28a6d5fed9fe74747cce8722676ac4489f9caf3c076283def48679aa52a753a978ead6ede22cfa12a37ee08b0410f286975a2b8e0afb507c0da1a1b70b849926fef8c9917747f205f19a2826f13d13ab454f4b0c5fe4f57cbc4befc1f5249028180108e25d85152c4b419d5b9ee1ab2b3986e9042c1433d00977f77fc5d3ca600976676c3e115fa4d9e33565e0dcb1873ccae6550131c666d4a4b4f5d8b9559613ad88060e7a967a7d8119659018cdf312c79791c8fec5e879108272b40e6aef18f8f011a1df897f0c8e1b0224421efc79fe62a59ece4d3f59133cbc24e9d44cbd4',
        'hex',
      );
      expect(Buffer.compare(key, expectedKey)).toBe(0);
    });
  });
});