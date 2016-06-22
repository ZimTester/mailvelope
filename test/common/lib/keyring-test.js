'use strict';

define(function(require) {

  var Keyring = require('common/lib/keyring').Keyring;
  var keyringSync = require('common/lib/keyringSync');
  var openpgp = require('openpgp');

  describe('Keyring unit tests', function() {
    var keyring;

    beforeEach(function() {
      sinon.stub(window, 'fetch');
      sinon.stub(openpgp, 'generateKeyPair');
      var openpgpKeyring = sinon.createStubInstance(openpgp.Keyring);
      sinon.stub(openpgp, 'Keyring');
      var sync = sinon.createStubInstance(keyringSync.KeyringSync);
      sinon.stub(keyringSync, 'KeyringSync');

      keyring = new Keyring('id');
      keyring.keyring = openpgpKeyring;
      keyring.keyring.privateKeys = [];
      keyring.sync = sync;
      sinon.stub(keyring , 'hasPrimaryKey');
    });

    afterEach(function() {
      window.fetch.restore();
      openpgp.generateKeyPair.restore();
      openpgp.Keyring.restore();
      keyringSync.KeyringSync.restore();
    });

    describe('generateKey', function() {
      var keygenOpt;

      beforeEach(function() {
        keygenOpt = {
          numBits: 2048,
          userIds: [{email:'a@b.co', fullName:'A B'}],
          passphrase: 'secret'
        };

        var keyStub = sinon.createStubInstance(openpgp.key.Key);
        keyStub.primaryKey = {
          getFingerprint: function() {},
          keyid: {toHex: function() { return 'ASDF'; }}
        };
        openpgp.generateKeyPair.returns(resolves({
          key: keyStub,
          publicKeyArmored: 'PUBLIC KEY BLOCK',
          privateKeyArmored: 'PRIVATE KEY BLOCK'
        }));
        keyring.hasPrimaryKey.returns(true);
        window.fetch.returns(resolves({status:201}));
      });

      it('should generate and upload key', function() {
        keygenOpt.uploadPublicKey = true;
        return keyring.generateKey(keygenOpt).then(function(key) {
          expect(key.privateKeyArmored).to.exist;
          expect(window.fetch.calledOnce).to.be.true;
        });
      });

      it('should generate and not upload key', function() {
        keygenOpt.uploadPublicKey = false;
        return keyring.generateKey(keygenOpt).then(function(key) {
          expect(key.privateKeyArmored).to.exist;
          expect(window.fetch.calledOnce).to.be.false;
        });
      });
    });

  });
});
