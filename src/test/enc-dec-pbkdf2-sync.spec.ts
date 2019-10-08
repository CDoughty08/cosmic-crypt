import { assert } from 'chai';

import {
  CosmicCrypt,
  DecryptErrorCode,
  EncryptErrorCode,
  UnpackErrorCode
} from '..';

describe('Encrypt/Decrypt Sync', () => {
  const text = Buffer.from('Test Data!');
  const password = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12');
  const iv = Buffer.from('1234123412341234');
  const salt = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');

  it('should fail with invalid password length', () => {
    const shortPassword = Buffer.from('This password is too short');

    try {
      CosmicCrypt.encryptPBKDF2Sync(text, { password: shortPassword, iv, salt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.PASSWORD_TOO_SHORT);
    }
  });

  it('should fail with invalid iv', () => {
    const badiv = Buffer.from('1234...');

    try {
      CosmicCrypt.encryptPBKDF2Sync(text, { password, iv: badiv, salt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.IV_INVALID_LENGTH);
    }
  });

  it('should fail with invalid salt length', () => {
    const badsalt = Buffer.from('not salty enough');

    try {
      CosmicCrypt.encryptPBKDF2Sync(text, { password, iv, salt: badsalt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.SALT_INVALID_LENGTH);
    }
  });

  it('should fail if signatures do not match', () => {

    const invalidEncryptedData = CosmicCrypt.encryptPBKDF2Sync(text, { password, iv, salt });
    invalidEncryptedData[invalidEncryptedData.length - 10] = 1;

    try {
      assert(CosmicCrypt.decryptPBKDF2Sync(invalidEncryptedData, password), 'Should be authentication error');
    }
    catch (e) {
      assert(e.code === DecryptErrorCode.AUTHENTICATION_ERROR, e.message);
    }
  });

  it('should fail with invalid metadata', () => {
    const invalidEncryptedData = Buffer.from('Invalid encryption data');
    try {
      assert(CosmicCrypt.decryptPBKDF2Sync(invalidEncryptedData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_META_LENGTH, e.message);
    }
  });

  it('should fail with encrypted data is incorrect length', () => {
    let invalidEncryptedData = CosmicCrypt.encryptPBKDF2Sync(text, { password, iv, salt });
    invalidEncryptedData = invalidEncryptedData.slice(0, invalidEncryptedData.length - 10);

    try {
      assert(CosmicCrypt.decryptPBKDF2Sync(invalidEncryptedData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_ENCRYPTED_DATA, e.message);
    }
  });

  it('should encrypt and decrypt data correctly', () => {
    const encrypted = CosmicCrypt.encryptPBKDF2Sync(text, { password, iv, salt });

    const decrypted = CosmicCrypt.decryptPBKDF2Sync(encrypted, password);

    assert(decrypted.equals(text));
  });

  it('should fail if marker is missing or invalid', () => {
    try {
      const encrypted = CosmicCrypt.encryptPBKDF2Sync(text, { password, iv, salt });
      encrypted[0] = 0;
      CosmicCrypt.decryptPBKDF2Sync(encrypted, password);
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.MISSING_MARKER, e.message);
    }
  });
});
