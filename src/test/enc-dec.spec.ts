import { assert } from 'chai';

import {
  decrypt,
  DecryptErrorCode,
  encrypt,
  EncryptErrorCode,
  UnpackErrorCode
} from '../';

describe('Encrypt/Decrypt', () => {
  const text = Buffer.from('Test Data!');
  const password = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12');
  const iv = Buffer.from('1234123412341234');
  const salt = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');

  it('should fail with invalid password length', async () => {
    const shortPassword = Buffer.from('This password is too short');

    try {
      await encrypt(text, shortPassword, iv, salt);
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.PASSWORD_TOO_SHORT);
    }
  });

  it('should fail with invalid iv', async () => {
    const badiv = Buffer.from('1234...');

    try {
      await encrypt(text, password, badiv, salt);
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.IV_INVALID_LENGTH);
    }
  });

  it('should fail with invalid salt length', async () => {
    const badsalt = Buffer.from('not salty enough');

    try {
      await encrypt(text, password, iv, badsalt);
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.SALT_INVALID_LENGTH);
    }
  });

  it('should fail if signatures do not match', async () => {
    const invalidEncryptedData = await encrypt(text, password, iv, salt);
    invalidEncryptedData[invalidEncryptedData.length - 10] = 1;

    try {
      assert(!await decrypt(invalidEncryptedData, password), 'Should be authentication error');
    }
    catch (e) {
      assert(e.code === DecryptErrorCode.AUTHENTICATION_ERROR, e.message);
    }
  });

  it('should fail with invalid metadata', async () => {
    const invalidEncryptedData = Buffer.from('Invalid encryption data');
    try {
      assert(!await decrypt(invalidEncryptedData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_META_LENGTH, e.message);
    }
  });

  it('should fail with encrypted data is incorrect length', async () => {
    let invalidEncryptedData = await encrypt(text, password, iv, salt);
    invalidEncryptedData = invalidEncryptedData.slice(0, invalidEncryptedData.length - 10);

    try {
      assert(!await decrypt(invalidEncryptedData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_ENCRYPTED_DATA, e.message);
    }
  });

  it('should encrypt and decrypt data correctly', async () => {
    const encrypted = await encrypt(text, password, iv, salt);

    const decrypted = await decrypt(encrypted, password);

    assert(decrypted.equals(text));
  });

  it('should fail if marker is missing or invalid', async () => {
    try {
      const encrypted = await encrypt(text, password, iv, salt);
      encrypted[0] = 0;
      await decrypt(encrypted, password);
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.MISSING_MARKER, e.message);
    }
  });
});
