import { assert } from 'chai';

import {
  CosmicCrypt,
  DecryptErrorCode,
  EncryptErrorCode,
  UnpackErrorCode
} from '..';
import { ScryptHeaderSize, ScryptTrailerSize } from '../lib/common/constants';

describe('Encrypt/Decrypt (SCRYPT KDF)', () => {
  const text = Buffer.from('Test Data!');
  const password = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12');
  const iv = Buffer.from('1234123412341234');
  const salt = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');

  it('should fail with invalid password length', async () => {
    const shortPassword = Buffer.from('This password is too short');

    try {
      await CosmicCrypt.encryptScrypt(text, { password: shortPassword, iv, salt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.PASSWORD_TOO_SHORT);
    }
  });

  it('should fail with invalid iv', async () => {
    const badiv = Buffer.from('1234...');

    try {
      await CosmicCrypt.encryptScrypt(text, { password, iv: badiv, salt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.IV_INVALID_LENGTH);
    }
  });

  it('should fail with invalid salt length', async () => {
    const badsalt = Buffer.from('not salty enough');

    try {
      await CosmicCrypt.encryptScrypt(text, { password, iv, salt: badsalt });
    }
    catch (e) {
      assert(e.code === EncryptErrorCode.SALT_INVALID_LENGTH);
    }
  });

  it('should fail if signatures do not match', async () => {
    const invalidEncryptedData = await CosmicCrypt.encryptScrypt(text, { password, iv, salt });
    invalidEncryptedData[invalidEncryptedData.length - 10] = 1;

    try {
      assert(!await CosmicCrypt.decryptScrypt(invalidEncryptedData, password), 'Should be authentication error');
    }
    catch (e) {
      assert(e.code === DecryptErrorCode.AUTHENTICATION_ERROR, e.message);
    }
  });

  it('should fail with invalid metadata', async () => {
    const invalidEncryptedData = Buffer.from('Invalid encryption data');
    try {
      assert(!await CosmicCrypt.decryptScrypt(invalidEncryptedData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_META_LENGTH, e.message);
    }
  });

  it('should fail with encrypted data is incorrect length', async () => {
    const validEncryptedData = await CosmicCrypt.encryptScrypt(text, { password, iv, salt });
    const invalidData = Buffer.concat([
      validEncryptedData.slice(0, ScryptHeaderSize),
      validEncryptedData.slice(ScryptHeaderSize, ScryptHeaderSize + 1),
      validEncryptedData.slice(validEncryptedData.byteLength - ScryptTrailerSize)
    ]);

    try {
      assert(!await CosmicCrypt.decryptScrypt(invalidData, password), 'Should be decrypt error');
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.INVALID_ENCRYPTED_DATA, e.message);
    }
  });

  it('should encrypt and decrypt data correctly', async () => {
    const encrypted = await CosmicCrypt.encryptScrypt(text, { password, iv, salt });

    const decrypted = await CosmicCrypt.decryptScrypt(encrypted, password);

    assert(decrypted.equals(text));
  });

  it('should fail if marker is missing or invalid', async () => {
    try {
      const encrypted = await CosmicCrypt.encryptScrypt(text, { password, iv, salt });
      encrypted[0] = 0;
      await CosmicCrypt.decryptScrypt(encrypted, password);
    }
    catch (e) {
      assert(e.code === UnpackErrorCode.MISSING_MARKER, e.message);
    }
  });
});
