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
    // tslint:disable-next-line:max-line-length
    const invalidEncryptedData = Buffer.from('313233343132333431323334313233344142434445464748494a4b4c4d4e4f505152535455565758595a31323334353686f3743027d2cd228365afbb7205d5944fc89b50a820b22471f8e2b8cb814c6d9c887ab2190ef00eb6d9a46516e9628faaf807c341722c47b8534dff8702889bb5ec1caf347aecf65b75ce613fb0e44f636bf6d56498b8d2e4ff00ed259d6bf21b5af83a5bf5a1254a5a38497dec3dc7180a0843a50aedbcef80aa819cb9f879b009f32c6c527832835013f414b752b9');
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
    // tslint:disable-next-line:max-line-length
    const invalidEncryptedData = Buffer.from('313233343132333431323334313233344142434445464748494a4b4c4d4e4f505152535455565758595a31323334353686f3743027d2cd228365afbb7205d5944fc89b50a820b22471f8e2b8cb814c6d9c887ab2190ef00eb6d9a46516e9628faaf807c341722c47b8534dff8702889bb5ec1caf347aecf65b75ce613fb0e44f636bf6d56498b8d2e4ff00ed259d6bf21b5af83a5bf5a1254a5a38497dec3dc7180a0843a50aedbcef80aa819cb9f879b009f32c6c527832835013f414b752');
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
});
