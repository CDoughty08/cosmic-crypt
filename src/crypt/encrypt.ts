import {
  deriveKey,

  ENCRYPT_ALGORITHM,
  HMAC_ALGORITHM,

  IV_LENGTH,
  PASS_LENGTH,
  SALT_LENGTH
} from '../utility';

import * as crypto from 'crypto';

export enum EncryptErrorCode {
  PASSWORD_TOO_SHORT,
  IV_INVALID_LENGTH,
  SALT_INVALID_LENGTH
}

export async function encrypt(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer): Promise<Buffer> {
  if (password.length < PASS_LENGTH) {
    throw { code: EncryptErrorCode.PASSWORD_TOO_SHORT, message: `Password must be ${PASS_LENGTH} bytes or more.` };
  }

  if (salt.length !== SALT_LENGTH) {
    throw { code: EncryptErrorCode.SALT_INVALID_LENGTH, message: `Salt must be ${SALT_LENGTH} bytes.` };
  }

  if (iv.length !== IV_LENGTH) {
    throw { code: EncryptErrorCode.IV_INVALID_LENGTH, message: `Initialization Vector must be ${IV_LENGTH} bytes.` };
  }

  const ivHex = iv.toString('hex');
  const saltHex = salt.toString('hex');

  const keyInfo = await deriveKey(password, salt);

  const cipher = crypto.createCipheriv(ENCRYPT_ALGORITHM, keyInfo.derivedKey, iv);

  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);

  const data = [
    cipher.update(buffer, 'utf8', 'hex'),
    cipher.final('hex')
  ].join('');

  hmac.update(data);
  hmac.update(ivHex);
  hmac.update(saltHex);

  const digest = hmac.digest('hex');

  return Buffer.from([
    ivHex,
    saltHex,
    digest,
    data
  ].join(''));
}
