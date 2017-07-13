import {
  deriveKey,
  deriveKeySync,

  ENCRYPT_ALGORITHM,
  HMAC_ALGORITHM,

  IV_LENGTH,
  PASS_LENGTH,
  PBKDF2_ROUNDS,
  ROUNDS_SIZE,
  SALT_LENGTH,

  // tslint:disable-next-line:ordered-imports
  // VERSION,
  MARKER
} from '../utility';

import * as crypto from 'crypto';

export enum EncryptErrorCode {
  PASSWORD_TOO_SHORT,
  IV_INVALID_LENGTH,
  SALT_INVALID_LENGTH
}

export async function encrypt(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds = PBKDF2_ROUNDS): Promise<Buffer> {
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

  const roundsBuffer = Buffer.alloc(ROUNDS_SIZE);
  roundsBuffer.writeUInt32LE(rounds, 0);
  const roundsHex = roundsBuffer.toString('hex');

  const keyInfo = await deriveKey(password, salt, rounds);

  const cipher = crypto.createCipheriv(ENCRYPT_ALGORITHM, keyInfo.derivedKey, iv);

  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);

  const data = Buffer.concat([
    cipher.update(buffer),
    cipher.final()
  ]).toString('hex');

  hmac.update(MARKER);
  hmac.update(roundsHex);
  hmac.update(data);
  hmac.update(ivHex);
  hmac.update(saltHex);

  const digest = hmac.digest('hex');

  return Buffer.from([
    Buffer.from(MARKER).toString('hex'),
    roundsHex,
    ivHex,
    saltHex,
    digest,
    data
  ].join(''));
}

export function encryptSync(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds = PBKDF2_ROUNDS): Buffer {
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

  const roundsBuffer = Buffer.alloc(ROUNDS_SIZE);
  roundsBuffer.writeUInt32LE(rounds, 0);
  const roundsHex = roundsBuffer.toString('hex');

  const keyInfo = deriveKeySync(password, salt, rounds);

  const cipher = crypto.createCipheriv(ENCRYPT_ALGORITHM, keyInfo.derivedKey, iv);

  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);

  const data = Buffer.concat([
    cipher.update(buffer),
    cipher.final()
  ]).toString('hex');

  hmac.update(MARKER);
  hmac.update(roundsHex);
  hmac.update(data);
  hmac.update(ivHex);
  hmac.update(saltHex);

  const digest = hmac.digest('hex');

  return Buffer.from([
    Buffer.from(MARKER).toString('hex'),
    roundsHex,
    ivHex,
    saltHex,
    digest,
    data
  ].join(''));
}
