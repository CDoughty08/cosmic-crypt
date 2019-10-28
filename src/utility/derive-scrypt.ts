import { scrypt, ScryptOptions, scryptSync } from './crypto';

import { PASS_KEY_SIZE } from '../lib/pbkdf2/constants';

export interface KeyMetadata {
  derivedKey: Buffer;
  hmacKey: Buffer;
}

export async function deriveSCryptKey(password: Buffer, salt: Buffer, opts: ScryptOptions): Promise<KeyMetadata> {
  const key = await scrypt(
    password.toString('hex'),
    salt,
    PASS_KEY_SIZE,
    opts
  );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}

export function deriveSCryptKeySync(password: Buffer, salt: Buffer, opts: ScryptOptions): KeyMetadata {
  const key = scryptSync(
    password.toString('hex'),
    salt,
    PASS_KEY_SIZE,
    opts
  );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}
