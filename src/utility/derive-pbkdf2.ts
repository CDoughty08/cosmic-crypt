import { pbkdf2, pbkdf2Sync } from './crypto';

import { PASS_KEY_SIZE } from '../lib/common/constants';
import { DERIVE_ALGORITHM } from '../lib/pbkdf2/constants';

export interface KeyMetadata {
  derivedKey: Buffer;
  hmacKey: Buffer;
}

export async function derivePBKDF2Key(password: Buffer, salt: Buffer, rounds: number): Promise<KeyMetadata> {

  const key = await pbkdf2(
    password.toString('hex'),
    salt,
    rounds,
    PASS_KEY_SIZE,
    DERIVE_ALGORITHM
  );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}

export function derivePBKDF2KeySync(password: Buffer, salt: Buffer, rounds: number): KeyMetadata {
  const key = pbkdf2Sync(
    password.toString('hex'),
    salt,
    rounds,
    PASS_KEY_SIZE,
    DERIVE_ALGORITHM
  );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}
