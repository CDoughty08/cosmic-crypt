import { pbkdf2, pbkdf2Sync, scrypt, ScryptOptions, scryptSync } from '../../utility/crypto';

import { DERIVE_ALGORITHM, KeyMetadata, PASS_KEY_SIZE } from './constants';

interface SymmetricDeriveArguments {
  PBKDF2: {
    rounds: number;
  };
  SCRYPT?: ScryptOptions;
}

export function deriveSymmetricKeySync<K extends keyof SymmetricDeriveArguments>(kdf: K, password: Buffer, salt: Buffer, opts: SymmetricDeriveArguments[K]): KeyMetadata {
  const key =
    kdf === 'PBKDF2'
      ? pbkdf2Sync(
        password.toString('hex'),
        salt,
        (opts as SymmetricDeriveArguments['PBKDF2']).rounds,
        PASS_KEY_SIZE,
        DERIVE_ALGORITHM
      )
      : scryptSync(
        password.toString('hex'),
        salt,
        PASS_KEY_SIZE,
        (opts as SymmetricDeriveArguments['SCRYPT']) || {}
      );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}

export async function deriveSymmetricKey<K extends keyof SymmetricDeriveArguments>(
  kdf: K,
  password: Buffer,
  salt: Buffer,
  opts: SymmetricDeriveArguments[K]
): Promise<KeyMetadata> {
  const key =
    kdf === 'PBKDF2'
      ? await pbkdf2(
        password.toString('hex'),
        salt,
        (opts as SymmetricDeriveArguments['PBKDF2']).rounds,
        PASS_KEY_SIZE,
        DERIVE_ALGORITHM
      )
      : await scrypt(
        password.toString('hex'),
        salt,
        PASS_KEY_SIZE,
        (opts as SymmetricDeriveArguments['SCRYPT']) || {}
      );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}
