import {
  DERIVE_ALGORITHM,

  PASS_KEY_SIZE,

  pbkdf2,
  pbkdf2Sync
} from './';

export interface KeyMetadata {
  derivedKey: Buffer;
  hmacKey: Buffer;
}

export async function deriveKey(password: Buffer, salt: Buffer, rounds: number): Promise<KeyMetadata> {
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

export function deriveKeySync(password: Buffer, salt: Buffer, rounds: number): KeyMetadata {
  const key = pbkdf2Sync(
    password.toString('hex'),
    salt,
    rounds,
    PASS_KEY_SIZE,
    DERIVE_ALGORITHM
  );

  const hex = key.toString('hex');
  const half = hex.length / 2;

  console.log({
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  });
  return {
    derivedKey: Buffer.from(hex.substr(0, half)),
    hmacKey: Buffer.from(hex.substr(half, half))
  };
}
