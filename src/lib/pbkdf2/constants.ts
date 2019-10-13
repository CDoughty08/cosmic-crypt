export const HMAC_ALGORITHM = 'sha512';
export const PBKDF2_CIPHER = 'aes-256-cbc';
export const DERIVE_ALGORITHM = 'sha512';

export const PBKDF2_ROUNDS = 10000;

export const PASS_KEY_SIZE = 32;

export const IV_LENGTH = 16;
export const PASS_LENGTH = 64;
export const HMAC_LENGTH = 64;
export const SALT_LENGTH = 32;

export const ROUNDS_SIZE = 4;

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  hmac: Buffer;
  salt: Buffer;
  rounds: Buffer;
}

export enum UnpackErrorCode {
  MISSING_MARKER,
  INVALID_META_LENGTH,
  INVALID_ENCRYPTED_DATA
}
