export const MARKER = 'CC-HEX';
export const HEX_MARKER_BUFFER = Buffer.from(MARKER);

export const SYMMETRIC_CIPHER = 'aes-256-cbc';
export const HMAC_ALGORITHM = 'sha512';

export const PASS_LENGTH = 64;
export const PASS_KEY_SIZE = 32;

export const IV_LENGTH = 16;

export const HMAC_LENGTH = 64;
export const SALT_LENGTH = 32;

export const ScryptHeaderSize = (MARKER.length * 2) + (IV_LENGTH * 2);
export const ScryptTrailerSize = (HMAC_LENGTH * 2) + (SALT_LENGTH * 2);

export const DERIVE_ALGORITHM = 'sha512';

export const PBKDF2_ROUNDS = 10000;

export const ROUNDS_SIZE = 4;

export const PBKDF2HeaderSize = (MARKER.length * 2) + (ROUNDS_SIZE * 2) + (IV_LENGTH * 2);
export const PBKDF2TrailerSize = (HMAC_LENGTH * 2) + (SALT_LENGTH * 2);

export interface KeyMetadata {
  derivedKey: Buffer;
  hmacKey: Buffer;
}

export interface PBKDF2CryptCredentials {
  password: Buffer;
  iv: Buffer;
  salt: Buffer;
}

export interface ScryptCredentials {
  password: Buffer;
  iv: Buffer;
  salt: Buffer;
}

export enum DecryptErrorCode {
  AUTHENTICATION_ERROR
}

export enum EncryptErrorCode {
  PASSWORD_TOO_SHORT,
  IV_INVALID_LENGTH,
  SALT_INVALID_LENGTH
}

export enum UnpackErrorCode {
  SUCCESS,
  MISSING_MARKER,
  INVALID_META_LENGTH,
  INVALID_ENCRYPTED_DATA
}

export interface KeyMetadata {
  derivedKey: Buffer;
  hmacKey: Buffer;
}
