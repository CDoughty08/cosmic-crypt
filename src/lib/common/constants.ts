export const MARKER = 'CCRYPT';
export const MARKER_BUFFER = Buffer.from(MARKER);

export const HMAC_ALGORITHM = 'sha512';

export const PASS_KEY_SIZE = 32;

export const HMAC_LENGTH = 64;
export const SALT_LENGTH = 32;

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
