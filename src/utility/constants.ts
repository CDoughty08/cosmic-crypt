export const MARKER = 'CCRYPT';
export const MARKER_BUFFER = Buffer.from(MARKER);

export interface PBKDF2CryptCredentials {
  password: Buffer;
  iv: Buffer;
  salt: Buffer;
}

export interface SCryptCredentials {
  password: Buffer;
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
