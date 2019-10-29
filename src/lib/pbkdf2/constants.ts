import { HMAC_LENGTH, MARKER, SALT_LENGTH } from '../common/constants';

export const PBKDF2_CIPHER = 'aes-256-cbc';
export const DERIVE_ALGORITHM = 'sha512';

export const PBKDF2_ROUNDS = 10000;

export const IV_LENGTH = 16;
export const PASS_LENGTH = 64;

export const ROUNDS_SIZE = 4;

export const PBKDF2HeaderSize = (MARKER.length * 2) + (ROUNDS_SIZE * 2) + (IV_LENGTH * 2);
export const PBKDF2TrailerSize = (HMAC_LENGTH * 2) + (SALT_LENGTH * 2);

export interface EncryptedData {
  headerRaw: Buffer;
  encrypted: Buffer;
  iv: Buffer;
  hmac: Buffer;
  salt: Buffer;
  rounds: Buffer;
}
